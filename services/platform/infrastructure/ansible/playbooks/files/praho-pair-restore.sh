#!/bin/bash
# Restore a base backup and its differential onto one Virtualmin domain, as ONE locked node
# execution, behind a two-layer write barrier. Or release a pair restore that stopped midway.
#
# Run by virtualmin_pair_restore.yml as root on the node. Under the per-domain chain lock
# (the same lock the backup chain steps take, so no chain backup interleaves):
#
#   1. barrier layer (a): server-level Apache rules answering 503 for whatever reaches the domain's
#      virtual host, in a configuration file of its own that restore-domain never rewrites, loaded
#      and verified. They are keyed on the virtual host itself (its document root) and, as a second
#      key, on every name the domain answers to, case-insensitively and with an optional trailing
#      dot, and they run before the virtual host's own rewrite rules (Apache 2.4.8 or later,
#      RewriteOptions InheritDownBefore). It is deliberately NOT a virtual host: Virtualmin
#      recognises a virtual host that serves the domain and rewrites it during a restore, which let
#      requests through;
#   2. barrier layer (b): disable-domain, verified;
#   3. restore the base, then re-apply and verify both layers;
#   4. restore the differential, then re-apply and verify both layers;
#   5. verify, and only then take the 503 section down.
#
# The domain is left DISABLED on success: enabling it again belongs to PRAHO's reconcile
# (ADR-0051), never to this script. Any failure after the barrier is up leaves both layers up
# and reports what was reached; only "release" (an operator decision) removes them.
#
# Before every destructive call the job's cancel marker is checked and the archive's sha256 is
# verified again. Nothing is interpolated into this script: inputs come from the environment.
#
# Inputs:
#   PRAHO_PAIR_ACTION     restore | release
#   PRAHO_DOMAIN, PRAHO_DOMAIN_ID, PRAHO_CHAIN_TOKEN, PRAHO_LOCK_WAIT, PRAHO_STAGING_DIR
#   PRAHO_BASE_ARCHIVE, PRAHO_DIFF_ARCHIVE, PRAHO_BASE_SHA, PRAHO_DIFF_SHA   (restore only)
#   PRAHO_STEP_HOLD       seconds to wait between the two restores (0-60, default 0): a window in
#                         which a cancel marker can land
#   PRAHO_RUN_DIR, PRAHO_APACHE_DIR, PRAHO_HTTP_PORT, PRAHO_HTTPS_PORT   optional, tests only
#                         (PRAHO_APACHE_DIR defaults to /etc/apache2/conf-enabled)
#
# Output: exactly one line, PAIR_RESULT=<base64 of a JSON object>, with exit status 0 whenever
# the result is trustworthy. Any other exit status means the outcome is uncertain.
set -euo pipefail
umask 077

RUN_DIR=${PRAHO_RUN_DIR:-/run/praho}
APACHE_DIR=${PRAHO_APACHE_DIR:-/etc/apache2/conf-enabled}
HTTP_PORT=${PRAHO_HTTP_PORT:-80}
HTTPS_PORT=${PRAHO_HTTPS_PORT:-443}
readonly RUN_DIR APACHE_DIR HTTP_PORT HTTPS_PORT
safe_dir='^/[A-Za-z0-9._/-]+$'
[[ $RUN_DIR =~ $safe_dir && $RUN_DIR != *..* ]] || exit 64
[[ $APACHE_DIR =~ $safe_dir && $APACHE_DIR != *..* ]] || exit 64
[[ $HTTP_PORT =~ ^[0-9]{1,5}$ && $HTTPS_PORT =~ ^[0-9]{1,5}$ ]] || exit 64

action=${PRAHO_PAIR_ACTION:?}
domain=${PRAHO_DOMAIN:?}
domain_id=${PRAHO_DOMAIN_ID:?}
token=${PRAHO_CHAIN_TOKEN:?}
lock_wait=${PRAHO_LOCK_WAIT:-60}
staging=${PRAHO_STAGING_DIR:?}
base_archive=${PRAHO_BASE_ARCHIVE:-}
diff_archive=${PRAHO_DIFF_ARCHIVE:-}
base_sha=${PRAHO_BASE_SHA:-}
diff_sha=${PRAHO_DIFF_SHA:-}
step_hold=${PRAHO_STEP_HOLD:-0}

[[ $action =~ ^(restore|release)$ ]] || exit 64
[[ $domain =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || exit 64
[[ $domain_id =~ ^[0-9]{1,30}$ ]] || exit 64
[[ $token =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || exit 64
[[ $lock_wait =~ ^[0-9]{1,4}$ ]] || exit 64
[[ $step_hold =~ ^[0-9]{1,2}$ ]] || exit 64
if [[ $action == restore ]]; then
  [[ $base_archive =~ ^virtualmin_backup_[0-9a-f]{32}\.tar\.gz$ ]] || exit 64
  [[ $diff_archive =~ ^virtualmin_backup_[0-9a-f]{32}\.tar\.gz$ ]] || exit 64
  [[ $base_sha =~ ^[0-9a-f]{64}$ && $diff_sha =~ ^[0-9a-f]{64}$ ]] || exit 64
  [[ $base_archive != "$diff_archive" ]] || exit 64
fi

lock_file="$RUN_DIR/chain-$domain_id.lock"
cancel_marker="$RUN_DIR/chain-$domain_id.cancelled.$token"
maint_conf="$APACHE_DIR/zz-praho-maint-$domain_id.conf"
progress="$RUN_DIR/pair-$domain_id.progress"
checkpoints=""
docroot=""
docroot_regex=""
probe_hosts=()
name_regex=""
CP_ODD=none

now() {
  local t
  t=$(date +%s.%N 2>/dev/null || true)
  [[ $t =~ ^[0-9]+\.[0-9]+$ ]] || t=$(date +%s)
  printf '%s' "$t"
}

# emit OUTCOME REASON RAN : one result line; the checkpoints so far ride along.
emit() {
  local json
  json=$(printf '{"outcome":"%s","reason":"%s","ran":%s,"action":"%s","domain_id":"%s","token":"%s","checkpoints":[%s]}' \
    "$1" "$2" "$3" "$action" "$domain_id" "$token" "$checkpoints")
  printf 'PAIR_RESULT=%s\n' "$(printf '%s' "$json" | base64 | tr -d '\n')"
}

is_disabled() {
  virtualmin list-domains --disabled --name-only 2>/dev/null | grep -qxF -- "$domain"
}

http_code() { # SCHEME PORT [HOST]
  local scheme=$1 port=$2 host=${3:-$domain} insecure=""
  [[ $scheme == https ]] && insecure="-k"
  # $insecure is deliberately unquoted: empty means no argument at all.
  # shellcheck disable=SC2086
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 $insecure \
    --resolve "$host:$port:127.0.0.1" "$scheme://$host:$port/" 2>/dev/null || printf '000'
}

ssl_loaded() { apache2ctl -M 2>/dev/null | grep -q 'ssl_module'; }

# probe_odd_hosts : every spelling the domain's virtual host can be reached by must be answered 503
# on every port that is open: the names in upper case, with a trailing dot, the mail name and every
# alias. Sets CP_ODD to 503, or to the first other answer (and writes which host gave it).
probe_odd_hosts() {
  local host code
  CP_ODD=503
  for host in "${probe_hosts[@]}"; do
    code=$(http_code http "$HTTP_PORT" "$host")
    if [[ $code != 503 ]]; then
      CP_ODD=$code
      printf 'host %s answered %s on port %s\n' "$host" "$code" "$HTTP_PORT" >>"$RUN_DIR/pair-$domain_id.diag"
      return
    fi
    if ssl_loaded; then
      code=$(http_code https "$HTTPS_PORT" "$host")
      if [[ $code != 503 ]]; then
        CP_ODD=$code
        printf 'host %s answered %s on port %s\n' "$host" "$code" "$HTTPS_PORT" >>"$RUN_DIR/pair-$domain_id.diag"
        return
      fi
    fi
  done
}

# checkpoint STEP : record whether the domain is disabled and what the two ports answer, to the
# domain's own name and to every odd spelling of its names.
checkpoint() {
  local disabled=false h80 h443=none
  is_disabled && disabled=true
  h80=$(http_code http "$HTTP_PORT")
  if ssl_loaded; then h443=$(http_code https "$HTTPS_PORT"); fi
  probe_odd_hosts
  [[ -n $checkpoints ]] && checkpoints+=","
  checkpoints+=$(printf '{"step":"%s","at":"%s","disabled":%s,"http80":"%s","http443":"%s","odd_hosts":"%s"}' "$1" "$(now)" "$disabled" "$h80" "$h443" "$CP_ODD")
  printf '%s\n' "$checkpoints" >"$progress"
  CP_DISABLED=$disabled CP_80=$h80 CP_443=$h443
}

barrier_holds() {
  [[ $CP_DISABLED == true && $CP_80 == 503 && ( $CP_443 == none || $CP_443 == 503 ) && $CP_ODD == 503 ]]
}

reload_apache() { apache2ctl graceful >/dev/null 2>&1; }

barrier_up() {
  # Server level, so every virtual host inherits it whatever Virtualmin does to its own file. The rules
  # run in the translation phase and are inherited BEFORE a virtual host's own rewrite rules: Virtualmin's
  # virtual host redirects its webmail and admin names itself, and a rule that ran after those would never
  # be reached for them. They match the virtual host (its document root, so also a Host header that names
  # nothing at all) or any spelling of the domain's names; nothing else on the node is touched.
  {
    printf 'RewriteOptions InheritDownBefore\nRewriteEngine On\n'
    printf 'RewriteCond %%{DOCUMENT_ROOT} ^%s(/|$) [OR]\n' "$docroot_regex"
    printf 'RewriteCond %%{HTTP_HOST} ^(%s)\\.?(:[0-9]+)?$ [NC]\n' "$name_regex"
    printf 'RewriteRule ^ - [R=503,L]\nErrorDocument 503 "Restore in progress"\n'
  } >"$maint_conf"
  reload_apache
}

barrier_down() {
  rm -f -- "$maint_conf"
  reload_apache
}

install -d -m 0700 -o root -g root "$RUN_DIR"
exec 9>"$lock_file"
if ! flock -w "$lock_wait" 9; then
  emit refused lock_busy false
  exit 0
fi

if [[ $action == release ]]; then
  # An operator's decision: the pair restore is over. The marker keeps a late invocation from
  # starting, the barrier comes down, and the domain stays disabled for reconcile to enable.
  install -m 0600 /dev/null "$cancel_marker"
  barrier_down
  rm -f -- "$progress"
  emit released barrier_removed false
  exit 0
fi

if [[ -e $cancel_marker ]]; then
  emit refused cancelled false
  exit 0
fi
if [[ ! -d $staging || -L $staging || $(stat -c '%u:%a' -- "$staging") != "0:700" ]]; then
  emit refused staging_not_private false
  exit 0
fi

verify_archive() { # NAME SHA
  local path="$staging/$1" sum
  [[ -f $path && ! -L $path && -s $path ]] || return 1
  sum=$(sha256sum -- "$path")
  [[ ${sum%% *} == "$2" ]]
}
if ! verify_archive "$base_archive" "$base_sha" || ! verify_archive "$diff_archive" "$diff_sha"; then
  emit refused archive_not_verified false
  exit 0
fi

if ! listed_id=$(virtualmin list-domains --domain "$domain" --id-only 2>/dev/null) || [[ $listed_id != "$domain_id" ]]; then
  emit refused domain_id_mismatch false
  exit 0
fi

# ---- what reaches the domain's virtual host: its document root and every name it answers to ----
domain_info=$(virtualmin list-domains --domain "$domain" --multiline 2>/dev/null || true)
docroot=$(sed -n 's/^ *HTML directory: *//p' <<<"$domain_info")
docroot=${docroot%%$'\n'*}
docroot=${docroot%/}
hostnames=$(sed -n 's/^ *Website hostnames: *//p' <<<"$domain_info")
hostnames=${hostnames%%$'\n'*}
if [[ ! $docroot =~ $safe_dir || $docroot == *..* ]]; then
  emit refused docroot_unknown false
  exit 0
fi
host_ok='^(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'
name_alternatives=()
seen_hosts=" "
add_probe_host() { # HOST : once per exact spelling (the upper-case spelling is a probe of its own)
  [[ $seen_hosts != *" $1 "* ]] || return 0
  seen_hosts+="$1 "
  probe_hosts+=("$1")
}
# read, not an unquoted expansion: a wildcard alias must not be globbed against the working directory.
read -r -a listed_names <<<"$hostnames"
for name in "$domain" "www.$domain" "mail.$domain" ${listed_names[@]+"${listed_names[@]}"}; do
  [[ $name =~ $host_ok ]] || continue
  escaped_name=${name//./\\.}
  if [[ $name == \*.* ]]; then
    # A wildcard alias: any prefix, probed with a made-up one.
    name_alternatives+=("[A-Za-z0-9.-]+\\.${escaped_name#\*\\.}")
    add_probe_host "wildcard-probe.${name#\*.}"
  else
    name_alternatives+=("$escaped_name")
    add_probe_host "$name"
  fi
done
add_probe_host "$(printf '%s' "$domain" | tr '[:lower:]' '[:upper:]')"
add_probe_host "$domain."
printf -v name_regex '%s|' "${name_alternatives[@]}"
name_regex=${name_regex%|}
docroot_regex=${docroot//./\\.}
readonly docroot name_regex docroot_regex

# ---- layer (a): the server-level 503 section; layer (b): disable-domain -----------------------
pre_disabled=false
is_disabled && pre_disabled=true
rm -f -- "$RUN_DIR/pair-$domain_id.diag"
barrier_up
virtualmin disable-domain --domain "$domain" >/dev/null 2>&1 || true
checkpoint barrier_up
if ! barrier_holds; then
  # Nothing destructive has run: undo our own changes and refuse, so a refusal always means
  # the node is as it was.
  barrier_down
  if [[ $pre_disabled == false ]] && is_disabled; then
    virtualmin enable-domain --domain "$domain" >/dev/null 2>&1 || true
  fi
  emit refused barrier_not_verified false
  exit 0
fi

# After the barrier, a stop leaves it up. fail REASON : report and stop.
fail() {
  emit failed "$1" true
  exit 0
}

# reapply STEP : a restore may re-enable the domain; both layers are put back and verified.
reapply() {
  if ! is_disabled; then
    virtualmin disable-domain --domain "$domain" >/dev/null 2>&1 || true
  fi
  # A restore rewrites the domain's Apache configuration and reloads Apache: layer (a) is written
  # again (idempotent) and reloaded before it is verified.
  barrier_up
  checkpoint "$1"
  if ! barrier_holds; then
    { ls -l "$APACHE_DIR"; apache2ctl configtest; } >"$RUN_DIR/pair-$domain_id.diag" 2>&1 || true
    fail "barrier_lost_after_$1"
  fi
}

restore_step() { # LABEL ARCHIVE SHA
  [[ ! -e $cancel_marker ]] || fail "cancelled_before_$1"
  verify_archive "$2" "$3" || fail "archive_not_verified_before_$1"
  printf '%s\n' "$1" >"$progress.step"
  if ! virtualmin restore-domain --domain "$domain" --source "$staging/$2" --all-features >"$RUN_DIR/pair-$domain_id.log" 2>&1; then
    checkpoint "${1}_failed"
    fail "restore_${1}_failed"
  fi
  reapply "after_$1"
}

restore_step base "$base_archive" "$base_sha"
if ((step_hold > 0)); then sleep "$step_hold"; fi
restore_step differential "$diff_archive" "$diff_sha"

# ---- verification, then the barrier comes down; the domain stays disabled ----------------------
virtualmin list-domains --domain "$domain" --name-only 2>/dev/null | grep -qxF -- "$domain" || fail domain_missing_after_restore
is_disabled || fail domain_enabled_after_restore
barrier_down
checkpoint barrier_down
rm -f -- "$progress" "$progress.step" "$RUN_DIR/pair-$domain_id.log"
emit ok completed true
