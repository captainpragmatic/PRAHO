#!/bin/bash
# Restore a base backup and its differential onto one Virtualmin domain, as ONE locked node
# execution, behind a two-layer write barrier. Or release a pair restore that stopped midway.
#
# Run by virtualmin_pair_restore.yml as root on the node. Under the per-domain chain lock
# (the same lock the backup chain steps take, so no chain backup interleaves):
#
#   1. barrier layer (a): a server-level Apache section answering 503 for the domain's names (and
#      only those), in a configuration file of its own that restore-domain never rewrites,
#      loaded and verified. It is deliberately NOT a virtual host: Virtualmin recognises a virtual
#      host that serves the domain and rewrites it during a restore, which let requests through;
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

http_code() { # SCHEME PORT
  local scheme=$1 port=$2 insecure=""
  [[ $scheme == https ]] && insecure="-k"
  # $insecure is deliberately unquoted: empty means no argument at all.
  # shellcheck disable=SC2086
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 $insecure \
    --resolve "$domain:$port:127.0.0.1" "$scheme://$domain:$port/" 2>/dev/null || printf '000'
}

ssl_loaded() { apache2ctl -M 2>/dev/null | grep -q 'ssl_module'; }

# checkpoint STEP : record whether the domain is disabled and what the two ports answer.
checkpoint() {
  local disabled=false h80 h443=none
  is_disabled && disabled=true
  h80=$(http_code http "$HTTP_PORT")
  if ssl_loaded; then h443=$(http_code https "$HTTPS_PORT"); fi
  [[ -n $checkpoints ]] && checkpoints+=","
  checkpoints+=$(printf '{"step":"%s","at":"%s","disabled":%s,"http80":"%s","http443":"%s"}' "$1" "$(now)" "$disabled" "$h80" "$h443")
  printf '%s\n' "$checkpoints" >"$progress"
  CP_DISABLED=$disabled CP_80=$h80 CP_443=$h443
}

barrier_holds() {
  [[ $CP_DISABLED == true && $CP_80 == 503 && ( $CP_443 == none || $CP_443 == 503 ) ]]
}

reload_apache() { apache2ctl graceful >/dev/null 2>&1; }

barrier_up() {
  local escaped=${domain//./\\.}
  # Server-level, so every virtual host inherits it, whatever Virtualmin does to them.
  {
    printf '<If "%%{HTTP_HOST} =~ /^(www\\.)?%s(:[0-9]+)?$/">\n' "$escaped"
    printf '  RewriteEngine On\n  RewriteRule ^ - [R=503,L]\n  ErrorDocument 503 "Restore in progress"\n</If>\n'
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

# ---- layer (a): the server-level 503 section; layer (b): disable-domain -----------------------
pre_disabled=false
is_disabled && pre_disabled=true
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
