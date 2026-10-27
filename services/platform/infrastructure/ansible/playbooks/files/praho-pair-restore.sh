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
#      requests through. A backup brings back the Apache configuration it was taken with, so after
#      every restore the document root and website hostnames are read again and the matchers and
#      the probe list become the UNION of everything seen so far: they never shrink while a restore
#      is in flight, and a restore whose result cannot be read back fails closed, barrier up;
#   2. barrier layer (b): disable-domain with its sub-servers (the account name), both verified;
#   3. restore the base, then re-read what reaches the virtual host, re-apply and verify both layers;
#   4. restore the differential, then do the same;
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
STATE_DIR=${PRAHO_PAIR_STATE_DIR:-/var/lib/praho/pair-restore}
HELD_STATE_DIR=${PRAHO_HELD_STATE_DIR:-/var/lib/praho/recovery}
APACHE_DIR=${PRAHO_APACHE_DIR:-/etc/apache2/conf-enabled}
HTTP_PORT=${PRAHO_HTTP_PORT:-80}
HTTPS_PORT=${PRAHO_HTTPS_PORT:-443}
readonly RUN_DIR STATE_DIR HELD_STATE_DIR APACHE_DIR HTTP_PORT HTTPS_PORT
safe_dir='^/[A-Za-z0-9._/-]+$'
[[ $RUN_DIR =~ $safe_dir && $RUN_DIR != *..* ]] || exit 64
[[ $STATE_DIR =~ $safe_dir && $STATE_DIR != / && $STATE_DIR != *..* ]] || exit 64
[[ $HELD_STATE_DIR =~ $safe_dir && $HELD_STATE_DIR != / && $HELD_STATE_DIR != *..* ]] || exit 64
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
recovery=${PRAHO_RECOVERY:-0}
ssl_helper=${PRAHO_RECOVERY_SSL_HELPER:-/var/lib/praho/recovery/ssl.py}

[[ $action =~ ^(restore|release)$ ]] || exit 64
[[ $domain =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || exit 64
[[ $domain_id =~ ^[0-9]{1,30}$ ]] || exit 64
[[ $token =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || exit 64
[[ $lock_wait =~ ^[0-9]{1,4}$ ]] || exit 64
[[ $step_hold =~ ^[0-9]{1,2}$ ]] || exit 64
[[ $recovery =~ ^[01]$ ]] || exit 64
valid_archive_name() {
  [[ $1 =~ ^virtualmin_backup_[0-9a-f]{32}\.tar\.gz$ ]] || \
    [[ $recovery == 1 && $1 == "migration_$token.tar.gz" ]]
}
if [[ $action == restore ]]; then
  valid_archive_name "$base_archive" || exit 64
  [[ $base_sha =~ ^[0-9a-f]{64}$ ]] || exit 64
  if [[ $recovery == 0 || -n $diff_archive ]]; then
    [[ $diff_archive =~ ^virtualmin_backup_[0-9a-f]{32}\.tar\.gz$ && $base_archive != migration_* ]] || exit 64
    [[ $diff_sha =~ ^[0-9a-f]{64}$ && $base_archive != "$diff_archive" ]] || exit 64
  else
    [[ -z $diff_sha ]] || exit 64
  fi
fi

lock_file="$RUN_DIR/chain-$domain_id.lock"
cancel_marker="$RUN_DIR/chain-$domain_id.cancelled.$token"
durable_cancel_marker="$STATE_DIR/chain-$domain_id.cancelled.$token"
release_completed="$STATE_DIR/chain-$domain_id.released.$token"
maint_conf="$APACHE_DIR/zz-praho-maint-$domain_id.conf"
progress="$RUN_DIR/pair-$domain_id.progress"
checkpoints=""
docroot_regexes=()   # one per document root the domain's virtual host has had since this job began
probe_hosts=()       # every spelling of every name it has answered to since then, probed at each checkpoint
name_regex=""        # the same names as one alternation, for the barrier's Host condition
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

# Flush both the marker and its directory before releasing any write hold. Perl is already
# required by Virtualmin and its IO::Handle sync is portable across Linux and the macOS fixtures.
durable_marker() {
  perl -MFcntl=:DEFAULT,:mode -MIO::Handle -e '
    my $path = shift;
    sysopen(my $file, $path, O_WRONLY | O_CREAT | O_NOFOLLOW, 0600) or die "Cannot open durable fence\n";
    my @info = stat($file);
    die "Unsafe durable fence\n" unless S_ISREG($info[2]) && $info[4] == $> && !($info[2] & 077);
    $file->sync or die "Cannot flush durable fence\n";
    close($file) or die "Cannot close durable fence\n";
    $path =~ s{/[^/]+$}{};
    sysopen(my $directory, $path, O_RDONLY | O_NOFOLLOW) or die "Cannot open fence directory\n";
    $directory->sync or die "Cannot flush fence directory\n";
    close($directory) or die "Cannot close fence directory\n";
  ' "$1"
}

cancelled() {
  [[ -e $cancel_marker || -e $durable_cancel_marker ||
    ( $recovery == 1 && ( -e $HELD_STATE_DIR/$token.activation || -e $HELD_STATE_DIR/$token.cleaned ) ) ]]
}

# domain_disabled : the domain itself is disabled, whatever its sub-servers are. What "as it was"
# means for the refusal path: an account suspended before sub-servers were cascaded has a disabled
# domain and an enabled account name, and must not be re-enabled by a refused restore.
domain_disabled() {
  virtualmin list-domains --disabled --name-only 2>/dev/null | grep -qxF -- "$domain"
}

# is_disabled : the domain AND every sub-server under it (its account name, ADR-0061) are disabled.
# A sub-server keeps serving unless it is disabled too; a listing that cannot be read is "not disabled".
is_disabled() {
  local disabled children child
  disabled=$(virtualmin list-domains --disabled --name-only 2>/dev/null) || return 1
  grep -qxF -- "$domain" <<<"$disabled" || return 1
  children=$(virtualmin list-domains --parent "$domain" --subserver --name-only 2>/dev/null) || return 1
  while IFS= read -r child; do
    [[ -z $child ]] || grep -qxF -- "$child" <<<"$disabled" || return 1
  done <<<"$children"
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
    local root_regex
    for root_regex in "${docroot_regexes[@]}"; do
      printf 'RewriteCond %%{DOCUMENT_ROOT} ^%s(/|$) [OR]\n' "$root_regex"
    done
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
if [[ -e $STATE_DIR || -L $STATE_DIR ]]; then
  [[ -d $STATE_DIR && ! -L $STATE_DIR && $(stat -c '%u:%a' -- "$STATE_DIR") == "0:700" ]] || exit 64
else
  install -d -m 0700 -o root -g root "$STATE_DIR"
fi
if [[ $action == release ]]; then
  # Fence a still-running or delayed invocation before waiting for its lock; reboot must not
  # turn a completed operation into permission to restore or disable a live account again.
  durable_marker "$durable_cancel_marker"
  install -m 0600 /dev/null "$cancel_marker"
fi
exec 9>"$lock_file"
if ! flock -w "$lock_wait" 9; then
  emit refused lock_busy false
  exit 0
fi

if [[ $action == release ]]; then
  # An operator's decision: the pair restore is over. The marker keeps a late invocation from
  # starting, the barrier comes down, and the domain stays disabled for reconcile to enable.
  if [[ -e $release_completed ]]; then
    emit released barrier_removed false
    exit 0
  fi
  barrier_down
  durable_marker "$release_completed"
  rm -f -- "$progress"
  emit released barrier_removed false
  exit 0
fi

if cancelled; then
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
if ! verify_archive "$base_archive" "$base_sha" || { [[ -n $diff_archive ]] && ! verify_archive "$diff_archive" "$diff_sha"; }; then
  emit refused archive_not_verified false
  exit 0
fi

if ! listed_id=$(virtualmin list-domains --domain "$domain" --id-only 2>/dev/null) || [[ $listed_id != "$domain_id" ]]; then
  emit refused domain_id_mismatch false
  exit 0
fi

# ---- what reaches the domain's virtual host: its document root and every name it answers to ----
host_ok='^(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'
name_alternatives=()
seen_hosts=" "
seen_names=" "
seen_roots=" "
add_probe_host() { # HOST : once per exact spelling (the upper-case spelling is a probe of its own)
  [[ $seen_hosts != *" $1 "* ]] || return 0
  seen_hosts+="$1 "
  probe_hosts+=("$1")
}

# read_one_surface DOMAIN : read DOMAIN's HTML directory and website hostnames NOW and fold them into
# the barrier's matchers and the probe list. Only ever adds: what an earlier read found stays covered
# and probed, so a restore that drops or moves something never narrows the barrier mid-flight.
# Returns 1, changing nothing, when the document root cannot be read as a safe absolute path.
read_one_surface() {
  local dom=$1 info root hostnames name escaped_name
  local -a listed_names
  info=$(virtualmin list-domains --domain "$dom" --multiline 2>/dev/null) || return 1
  root=$(sed -n 's/^ *HTML directory: *//p' <<<"$info")
  root=${root%%$'\n'*}
  root=${root%/}
  [[ $root =~ $safe_dir && $root != *..* ]] || return 1
  hostnames=$(sed -n 's/^ *Website hostnames: *//p' <<<"$info")
  hostnames=${hostnames%%$'\n'*}

  if [[ $seen_roots != *" $root "* ]]; then
    seen_roots+="$root "
    docroot_regexes+=("${root//./\\.}")
  fi
  # read, not an unquoted expansion: a wildcard alias must not be globbed against the working directory.
  read -r -a listed_names <<<"$hostnames"
  for name in "$dom" "www.$dom" "mail.$dom" ${listed_names[@]+"${listed_names[@]}"}; do
    [[ $name =~ $host_ok ]] || continue
    [[ $seen_names != *" $name "* ]] || continue
    seen_names+="$name "
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
  add_probe_host "$(printf '%s' "$dom" | tr '[:lower:]' '[:upper:]')"
  add_probe_host "$dom."
}

# read_surface : the domain's own virtual host AND every sub-server under it. The account name
# (ADR-0061) is a sub-server with a virtual host, document root and names of its own that serve the
# customer's files through a link, so the barrier must answer 503 for it too. A child listing that
# cannot be read fails like an unreadable document root.
read_surface() {
  local children child
  read_one_surface "$domain" || return 1
  children=$(virtualmin list-domains --parent "$domain" --subserver --name-only 2>/dev/null) || return 1
  while IFS= read -r child; do
    [[ -n $child ]] || continue
    [[ $child =~ $host_ok ]] || return 1
    read_one_surface "$child" || return 1
  done <<<"$children"
  printf -v name_regex '%s|' "${name_alternatives[@]}"
  name_regex=${name_regex%|}
}

if ! read_surface; then
  emit refused docroot_unknown false
  exit 0
fi

# ---- layer (a): the server-level 503 section; layer (b): disable-domain -----------------------
pre_disabled=false
domain_disabled && pre_disabled=true
rm -f -- "$RUN_DIR/pair-$domain_id.diag"
barrier_up
virtualmin disable-domain --domain "$domain" --subservers >/dev/null 2>&1 || true
checkpoint barrier_up
if ! barrier_holds; then
  # Nothing destructive has run: undo our own changes and refuse, so a refusal always means
  # the node is as it was. If the domain cannot be enabled again it is NOT as it was: that is
  # reported as such (a failure PRAHO parks for an operator), never as a clean refusal.
  barrier_down
  if [[ $pre_disabled == false ]] && domain_disabled; then
    virtualmin enable-domain --domain "$domain" --subservers >/dev/null 2>&1 || true
    if domain_disabled; then
      emit failed barrier_undo_incomplete true
      exit 0
    fi
  fi
  emit refused barrier_not_verified false
  exit 0
fi

# After the barrier, a stop leaves it up. fail REASON : report and stop.
fail() {
  emit failed "$1" true
  exit 0
}

# reapply STEP : a restore may re-enable the domain and may bring back Apache configuration the live
# domain did not have (another document root, another website alias). The domain's surface is read
# again and widened first, layer (a) is written from the widened picture and reloaded, then both
# layers are verified with the widened probe list. If the surface cannot be read the barrier is still
# put back (on what is known) and the job stops with it up.
reapply() {
  local surface_read=true
  read_surface || surface_read=false
  barrier_up
  if ! is_disabled; then
    virtualmin disable-domain --domain "$domain" --subservers >/dev/null 2>&1 || true
  fi
  checkpoint "$1"
  if [[ $surface_read == false ]]; then
    printf 'could not read the document root and website hostnames after %s\n' "$1" >>"$RUN_DIR/pair-$domain_id.diag"
    fail "surface_unreadable_after_$1"
  fi
  if ! barrier_holds; then
    { ls -l "$APACHE_DIR"; apache2ctl configtest; } >"$RUN_DIR/pair-$domain_id.diag" 2>&1 || true
    fail "barrier_lost_after_$1"
  fi
}

restore_step() { # LABEL ARCHIVE SHA
  local -a restore_flags=(--all-features)
  local ssl_archive="$staging/recovery-ssl-$token-$1.tar.gz"
  # Recovery creates a disabled placeholder first. Suppress Unix restore so neither the
  # archived password nor cron becomes usable before PRAHO's ownership commit.
  if [[ $recovery == 1 ]]; then
    restore_flags+=(--except-feature unix --except-feature ssl)
    "$ssl_helper" --source "$staging/$2" --destination "$ssl_archive" --domain "$domain" \
      --domain-id "$domain_id" --sha256 "$3" || fail "ssl_paths_not_prepared_before_$1"
  fi
  ! cancelled || fail "cancelled_before_$1"
  verify_archive "$2" "$3" || fail "archive_not_verified_before_$1"
  printf '%s\n' "$1" >"$progress.step"
  if ! virtualmin restore-domain --domain "$domain" --source "$staging/$2" "${restore_flags[@]}" >"$RUN_DIR/pair-$domain_id.log" 2>&1; then
    # A restore that stops midway may already have rewritten the Apache configuration: cover what it
    # left (best effort, the job is parked either way) before the checkpoint probes it.
    read_surface || true
    barrier_up
    checkpoint "${1}_failed"
    fail "restore_${1}_failed"
  fi
  if [[ $recovery == 1 ]]; then
    # SSL restore otherwise copies source-ID certificate directives and writes into that namespace.
    # The bounded derivative keeps the original SSL vhost settings but forces every certificate
    # directive into the existing target-ID directory before Virtualmin's native callback sees it.
    if ! virtualmin restore-domain --domain "$domain" --source "$ssl_archive" --feature virtualmin --feature ssl \
        >>"$RUN_DIR/pair-$domain_id.log" 2>&1; then
      read_surface || true
      barrier_up
      checkpoint "${1}_ssl_failed"
      fail "restore_${1}_ssl_failed"
    fi
    rm -f -- "$ssl_archive"
  fi
  reapply "after_$1"
}

restore_step base "$base_archive" "$base_sha"
if ((step_hold > 0)); then sleep "$step_hold"; fi
if [[ -n $diff_archive ]]; then restore_step differential "$diff_archive" "$diff_sha"; fi

# ---- verification, then the barrier comes down; the domain stays disabled ----------------------
virtualmin list-domains --domain "$domain" --name-only 2>/dev/null | grep -qxF -- "$domain" || fail domain_missing_after_restore
is_disabled || fail domain_enabled_after_restore
if [[ $recovery == 0 ]]; then
  # This normal pair completes its hold here without a separate release RPC. Retained archive
  # bytes must not authorize this UUID to overwrite a subsequently live account after reboot.
  durable_marker "$durable_cancel_marker"
  barrier_down
  checkpoint barrier_down
  durable_marker "$release_completed"
fi
rm -f -- "$progress" "$progress.step" "$RUN_DIR/pair-$domain_id.log"
emit ok completed true
