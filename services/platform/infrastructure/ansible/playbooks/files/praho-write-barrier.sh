#!/bin/bash
# The migration's write barrier on the source node (ADR-0061 Phase 2, plan amendment E2).
#
# Run by virtualmin_write_barrier.yml as root, under the per-domain migration lock; an action
# refuses to start when the cancel marker of its operation token exists (amendment A).
#
#   record   read-only but for one file: the crontab, kept on this node (STATE_DIR, root-only, never
#            overwritten by a replay; it never leaves the node, so no log can hold it) with the sha256
#            of its active lines, the enabled
#            state of the domain and of every sub-server, the domain's databases and every account
#            holding a privilege on them (lock state, plugin, a digest of the stored credential, a
#            digest of the normalised grants), and every reason the barrier must be refused
#   apply    the fence on administration first (the owner's Webmin sessions deleted and Webmin
#            reloaded, no Webmin request of the owner left, disable-domain --subservers, the user's
#            processes killed), then under it the accounts enumerated again (they must equal the
#            recorded set), locked, and their connections killed; then the barrier is verified
#   verify   read-only: the barrier holds (no active cron job; the domain and every sub-server
#            disabled and serving Virtualmin's disabled page; every recorded account locked, with no
#            connection, and no other account on the databases; no Webmin session or request of the
#            owner; the user's processes only fresh php-fpm and fcgiwrap)
#   release  exactly what was recorded: each account to its recorded lock state, enable-domain only
#            where recorded enabled, the crontab put back by replacement from the kept copy if its
#            active lines differ,
#            then verified, with a probe write as the owner for an enabled domain
#   idle     on the target: no restore-domain or backup-domain of the domain is running (bounded)
#
# release and idle first write the cancel marker of PRAHO_PREVIOUS_TOKEN, then take the lock with a
# bounded wait: holding it proves no earlier command of the migration still runs on this node.
#
# Disable-domain, not cron.deny, stops the jobs: the lab showed cron.deny does not stop an installed
# job and makes enable-domain fail with the jobs left commented. Nothing is interpolated into this
# script: inputs come from the environment and are validated.
#
# Output: exactly one line, BARRIER_RESULT=<base64 of a JSON object>, with exit status 0 whenever the
# result is trustworthy. Any other exit status means the outcome is uncertain.
set -euo pipefail
umask 077

RUN_DIR=${PRAHO_RUN_DIR:-/run/praho}
STATE_DIR=${PRAHO_STATE_DIR:-/var/lib/praho/migration}
WEBMIN_VAR=${PRAHO_WEBMIN_VAR:-/var/webmin}
PROC_DIR=${PRAHO_PROC_DIR:-/proc}
APACHE_SITES=${PRAHO_APACHE_SITES:-/etc/apache2/sites-enabled}
readonly RUN_DIR STATE_DIR WEBMIN_VAR PROC_DIR APACHE_SITES
safe_dir='^/[A-Za-z0-9._/-]+$'
for dir in "$RUN_DIR" "$STATE_DIR" "$WEBMIN_VAR" "$PROC_DIR" "$APACHE_SITES"; do
  [[ $dir =~ $safe_dir && $dir != *..* ]] || exit 64
done

action=${PRAHO_BARRIER_ACTION:?}
domain=${PRAHO_DOMAIN:?}
domain_id=${PRAHO_DOMAIN_ID:?}
token=${PRAHO_OPERATION_TOKEN:?}
previous=${PRAHO_PREVIOUS_TOKEN:-}
saved=${PRAHO_SAVED_TOKEN:-$token}
lock_wait=${PRAHO_LOCK_WAIT:-60}
drain_wait=${PRAHO_DRAIN_WAIT:-60}
accounts_b64=${PRAHO_ACCOUNTS:-}
enabled_b64=${PRAHO_ENABLED:-}
killed_at=${PRAHO_KILLED_AT:-0}
has_crontab_record=${PRAHO_HAS_CRONTAB:-}
crontab_active_sha=${PRAHO_CRONTAB_ACTIVE_SHA:-}

uuid='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
host_ok='^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'
[[ $action =~ ^(record|apply|verify|release|idle)$ ]] || exit 64
[[ $domain =~ $host_ok ]] || exit 64
[[ $domain_id =~ ^[0-9]{1,30}$ ]] || exit 64
[[ $token =~ $uuid ]] || exit 64
[[ -z $previous || $previous =~ $uuid ]] || exit 64
[[ $saved =~ $uuid ]] || exit 64
[[ $lock_wait =~ ^[0-9]{1,4}$ && $drain_wait =~ ^[0-9]{1,4}$ && $killed_at =~ ^[0-9]{1,12}$ ]] || exit 64
[[ $accounts_b64 =~ ^[A-Za-z0-9+/=]*$ && $enabled_b64 =~ ^[A-Za-z0-9+/=]*$ ]] || exit 64
[[ -z $has_crontab_record || $has_crontab_record =~ ^[01]$ ]] || exit 64
[[ -z $crontab_active_sha || $crontab_active_sha =~ ^[0-9a-f]{64}$ ]] || exit 64

lock_file="$RUN_DIR/migration-$domain_id.lock"
cancel_marker="$RUN_DIR/migration-$domain_id.cancelled.$token"
durable_cancel_marker="$STATE_DIR/migration-$domain_id.cancelled.$token"
release_started="$STATE_DIR/migration-$domain_id.$saved.release-started"
release_completed="$STATE_DIR/migration-$domain_id.$saved.release-completed"
kept_crontab="$STATE_DIR/migration-$domain_id.$saved.crontab"
account_ok='^[A-Za-z0-9._@-]{1,80}$'
account_host_ok='^[A-Za-z0-9.%_:-]{1,255}$'
database_ok='^[A-Za-z0-9_]{1,64}$'
fields=""   # extra JSON members of the result, each ',"name":value'

# add NAME JSON : one member of the result (JSON already formed from validated values).
add() { fields+=",\"$1\":$2"; }

# emit OUTCOME REASON : the one result line.
emit() {
  local json
  json=$(printf '{"outcome":"%s","reason":"%s","action":"%s","domain_id":"%s","token":"%s"%s}' \
    "$1" "$2" "$action" "$domain_id" "$token" "$fields")
  printf 'BARRIER_RESULT=%s\n' "$(printf '%s' "$json" | base64 | tr -d '\n')"
}

# stop OUTCOME REASON : report and stop.
stop() {
  emit "$1" "$2"
  exit 0
}

# Persist fence evidence before exposing a writer; IO::Handle sync flushes the file and parent
# directory on both Linux nodes and the macOS fixtures, without a GNU-only sync command.
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

sha() { sha256sum | cut -d' ' -f1; }
unb64() { base64 --decode 2>/dev/null; }
sql() { mysql -N -B -e "$1"; }

owner=""
owner_db_user=""
owner_db_pass=""
multiline=""
read_owner() {
  multiline=$(virtualmin list-domains --domain "$domain" --multiline 2>/dev/null) || return 1
  owner=$(sed -n 's/^ *Username: //p' <<<"$multiline" | head -n1)
  owner_db_user=$(sed -n 's/^ *Username for mysql: //p' <<<"$multiline" | head -n1)
  owner_db_pass=$(sed -n 's/^ *Password for mysql: //p' <<<"$multiline" | head -n1)
  [[ $owner =~ $account_ok ]] || return 1
  [[ -z $owner_db_user || $owner_db_user =~ $account_ok ]] || return 1
}

# The domain itself, then every sub-server under it (its account name, ADR-0061).
names=()
read_names() {
  local children child
  names=("$domain")
  children=$(virtualmin list-domains --parent "$domain" --subserver --name-only 2>/dev/null) || return 1
  while IFS= read -r child; do
    [[ -n $child ]] || continue
    [[ $child =~ $host_ok ]] || return 1
    names+=("$child")
  done <<<"$children"
}

is_disabled() { # NAME
  grep -qxF -- "$1" <<<"$disabled_listing"
}
disabled_listing=""
read_disabled() { disabled_listing=$(virtualmin list-domains --disabled --name-only 2>/dev/null); }

# Active crontab lines: everything but comments and blank lines (the hash survives disable -> enable).
crontab_text() { crontab -u "$owner" -l 2>/dev/null || true; }
active_lines() { grep -vE '^[[:space:]]*(#|$)' || true; }
# Active jobs: active lines that are not environment assignments (MAILTO=, PATH=).
active_jobs() { active_lines | grep -vE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=' || true; }

databases=()
read_databases() {
  local listing db
  databases=()
  listing=$(virtualmin list-databases --domain "$domain" --name-only 2>/dev/null) || return 1
  while IFS= read -r db; do
    [[ -n $db ]] || continue
    [[ $db =~ $database_ok ]] || return 1
    databases+=("$db")
  done <<<"$listing"
}

in_list() { # ITEM : the SQL list of the domain's databases, quoted
  local out="" db
  for db in "${databases[@]-}"; do [[ -z $db ]] || out+="'$db',"; done
  printf '%s' "${out%,}"
}

# Every account holding a privilege on one of the domain's databases, as "user<TAB>host" lines,
# resolved by MariaDB itself (database-level grants may be name patterns).
db_accounts() {
  local db q=""
  # A web-only account has no database grants to fence. An empty derived table is not SQL.
  [[ -n ${databases[*]:-} ]] || return 0
  for db in "${databases[@]}"; do
    q+="SELECT User, Host FROM mysql.db WHERE '$db' LIKE Db UNION "
    q+="SELECT User, Host FROM mysql.tables_priv WHERE Db = '$db' UNION "
    q+="SELECT User, Host FROM mysql.columns_priv WHERE Db = '$db' UNION "
    q+="SELECT User, Host FROM mysql.procs_priv WHERE Db = '$db' UNION "
  done
  sql "SELECT DISTINCT User, Host FROM (${q% UNION }) AS a ORDER BY User, Host"
}

# grants_digest USER HOST : SHOW GRANTS with the stored credential stripped, sorted, hashed.
# Fails if anything credential-like remains.
grants_digest() {
  local grants
  grants=$(sql "SHOW GRANTS FOR '$1'@'$2'") || return 1
  grants=$(sed -E "s/ IDENTIFIED BY PASSWORD '[^']*'//; s/ IDENTIFIED VIA [^ ]+( USING '[^']*')?//" <<<"$grants" | sort)
  if grep -qiE "PASSWORD|IDENTIFIED|USING" <<<"$grants"; then return 1; fi
  printf '%s' "$grants" | sha
}

account_json=""   # the accounts as a JSON array, built by read_accounts
account_lines=""  # the same as "user<TAB>host<TAB>locked" lines
read_accounts() {
  local rows user host locked plugin auth grants entries=""
  account_lines=""
  rows=$(db_accounts) || return 1
  while IFS=$'\t' read -r user host; do
    [[ -n $user ]] || continue
    [[ $user =~ $account_ok && $host =~ $account_host_ok ]] || return 2
    locked=$(sql "SELECT IFNULL(JSON_VALUE(Priv, '\$.account_locked'), 'false') FROM mysql.global_priv WHERE User = '$user' AND Host = '$host'") || return 1
    [[ $locked == true || $locked == 1 ]] && locked=1 || locked=0
    plugin=$(sql "SELECT IFNULL(JSON_VALUE(Priv, '\$.plugin'), '') FROM mysql.global_priv WHERE User = '$user' AND Host = '$host'") || return 1
    [[ $plugin =~ ^[a-z_]{0,40}$ ]] || return 2
    auth=$(sql "SELECT IFNULL(JSON_VALUE(Priv, '\$.authentication_string'), '') FROM mysql.global_priv WHERE User = '$user' AND Host = '$host'" | sha) || return 1
    grants=$(grants_digest "$user" "$host") || return 3
    entries+=$(printf '{"user":"%s","host":"%s","locked":%s,"plugin":"%s","auth_sha":"%s","grants_sha":"%s"},' \
      "$user" "$host" "$([[ $locked == 1 ]] && echo true || echo false)" "$plugin" "$auth" "$grants")
    account_lines+="$user"$'\t'"$host"$'\t'"$locked"$'\n'
  done <<<"$rows"
  account_json="[${entries%,}]"
}

# Why the barrier cannot be put up here; empty when it can. Read-only.
refusal() {
  local count db user host
  for name in "${names[@]}"; do
    if virtualmin list-domains --domain "$name" --multiline 2>/dev/null | grep -qE '^ *Features:.* mail( |$)'; then
      echo "mail_feature"; return 0
    fi
  done
  if sshd -T 2>/dev/null | grep -qiE '^subsystem sftp internal-sftp'; then echo "internal_sftp"; return 0; fi
  count=$(sql "SELECT COUNT(*) FROM mysql.user WHERE is_role = 'Y'") || { echo "database_unreadable"; return 0; }
  [[ $count == 0 ]] || { echo "database_roles"; return 0; }
  if [[ -n ${databases[*]:-} ]]; then
    count=$(sql "SELECT IF(@@event_scheduler = 'ON', (SELECT COUNT(*) FROM information_schema.events WHERE EVENT_SCHEMA IN ($(in_list))), 0)") || { echo "database_unreadable"; return 0; }
    [[ $count == 0 ]] || { echo "database_events"; return 0; }
  fi
  count=$(sql "SELECT COUNT(*) FROM mysql.user WHERE (Insert_priv = 'Y' OR Update_priv = 'Y' OR Delete_priv = 'Y' OR Create_priv = 'Y' OR Drop_priv = 'Y' OR Alter_priv = 'Y' OR Super_priv = 'Y' OR File_priv = 'Y') AND NOT (User IN ('root', 'mysql') AND Host = 'localhost')") || { echo "database_unreadable"; return 0; }
  [[ $count == 0 ]] || { echo "database_global_writer"; return 0; }
  local managed
  managed=$(virtualmin list-users --domain "$domain" --multiline 2>/dev/null \
    | awk '/^ *Unix username: /{u=$3} /^ *Databases: .*\(mysql\)/{print u}') || { echo "users_unreadable"; return 0; }
  while IFS=$'\t' read -r user host _; do
    [[ -n $user ]] || continue
    if [[ $user != "$owner_db_user" ]] && ! grep -qxF -- "$user" <<<"$managed"; then echo "unmanaged_account"; return 0; fi
    count=$(sql "SELECT (SELECT COUNT(*) FROM mysql.db WHERE User = '$user' AND Host = '$host' AND Db NOT IN ($(in_list))) + (SELECT COUNT(*) FROM mysql.tables_priv WHERE User = '$user' AND Host = '$host' AND Db NOT IN ($(in_list))) + (SELECT COUNT(*) FROM mysql.procs_priv WHERE User = '$user' AND Host = '$host' AND Db NOT IN ($(in_list)))") || { echo "database_unreadable"; return 0; }
    [[ $count == 0 ]] || { echo "shared_account"; return 0; }
  done <<<"$account_lines"
  if [[ -n ${databases[*]:-} && -n $owner_db_user ]]; then
    db=${databases[0]}
    count=$(sql "SELECT COUNT(*) FROM mysql.db WHERE User = '$owner_db_user' AND '$db' LIKE Db AND Create_priv = 'Y' AND Insert_priv = 'Y' AND Drop_priv = 'Y'") || { echo "database_unreadable"; return 0; }
    [[ $count != 0 ]] || { echo "owner_cannot_probe"; return 0; }
    if ! is_disabled "$domain" && awk -F'\t' -v u="$owner_db_user" '$1 == u && $3 == 1 { f = 1 } END { exit !f }' <<<"$account_lines"; then
      echo "owner_account_locked"; return 0
    fi
  fi
}

# Webmin: the owner's sessions and requests.
session_store="$WEBMIN_VAR/sessiondb"
owner_sessions() { # prints how many sessions of the owner the store holds
  perl -e 'use Fcntl; use SDBM_File; my ($db, $u) = @ARGV; tie(my %s, "SDBM_File", $db, O_RDONLY, 0600) or exit 4;
    my $n = 0; for my $k (keys %s) { my ($who) = split(/\s+/, $s{$k}); $n++ if defined $who && $who eq $u } print "$n\n"' \
    "$session_store" "$owner"
}
drop_owner_sessions() {
  perl -e 'use Fcntl; use SDBM_File; my ($db, $u) = @ARGV; tie(my %s, "SDBM_File", $db, O_RDWR, 0600) or exit 4;
    for my $k (keys %s) { my ($who) = split(/\s+/, $s{$k}); delete $s{$k} if defined $who && $who eq $u } untie %s' \
    "$session_store" "$owner"
}
reload_webmin() {
  local pid
  pid=$(cat "$WEBMIN_VAR/miniserv.pid" 2>/dev/null || true)
  [[ $pid =~ ^[0-9]{1,10}$ ]] || return 1
  kill -HUP "$pid"
}
owner_requests() { # prints how many processes carry the owner's Webmin login in their environment
  local environ n=0
  for environ in "$PROC_DIR"/[0-9]*/environ; do
    [[ -r $environ ]] || continue
    # A process can end between the glob and the read: its environment is then simply not there.
    if { tr '\0' '\n' <"$environ"; } 2>/dev/null | grep -qxF -- "REMOTE_USER=$owner"; then n=$((n + 1)); fi
  done
  printf '%s\n' "$n"
}

# The domain's restores and backups running here (the remote API runs each as virtual-server/<program>.pl).
domain_operations() {
  local arguments line count=0 domain_arg
  domain_arg="--domain[[:space:]]+${domain//./\\.}([[:space:]]|$)"
  # HTTP execution sets the child process title to the native program but keeps its
  # arguments only in Perl's @ARGV. Neither that child nor remote.cgi can be attributed
  # to a domain from ps. Refuse conservatively until the whole unknown cohort is idle.
  if ! arguments=$(ps -eo args= 2>/dev/null); then printf '1\n'; return; fi
  while IFS= read -r line; do
    if [[ $line =~ virtual-server/remote[.]cgi([[:space:]]|$) ]]; then
      count=$((count + 1))
    elif [[ $line =~ virtual-server/(restore|backup|create|delete)-domain[.]pl([[:space:]]|$) ]]; then
      if [[ $line != *" --domain "* || $line =~ $domain_arg ]]; then count=$((count + 1)); fi
    fi
  done <<<"$arguments"
  printf '%s\n' "$count"
}

# barrier_broken : why the barrier does not hold, or nothing. Read-only.
barrier_broken() {
  local name conf page page_sha body_sha user host locked live expected n now
  read_disabled
  [[ -z $(crontab_text | active_jobs) ]] || { echo "cron_job_active"; return 0; }
  for name in "${names[@]}"; do
    is_disabled "$name" || { echo "not_disabled:$name"; return 0; }
    conf=$(grep -lE "^[[:space:]]*ServerName[[:space:]]+${name//./\\.}[[:space:]]*$" "$APACHE_SITES"/* 2>/dev/null | head -n1 || true)
    [[ -n $conf ]] || { echo "vhost_unknown:$name"; return 0; }
    n=$(grep -cE '^[[:space:]]*<VirtualHost' "$conf" || true)
    [[ $(grep -cE '^[[:space:]]*AliasMatch \^/\.\*\$ .*/disabled_by_virtualmin\.html' "$conf" || true) -ge ${n:-1} ]] || { echo "vhost_open:$name"; return 0; }
    page=$(sed -nE 's/^[[:space:]]*AliasMatch \^\/\.\*\$ (.*disabled_by_virtualmin\.html).*/\1/p' "$conf" | head -n1)
    [[ -r $page ]] || { echo "disabled_page_missing:$name"; return 0; }
    page_sha=$(sha <"$page")
    body_sha=$(curl -sk --max-time 10 --resolve "$name:443:127.0.0.1" "https://$name/" 2>/dev/null | sha)
    [[ $body_sha == "$page_sha" ]] || { echo "serving:$name"; return 0; }
  done
  expected=$(unb64 <<<"$accounts_b64" | cut -f1,2 | sort)
  live=$(db_accounts | sort) || { echo "database_unreadable"; return 0; }
  [[ $live == "$expected" ]] || { echo "accounts_changed"; return 0; }
  while IFS=$'\t' read -r user host _; do
    [[ -n $user ]] || continue
    locked=$(sql "SELECT IFNULL(JSON_VALUE(Priv, '\$.account_locked'), 'false') FROM mysql.global_priv WHERE User = '$user' AND Host = '$host'")
    [[ $locked == true || $locked == 1 ]] || { echo "account_open:$user@$host"; return 0; }
    n=$(sql "SELECT COUNT(*) FROM information_schema.processlist WHERE User = '$user'")
    [[ $n == 0 ]] || { echo "account_connected:$user"; return 0; }
  done <<<"$(unb64 <<<"$accounts_b64")"
  [[ $(owner_sessions) == 0 ]] || { echo "webmin_session"; return 0; }
  [[ $(owner_requests) == 0 ]] || { echo "webmin_request"; return 0; }
  now=$(date +%s)
  while read -r etimes comm; do
    [[ -n ${comm:-} ]] || continue
    [[ $comm =~ ^(php-fpm|fcgiwrap) ]] || { echo "user_process:$comm"; return 0; }
    ((etimes <= now - killed_at)) || { echo "user_process_survived:$comm"; return 0; }
  done <<<"$(ps -o etimes=,comm= -u "$owner" 2>/dev/null || true)"
}

# ---- the lock, and the cancel marker ---------------------------------------------------------------
install -d -m 0700 -o root -g root "$RUN_DIR"
if [[ -e $STATE_DIR || -L $STATE_DIR ]]; then
  [[ -d $STATE_DIR && ! -L $STATE_DIR && $(stat -c '%u:%a' -- "$STATE_DIR") == "0:700" ]] || exit 64
else
  install -d -m 0700 -o root -g root "$STATE_DIR"
fi
if [[ -n $previous ]]; then
  # The previous attempt may still be running here: mark it cancelled before waiting for the lock.
  durable_marker "$STATE_DIR/migration-$domain_id.cancelled.$previous"
  install -m 0600 /dev/null "$RUN_DIR/migration-$domain_id.cancelled.$previous"
fi
if [[ $action == release ]]; then
  durable_marker "$STATE_DIR/migration-$domain_id.cancelled.$saved"
fi
exec 9>"$lock_file"
if ! flock -w "$lock_wait" 9; then
  stop busy lock_busy
fi
if [[ $action == release ]]; then
  [[ ! -e $release_completed ]] || stop ok released
  [[ ! -e $release_started ]] || stop failed release_interrupted
else
  [[ ! -e $cancel_marker && ! -e $durable_cancel_marker && ! -e $release_started && ! -e $release_completed ]] \
    || stop refused cancelled
fi

if [[ $action == idle ]]; then
  for ((i = 0; i <= drain_wait; i++)); do
    [[ $(domain_operations) != 0 ]] || stop ok idle
    sleep 1
  done
  stop busy operation_running
fi

read_owner || stop refused domain_unreadable
read_names || stop refused subservers_unreadable
read_disabled || stop refused domain_unreadable
read_databases || stop refused databases_unreadable
# Webmin's session store must be the SDBM one the fence edits; release never needs it.
if [[ $action != release && ! -e $session_store.pag ]]; then stop refused webmin_sessions_unknown; fi

case $action in
  record)
    read_accounts || stop refused "accounts_unreadable"
    reason=$(refusal)
    [[ -z $reason ]] || stop refused "$reason"
    install -d -m 0700 -o root -g root "$STATE_DIR"
    has_crontab=false
    crontab -u "$owner" -l >/dev/null 2>&1 && has_crontab=true
    if [[ ! -e $kept_crontab ]]; then
      # Kept once: a replay after the fence must never keep the commented crontab instead.
      crontab_text >"$kept_crontab.tmp.$$"
      mv -f -- "$kept_crontab.tmp.$$" "$kept_crontab"
      durable_marker "$kept_crontab"
    fi
    text=$(<"$kept_crontab")
    enabled=""
    for name in "${names[@]}"; do
      enabled+=$(printf '{"name":"%s","enabled":%s},' "$name" "$(is_disabled "$name" && echo false || echo true)")
    done
    dbs=""
    for db in "${databases[@]-}"; do [[ -z $db ]] || dbs+="\"$db\","; done
    add has_crontab "$has_crontab"
    add crontab_sha "\"$(printf '%s' "$text" | sha)\""
    add active_sha "\"$(printf '%s' "$text" | active_lines | sha)\""
    add enabled "[${enabled%,}]"
    add databases "[${dbs%,}]"
    add accounts "$account_json"
    stop ok recorded
    ;;

  apply)
    # The fence on administration first, so nothing creates a writer while the accounts are counted.
    drop_owner_sessions || stop failed webmin_sessions_unwritable
    reload_webmin || stop failed webmin_not_reloaded
    for ((i = 0; ; i++)); do
      [[ $(owner_requests) != 0 ]] || break
      ((i < drain_wait)) || stop failed webmin_request_running
      sleep 1
    done
    virtualmin disable-domain --domain "$domain" --subservers >/dev/null 2>&1 || true
    pkill -KILL -u "$owner" 2>/dev/null || true
    killed=$(date +%s)
    add killed_at "$killed"
    sleep 1
    # Under the fence: the accounts must be exactly the recorded ones.
    read_accounts || stop failed accounts_unreadable
    [[ $(printf '%s' "$account_lines" | cut -f1,2 | sort) == "$(unb64 <<<"$accounts_b64" | cut -f1,2 | sort)" ]] \
      || stop failed accounts_changed
    while IFS=$'\t' read -r user host _; do
      [[ -n $user ]] || continue
      sql "ALTER USER '$user'@'$host' ACCOUNT LOCK" >/dev/null || stop failed "lock_failed"
    done <<<"$account_lines"
    for id in $(sql "SELECT ID FROM information_schema.processlist WHERE User IN ($(cut -f1 <<<"$account_lines" | sed "s/.*/'&'/" | paste -sd, -))" 2>/dev/null || true); do
      [[ $id =~ ^[0-9]+$ ]] && sql "KILL $id" >/dev/null 2>&1 || true
    done
    killed_at=$killed
    broken=$(barrier_broken)
    [[ -z $broken ]] || stop failed "barrier_not_verified:$broken"
    stop ok applied
    ;;

  verify)
    broken=$(barrier_broken)
    [[ -z $broken ]] || stop failed "$broken"
    stop ok holds
    ;;

  release)
    durable_marker "$release_started"
    # Exactly what was recorded: lock states, then the enabled states, then the crontab.
    while IFS=$'\t' read -r user host locked; do
      [[ -n $user ]] || continue
      [[ $user =~ $account_ok && $host =~ $account_host_ok && $locked =~ ^[01]$ ]] || stop failed account_record_invalid
      if [[ $locked == 1 ]]; then mode=LOCK; else mode=UNLOCK; fi
      sql "ALTER USER '$user'@'$host' ACCOUNT $mode" >/dev/null || stop failed unlock_failed
    done <<<"$(unb64 <<<"$accounts_b64")"
    # The domain first, its sub-servers following it as every call does (--subservers); then each
    # sub-server is put back to its own recorded state, so one disabled before stays disabled.
    read_disabled || stop failed domain_unreadable
    while IFS=$'\t' read -r name was_enabled; do
      [[ -n $name ]] || continue
      [[ $name =~ $host_ok && $was_enabled =~ ^[01]$ ]] || stop failed enabled_record_invalid
      if [[ $name == "$domain" ]]; then
        if [[ $was_enabled == 1 ]]; then
          virtualmin enable-domain --domain "$name" --subservers >/dev/null 2>&1 || true
          read_disabled || stop failed domain_unreadable
        fi
      elif [[ $was_enabled == 1 ]] && is_disabled "$name"; then
        virtualmin enable-domain --domain "$name" --subservers >/dev/null 2>&1 || true
      elif [[ $was_enabled == 0 ]] && ! is_disabled "$name"; then
        virtualmin disable-domain --domain "$name" --subservers >/dev/null 2>&1 || true
      fi
    done <<<"$(unb64 <<<"$enabled_b64")"
    [[ -n $crontab_active_sha ]] || stop failed crontab_record_missing
    if [[ $(crontab_text | active_lines | sha) != "$crontab_active_sha" ]]; then
      # A failed or partial enable can leave the jobs commented: put the recorded crontab back.
      [[ -n $has_crontab_record ]] || stop failed crontab_record_missing
      if [[ $has_crontab_record == 0 ]]; then
        crontab -u "$owner" -r >/dev/null 2>&1 || true
      else
        [[ -r $kept_crontab ]] || stop failed crontab_copy_missing
        crontab -u "$owner" "$kept_crontab" || stop failed crontab_not_restored
      fi
    fi
    # Verified against the record, never against "enabled".
    read_disabled || stop failed domain_unreadable
    [[ $(crontab_text | active_lines | sha) == "$crontab_active_sha" ]] || stop failed crontab_differs
    while IFS=$'\t' read -r name was_enabled; do
      [[ -n $name ]] || continue
      if is_disabled "$name"; then now_enabled=0; else now_enabled=1; fi
      [[ $now_enabled == "$was_enabled" ]] || stop failed "enabled_state_differs:$name"
    done <<<"$(unb64 <<<"$enabled_b64")"
    while IFS=$'\t' read -r user host locked; do
      [[ -n $user ]] || continue
      now_locked=$(sql "SELECT IFNULL(JSON_VALUE(Priv, '\$.account_locked'), 'false') FROM mysql.global_priv WHERE User = '$user' AND Host = '$host'")
      [[ $now_locked == true || $now_locked == 1 ]] && now_locked=1 || now_locked=0
      [[ $now_locked == "$locked" ]] || stop failed "lock_state_differs:$user@$host"
    done <<<"$(unb64 <<<"$accounts_b64")"
    if [[ -n ${databases[*]:-} && -n $owner_db_user ]]; then
      probe="praho_barrier_probe_${token:0:8}"
      if is_disabled "$domain"; then
        # Suspended: the owner's login must still be refused.
        if MYSQL_PWD=$owner_db_pass mysql -u "$owner_db_user" -h localhost -N -B -e "SELECT 1" >/dev/null 2>&1; then
          stop failed owner_login_open
        fi
      else
        MYSQL_PWD=$owner_db_pass mysql -u "$owner_db_user" -h localhost -N -B "${databases[0]}" \
          -e "CREATE TABLE $probe (x INT); INSERT INTO $probe VALUES (1); DROP TABLE $probe" >/dev/null 2>&1 \
          || stop failed probe_write_failed
      fi
    fi
    durable_marker "$release_completed"
    rm -f -- "$kept_crontab"
    stop ok released
    ;;
esac
