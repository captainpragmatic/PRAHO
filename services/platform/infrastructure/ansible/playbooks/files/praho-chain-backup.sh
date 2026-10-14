#!/bin/bash
# One differential-chain step for one Virtualmin domain, under the per-domain lock.
#
# Run by virtualmin_chain_backup.yml as root on the node. Everything the chain depends
# on happens in this one locked execution: the cancel marker is read, the snapshot
# fingerprint is read before and after, the differential's expected fingerprint is
# checked, and the backup runs. Nothing in the result can come from a different run.
#
# Inputs (environment only, never interpolated into this script):
#   PRAHO_CHAIN_ACTION    run | cancel
#   PRAHO_CHAIN_MODE      base | differential (run only)
#   PRAHO_DOMAIN          the domain name
#   PRAHO_DOMAIN_ID       Virtualmin's numeric domain id, read by PRAHO from list-domains
#   PRAHO_CHAIN_TOKEN     the job's run token (a UUID)
#   PRAHO_ARCHIVE         archive file name inside the private staging directory (run only)
#   PRAHO_EXPECTED_FP     the snapshot fingerprint a differential requires (differential only)
#   PRAHO_LOCK_WAIT       seconds to wait for the lock
#   PRAHO_STAGING_DIR     the private staging directory
#   PRAHO_SNAPSHOT_DIR    optional: where Virtualmin keeps its differential snapshots (tests only;
#                         the playbook never sets it)
#   PRAHO_RUN_DIR         optional: where the lock, markers and log live (tests only)
#
# Output: exactly one line, CHAIN_RESULT=<base64 of a JSON object>. Exit status 0 means the
# result line is trustworthy, including every refusal. Any other exit status means the
# step is uncertain and must be treated as one: the caller never retries it blindly.
set -euo pipefail
umask 077

# The two directories default to the real ones. They can be overridden so the script can run
# against a fake node in a temporary directory; an override must be an absolute path made of a
# safe alphabet with no "..", exactly like every other input.
SNAPSHOT_DIR=${PRAHO_SNAPSHOT_DIR:-/var/webmin/modules/virtual-server/incremental}
RUN_DIR=${PRAHO_RUN_DIR:-/run/praho}
readonly SNAPSHOT_DIR RUN_DIR
safe_dir='^/[A-Za-z0-9._/-]+$'
[[ $SNAPSHOT_DIR =~ $safe_dir && $SNAPSHOT_DIR != *..* ]] || exit 64
[[ $RUN_DIR =~ $safe_dir && $RUN_DIR != *..* ]] || exit 64

action=${PRAHO_CHAIN_ACTION:?}
mode=${PRAHO_CHAIN_MODE:-}
domain=${PRAHO_DOMAIN:?}
domain_id=${PRAHO_DOMAIN_ID:?}
token=${PRAHO_CHAIN_TOKEN:?}
archive=${PRAHO_ARCHIVE:-}
expected_fp=${PRAHO_EXPECTED_FP:-}
lock_wait=${PRAHO_LOCK_WAIT:-60}
staging=${PRAHO_STAGING_DIR:?}

[[ $action =~ ^(run|cancel)$ ]] || exit 64
[[ $domain_id =~ ^[0-9]{1,30}$ ]] || exit 64
[[ $token =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || exit 64
[[ $lock_wait =~ ^[0-9]{1,4}$ ]] || exit 64
[[ $domain =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]] || exit 64
if [[ $action == run ]]; then
  [[ $mode =~ ^(base|differential)$ ]] || exit 64
  [[ $archive =~ ^virtualmin_backup_[0-9a-f]{32}\.tar\.gz$ ]] || exit 64
  if [[ $mode == differential ]]; then
    [[ $expected_fp =~ ^[0-9a-f]{64}:[0-9]+$ ]] || exit 64
  fi
else
  mode=cancel
fi

snapshot="$SNAPSHOT_DIR/$domain_id"
lock_file="$RUN_DIR/chain-$domain_id.lock"
cancel_marker="$RUN_DIR/chain-$domain_id.cancelled.$token"
running_marker="$RUN_DIR/chain-$domain_id.running"
dest="$staging/$archive"

# emit OUTCOME REASON RAN [FP_BEFORE FP_AFTER BACKUP_RC SHA256 SIZE DETAIL]
# Every field is built from validated values or a fixed word; the detail is stripped to a
# safe alphabet. The whole object is base64 so no output stream can reshape it.
emit() {
  local outcome=$1 reason=$2 ran=$3 fp_before=${4:-} fp_after=${5:-}
  local backup_rc=${6:--1} sha=${7:-} size=${8:-0} detail=${9:-}
  local json
  detail=$(printf '%s' "$detail" | tr -cd 'A-Za-z0-9 ._:/-' | cut -c1-200)
  json=$(printf '{"outcome":"%s","reason":"%s","ran":%s,"mode":"%s","domain_id":"%s","token":"%s",' \
    "$outcome" "$reason" "$ran" "$mode" "$domain_id" "$token")
  json+=$(printf '"archive":"%s","fp_before":"%s","fp_after":"%s","backup_rc":%s,"sha256":"%s","size":%s,"detail":"%s"}' \
    "$archive" "$fp_before" "$fp_after" "$backup_rc" "$sha" "$size" "$detail")
  printf 'CHAIN_RESULT=%s\n' "$(printf '%s' "$json" | base64 | tr -d '\n')"
}

# Snapshot fingerprint: sha256 and size of the tar --listed-incremental file, or ABSENT.
fingerprint() {
  local sum size
  if [[ -f $snapshot && ! -L $snapshot ]]; then
    sum=$(sha256sum -- "$snapshot")
    size=$(stat -c %s -- "$snapshot")
    printf '%s:%s' "${sum%% *}" "$size"
  else
    printf 'ABSENT'
  fi
}

# Remove an archive and the sidecars Virtualmin writes beside it (they carry database passwords).
discard_archive() {
  rm -f -- "$dest" "$dest.dom" "$dest.info"
}

install -d -m 0700 -o root -g root "$RUN_DIR"
exec 9>"$lock_file"
if ! flock -w "$lock_wait" 9; then
  emit refused lock_busy false
  exit 0
fi

# The marker is checked under the lock, so a step that waited for the lock while its
# job was being cancelled sees the marker the moment it gets in.
if [[ $action == cancel ]]; then
  install -m 0600 /dev/null "$cancel_marker"
  emit cancelled marker_written false
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
if [[ -e $dest ]]; then
  emit refused archive_exists false
  exit 0
fi

# The id PRAHO passed must be the id of this domain on this node; otherwise the
# fingerprint below would describe some other domain's snapshot.
if ! listed_id=$(virtualmin list-domains --domain "$domain" --id-only 2>/dev/null); then
  emit refused domain_lookup_failed false
  exit 0
fi
if [[ $listed_id != "$domain_id" ]]; then
  emit refused domain_id_mismatch false
  exit 0
fi

fp_before=$(fingerprint)
if [[ $mode == differential && $fp_before != "$expected_fp" ]]; then
  emit refused fingerprint_mismatch false "$fp_before"
  exit 0
fi

printf '%s\n' "$token" >"$running_marker"
trap 'rm -f -- "$running_marker"' EXIT

backup_args=(--domain "$domain" --dest "$dest" --all-features)
if [[ $mode == differential ]]; then
  backup_args+=(--differential)
fi
log_file="$RUN_DIR/chain-$domain_id.log"
if virtualmin backup-domain "${backup_args[@]}" >"$log_file" 2>&1; then
  backup_rc=0
else
  backup_rc=$?
fi
fp_after=$(fingerprint)
detail=$(grep -v '^[[:space:]]*$' "$log_file" | tail -n 1 || true)
rm -f -- "$log_file"

if ((backup_rc != 0)); then
  discard_archive
  emit failed backup_command_failed true "$fp_before" "$fp_after" "$backup_rc" "" 0 "$detail"
  exit 0
fi
if [[ ! -f $dest || -L $dest || ! -s $dest ]]; then
  discard_archive
  emit failed archive_missing true "$fp_before" "$fp_after" 0
  exit 0
fi
# A base must have written a new snapshot; a differential must have left it untouched.
if [[ $mode == base && ( $fp_after == ABSENT || $fp_after == "$fp_before" ) ]]; then
  discard_archive
  emit failed snapshot_not_reset true "$fp_before" "$fp_after" 0
  exit 0
fi
if [[ $mode == differential && $fp_after != "$fp_before" ]]; then
  discard_archive
  emit failed snapshot_changed true "$fp_before" "$fp_after" 0
  exit 0
fi

sum=$(sha256sum -- "$dest")
size=$(stat -c %s -- "$dest")
emit ok completed true "$fp_before" "$fp_after" 0 "${sum%% *}" "$size"
