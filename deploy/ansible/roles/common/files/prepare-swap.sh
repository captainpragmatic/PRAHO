#!/usr/bin/env bash
# Prepare one swap file without overwriting existing data. Linux/GNU tools only.
set -euo pipefail
umask 077

fail() { printf '%s\n' "$1" >&2; exit 1; }
[[ $(id -u) == 0 ]] || fail 'Swap preparation requires root.'
swap_mb=${1:-2048}
[[ $swap_mb =~ ^[1-9][0-9]{0,4}$ ]] || fail 'Invalid swap size in MiB.'
(( swap_mb <= 16384 )) || fail 'Swap size exceeds the supported limit.'
swap_bytes=$((swap_mb * 1024 * 1024))
workspace=/var/lib/praho-swap
candidate=$workspace/pending
destination=/swapfile

exec 9>/run/praho-swap.lock
flock -x 9

if [[ -e $workspace || -L $workspace ]]; then
  [[ ! -L $workspace && -d $workspace ]] || fail 'Unsafe swap workspace.'
  [[ $(stat -c '%u:%a' -- "$workspace") == 0:700 ]] || fail 'Unsafe swap workspace ownership/mode.'
else
  mkdir -m 0700 -- "$workspace"
fi
[[ $(stat -c %d -- "$workspace") == "$(stat -c %d -- /)" ]] || fail 'Swap workspace must share the root filesystem.'

validate_file() {
  [[ ! -L $1 && -f $1 ]] || fail 'Swap path must be an ordinary file.'
  [[ $(stat -c '%u:%a' -- "$1") == 0:600 ]] || fail 'Unsafe swap file ownership/mode.'
}

if [[ -e $destination || -L $destination ]]; then
  validate_file "$destination"
  [[ $(stat -c %s -- "$destination") == "$swap_bytes" ]] || fail 'Existing swap file has a different size; refusing to resize.'
  [[ $(blkid -p -s TYPE -o value -- "$destination") == swap ]] || fail 'Existing file is not swap; refusing to format.'
  if [[ -e $candidate || -L $candidate ]]; then
    validate_file "$candidate"
    [[ $(stat -c '%d:%i' -- "$candidate") == "$(stat -c '%d:%i' -- "$destination")" ]] || fail 'Unrelated pending swap file requires review.'
    rm -- "$candidate"
  fi
  printf 'existing\n'
  exit 0
fi

filesystem=$(findmnt -n -o FSTYPE --target "$workspace")
[[ $filesystem == ext4 || $filesystem == xfs ]] || fail 'Swap allocation supports ext4/XFS only.'
allocated_bytes=0
if [[ -e $candidate || -L $candidate ]]; then
  validate_file "$candidate"
  [[ $(stat -c %h -- "$candidate") == 1 ]] || fail 'Pending swap file has unexpected hard links.'
  (( $(stat -c %s -- "$candidate") <= swap_bytes )) || fail 'Pending swap file exceeds requested size.'
  allocated_blocks=$(stat -c %b -- "$candidate")
  [[ $allocated_blocks =~ ^[0-9]+$ ]] || fail 'Could not determine pending swap allocation.'
  allocated_bytes=$((allocated_blocks * 512))
  if (( allocated_bytes > swap_bytes )); then allocated_bytes=$swap_bytes; fi
fi

# df already excludes the pending file's physical extents, including an interrupted
# allocation. Sparse bytes do not count toward the space already reserved.
free_bytes=$(df -B1 --output=avail -- "$workspace" | awk 'NR == 2 { print $1 }')
[[ $free_bytes =~ ^[0-9]+$ ]] || fail 'Could not determine free disk space.'
(( free_bytes >= swap_bytes - allocated_bytes + 1073741824 )) || fail 'Swap allocation must leave at least 1 GiB free.'

if [[ ! -e $candidate ]]; then
  (set -o noclobber; : > "$candidate")
fi

# A failed/interrupted attempt leaves only this bounded candidate; the next run
# validates and resumes it under the same kernel lock. Never format /swapfile.
fallocate -l "$swap_bytes" -- "$candidate"
mkswap -- "$candidate" >/dev/null
ln -T -- "$candidate" "$destination"
rm -- "$candidate"
printf 'created\n'
