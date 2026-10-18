#!/bin/bash
# Point an account name's web root at its customer's site (ADR-0061 P1.15).
#
# Runs AS THE CUSTOMER (runuser, never root): the home directory and everything under it are
# customer-writable, so running as the customer gives this no more access than the customer already
# has, and a link the customer owns is the only kind the node serves (owner-matched symlinks, #734).
#
#   1. every directory from /home/<user> down to the sub-server's home is checked with lstat: a real
#      directory owned by the customer, never a symlink (a swapped path could point at another
#      account's files or at /etc);
#   2. inside the sub-server's home only, public_html becomes the relative link ../../public_html,
#      the customer's own web root. A real directory is first kept as public_html.own, once; the link
#      replaces public_html in one rename.
#
# Idempotent: a correct link changes nothing. Output: one line, LINK=changed or LINK=unchanged, exit 0;
# a refusal is LINK=refused:<reason> with exit 3, and nothing has been changed.
#
# Usage: runuser -u <user> -- /bin/bash -s -- <sub-server home> <user>   (script on stdin)
set -euo pipefail
umask 022

home=${1:?}
user=${2:?}
readonly target=../../public_html

refuse() {
  printf 'LINK=refused:%s\n' "$1"
  exit 3
}

[[ $user =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || refuse bad_user
[[ $home =~ ^/home/[a-z][a-z0-9_-]{0,31}/domains/[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ && $home != *..* ]] || refuse bad_home
[[ $home == "/home/$user/domains/"* ]] || refuse home_not_this_users
[[ $(id -un) == "$user" ]] || refuse not_running_as_the_customer

uid=$(id -u)
real_dir_owned() { # PATH : a directory, not a symlink, owned by the customer
  [[ -d $1 && ! -L $1 ]] || return 1
  [[ $(stat -c %u -- "$1") == "$uid" ]]
}

path=/home/$user
real_dir_owned "$path" || refuse unsafe_path
rest=${home#"/home/$user/"}
IFS=/ read -r -a parts <<<"$rest"
for part in "${parts[@]}"; do
  path=$path/$part
  real_dir_owned "$path" || refuse unsafe_path
done

cd -- "$home"
if [[ -L public_html && $(readlink -- public_html) == "$target" ]]; then
  printf 'LINK=unchanged\n'
  exit 0
fi
if [[ -e public_html && ! -L public_html ]]; then
  [[ -d public_html ]] || refuse public_html_not_a_directory
  [[ ! -e public_html.own && ! -L public_html.own ]] || refuse own_copy_exists
  mv -T -- public_html public_html.own
fi
rm -f -- public_html.new
ln -s -- "$target" public_html.new
mv -T -- public_html.new public_html
printf 'LINK=changed\n'
