#!/usr/bin/env bash
# Provision the bellud connector vault master key.
#
# Usage:
#   sudo bellucode-vault-init.sh                 # systemd-creds (preferred)
#   sudo bellucode-vault-init.sh --key-file      # 0400 key file fallback
#   bellucode-vault-init.sh --help
#
# Key source order used by bellud at startup:
#   1. OS keyring
#   2. systemd credential  (LoadCredentialEncrypted=bellucode-master-key:/etc/bellucode/master-key.cred)
#   3. key file            (BELLUCODE_MASTER_KEY_FILE)
#   4. passphrase          (BELLUCODE_VAULT_PASSPHRASE)
#
# Default mode needs systemd >= 250. It writes 32 random bytes, encrypted with
# `systemd-creds encrypt --name=bellucode-master-key`, to /etc/bellucode/master-key.cred (0600).
#
# --key-file fallback (systemd < 250, or no systemd-creds): writes 32 raw bytes to
#   ~SERVICE_USER/.config/bellucode/master.key, owner SERVICE_USER, mode 0400. The file must
#   stay outside ~/.local/share/bellucode (the vault data dir). Then add to
#   ~/.config/bellucode/env:  BELLUCODE_MASTER_KEY_FILE=/home/<user>/.config/bellucode/master.key
#   and remove the LoadCredentialEncrypted= line from the unit.
#
# Environment: SERVICE_USER (default: ubuntu), BELLUCODE_CRED_DIR (default: /etc/bellucode).
# Idempotent: an existing key is never overwritten. The key is never printed.
# To rotate, remove the existing file by hand and rerun.
set -euo pipefail
umask 077

CRED_NAME="bellucode-master-key"
SERVICE_USER="${SERVICE_USER:-ubuntu}"
CRED_DIR="${BELLUCODE_CRED_DIR:-/etc/bellucode}"
CRED_FILE="${CRED_DIR}/master-key.cred"

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() { echo "bellucode-vault-init: $*" >&2; exit 1; }

mode="creds"
case "${1:-}" in
  "") ;;
  --key-file) mode="keyfile" ;;
  -h | --help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
id "$SERVICE_USER" >/dev/null 2>&1 || die "user '$SERVICE_USER' does not exist (set SERVICE_USER)"

init_creds() {
  command -v systemd-creds >/dev/null 2>&1 \
    || die "systemd-creds not found; systemd >= 250 is required. Use --key-file instead."
  local ver
  ver="$(systemctl --version | awk 'NR==1 {print $2}')"
  case "$ver" in
    '' | *[!0-9]*) die "cannot determine the systemd version; use --key-file instead." ;;
  esac
  [ "$ver" -ge 250 ] || die "systemd $ver is too old (need >= 250). Use --key-file instead."

  install -d -m 0755 -o root -g root "$CRED_DIR"
  if [ -s "$CRED_FILE" ]; then
    echo "master key credential already exists: $CRED_FILE (unchanged)"
    return
  fi

  local tmp
  tmp="$(mktemp "${CRED_DIR}/.master-key.XXXXXX")"
  trap 'rm -f -- "$tmp"' EXIT
  head -c 32 /dev/urandom \
    | systemd-creds encrypt --name="$CRED_NAME" - "$tmp"
  chmod 0600 "$tmp"
  chown root:root "$tmp"
  mv -f -- "$tmp" "$CRED_FILE"
  trap - EXIT
  echo "created $CRED_FILE (0600)"
  echo "next: install the unit with LoadCredentialEncrypted=${CRED_NAME}:${CRED_FILE}, then restart bellucode"
}

init_keyfile() {
  local home dir file tmp
  home="$(getent passwd "$SERVICE_USER" | cut -d: -f6)"
  [ -n "$home" ] || die "cannot resolve home directory of $SERVICE_USER"
  dir="${home}/.config/bellucode"
  file="${dir}/master.key"

  install -d -m 0700 -o "$SERVICE_USER" -g "$(id -gn "$SERVICE_USER")" "$dir"
  if [ -e "$file" ]; then
    echo "master key file already exists: $file (unchanged)"
    return
  fi

  tmp="$(mktemp "${dir}/.master.key.XXXXXX")"
  trap 'rm -f -- "$tmp"' EXIT
  head -c 32 /dev/urandom >"$tmp"
  chown "$SERVICE_USER:$(id -gn "$SERVICE_USER")" "$tmp"
  chmod 0400 "$tmp"
  mv -f -- "$tmp" "$file"
  trap - EXIT
  echo "created $file (0400, owner $SERVICE_USER)"
  echo "next: add BELLUCODE_MASTER_KEY_FILE=${file} to ${dir}/env, drop LoadCredentialEncrypted= from the unit, restart bellucode"
}

if [ "$mode" = "creds" ]; then init_creds; else init_keyfile; fi
