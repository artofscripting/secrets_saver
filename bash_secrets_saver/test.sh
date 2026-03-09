#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/secrets_saver.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

export SS_FILENAME="$tmpdir/secrets.ep"

if [[ -z "${SS_MASTER_KEY:-}" ]]; then
  read -r -s -p "Enter test master key: " SS_MASTER_KEY
  echo
fi
export SS_MASTER_KEY

ss_init "$SS_FILENAME"
ss_set_secret "a" "1"
ss_set_secret "b" "2"

val="$(ss_get_secret "a")"
if [[ "$val" != "1" ]]; then
  echo "expected secret value 1, got: $val" >&2
  exit 1
fi

keys="$(ss_list_secrets)"
if [[ "$keys" != $'a\nb' ]]; then
  echo "unexpected keys output: $keys" >&2
  exit 1
fi

ss_clear_database
if [[ -n "$(ss_list_secrets)" ]]; then
  echo "expected empty key list after clear" >&2
  exit 1
fi

echo "bash_secrets_saver tests passed"
