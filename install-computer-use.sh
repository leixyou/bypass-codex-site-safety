#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ $# -eq 0 ]]; then
  set -- install
fi
exec python3 "$ROOT/computer_use_lab.py" "$@"
