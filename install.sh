#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ $# -eq 0 ]]; then
  set -- install --preset shopping-cn --persist
fi
exec python3 "$ROOT/codex_browser_lab.py" "$@"
