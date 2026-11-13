#!/usr/bin/env bash
# xssmap launcher (Linux / macOS)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v python3 >/dev/null 2>&1; then
  exec python3 "${here}/run.py" "$@"
fi
echo "[-] python3 not found" >&2
exit 2
