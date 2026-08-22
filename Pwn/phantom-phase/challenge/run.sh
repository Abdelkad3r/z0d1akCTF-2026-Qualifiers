#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$HERE/ld-linux-x86-64.so.2" \
  --library-path "$HERE" \
  "$HERE/phantom_phase"
