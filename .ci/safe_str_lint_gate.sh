#!/usr/bin/env bash
set -euo pipefail

python3 tools/safety/unsafe_api_lint.py "${1:-}"
