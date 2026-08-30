#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Python binding.
# Builds libitb.so via build.sh, points ITB_LIBITB_PATH at the
# freshly-built shared library, then invokes
# `python -m unittest discover` against the tests/ tree. Forwards any
# positional arguments through to unittest (e.g. a specific test
# module via dotted path).
#
# Usage:
#   ./run_tests.sh                          # full discover-and-run
#   ./run_tests.sh tests.test_smoke        # one module

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"

if [[ $# -gt 0 ]]; then
    exec python3 -m unittest -v "$@"
fi

exec python3 -m unittest discover -v -s tests -t .
