#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Python binding.
# Verifies libitb.so is present, sets LD_LIBRARY_PATH, then invokes
# `python -m unittest discover` against the tests/ tree. Forwards any
# positional arguments through to unittest (e.g. a specific test path).
#
# Usage:
#   ./run_tests.sh                                 # full discover-and-run
#   ./run_tests.sh tests/test_blake3.py            # one file
#   ./run_tests.sh tests/easy.test_persistence    # one module via dotted path

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

if [[ ! -f "$DIST_DIR/libitb.so" ]]; then
    echo "error: libitb.so not found at $DIST_DIR" >&2
    echo "       run ./build.sh first" >&2
    exit 1
fi

export LD_LIBRARY_PATH="$DIST_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

if [[ $# -gt 0 ]]; then
    exec python -m unittest -v "$@"
fi

exec python -m unittest discover -v tests
