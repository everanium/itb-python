#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Python binding:
# runs the utility with every argument passed through. The binding is
# pure Python over ctypes, so there is nothing to compile here;
# build.sh owns libitb3.so and the compile check over the sources.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

exec python3 loop/main.py "$@"
