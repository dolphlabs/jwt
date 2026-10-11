#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
slangc=${SLANGC:-slangc}
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/jwt-test.XXXXXX")
trap 'rm -rf "$run_dir"' EXIT HUP INT TERM
actual=$(cd "$run_dir" && "$slangc" "$repo/tests/consumer/main.sl" --run)
expected=$(cat "$repo/tests/consumer/expected.txt")
if [ "$actual" != "$expected" ]; then
    printf '%s\n' "JWT tests: output mismatch" >&2
    printf '%s\n' "--- expected ---" "$expected" "--- actual ---" "$actual" >&2
    exit 1
fi
printf '%s\n' "$actual"
