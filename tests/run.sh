#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
slangc=${SLANGC:-slangc}
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/jwt-test.XXXXXX")
trap 'rm -rf "$run_dir"' EXIT HUP INT TERM
# consumer: HS256 and the hardened parser; keys: algorithm-bound keys,
# JWK/JWKS, OIDC and the JWKS client
for t in consumer keys; do
    actual=$(cd "$run_dir" && "$slangc" "$repo/tests/$t/main.sl" --run 2>/dev/null)
    expected=$(cat "$repo/tests/$t/expected.txt")
    if [ "$actual" != "$expected" ]; then
        printf '%s\n' "JWT tests ($t): output mismatch" >&2
        printf '%s\n' "--- expected ---" "$expected" "--- actual ---" "$actual" >&2
        exit 1
    fi
    printf '%s\n' "$actual"
done
