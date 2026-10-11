#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
slangc=${SLANGC:-slangc}
go_cmd=${GO:-go}
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/jwt-bench.XXXXXX")
if [ "${KEEP_RESULTS:-0}" = "1" ]; then
    trap 'printf "raw benchmark output: %s\n" "$run_dir"' EXIT HUP INT TERM
else
    trap 'rm -rf "$run_dir"' EXIT HUP INT TERM
fi

"$slangc" "$repo/bench/main.sl" -o "$run_dir/slang-bench"
"$go_cmd" build -o "$run_dir/go-bench" "$repo/bench/go/main.go"

summaries=""
for round in 1 2 3 4; do
    s1="$run_dir/slang-a1-$round.txt"
    g1="$run_dir/go-b1-$round.txt"
    g2="$run_dir/go-b2-$round.txt"
    s2="$run_dir/slang-a2-$round.txt"
    "$run_dir/slang-bench" >"$s1"
    "$run_dir/go-bench" >"$g1"
    "$run_dir/go-bench" >"$g2"
    "$run_dir/slang-bench" >"$s2"
    if [ "$round" = "1" ]; then
        slang_token=$(sed -n '1s/^T //p' "$s1")
        go_token=$(sed -n '1s/^T //p' "$g1")
        if [ -z "$slang_token" ] || [ "$slang_token" != "$go_token" ]; then
            printf '%s\n' "Slang and Go produced different compact tokens" >&2
            exit 1
        fi
        printf '%s\n' "cross-language token match ok"
    fi
    summaries="$summaries slang_a1_$round=$s1 go_b1_$round=$g1 go_b2_$round=$g2 slang_a2_$round=$s2"
done

# Each run is named explicitly so the summarizer can preserve ABBA order.
# shellcheck disable=SC2086
"$go_cmd" run "$repo/bench/summarize.go" $summaries
