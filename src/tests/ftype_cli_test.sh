#!/bin/sh
# Verify --ftype-ext keeps hostile pathname bytes inside one NUL field.

set -eu

: "${FAPOLICYD_CLI:?}"

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/fapolicyd-ftype.XXXXXX")
trap 'rm -rf "$tmpdir"' 0

dir=$(printf '%s\n%s' "$tmpdir/name" "forged: application")
mkdir "$dir"
path=$(printf '%s/%s\n%s\t%s\033' \
	"$dir" "x-executable" "tab" "escape")
printf 'content\n' > "$path"

"$FAPOLICYD_CLI" --ftype-ext="$path" > "$tmpdir/output"

printf '%s\0' "$path" > "$tmpdir/expected-prefix"
prefix_size=$(wc -c < "$tmpdir/expected-prefix")
dd if="$tmpdir/output" of="$tmpdir/actual-prefix" bs=1 \
	count="$prefix_size" 2>/dev/null
cmp -s "$tmpdir/expected-prefix" "$tmpdir/actual-prefix"

tr -cd '\000' < "$tmpdir/output" > "$tmpdir/nuls"
test "$(wc -c < "$tmpdir/nuls")" -eq 2

output_size=$(wc -c < "$tmpdir/output")
test "$output_size" -gt $((prefix_size + 1))
