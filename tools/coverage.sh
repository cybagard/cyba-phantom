#!/usr/bin/env bash
# coverage — the 07 §1 coverage gate.
#
# 07 §1 requires >= 80 % on internal/{token,score,tlog,limiter,store}; in
# M-1 none of those packages exist, so that half of the gate is a vacuous
# pass. Until the gate set lands, the gate applies to tools/ (the only
# real code in the repository).
set -uo pipefail

gate() { # gate <package> <minimum-percent>
  local pkg="$1" min="$2" line pct
  line=$(go test -race -coverprofile=/dev/null "./$pkg" 2>&1 | tail -1)
  pct=$(printf '%s' "$line" | sed -n 's/.*coverage: \([0-9][0-9]*\.[0-9]*\)%.*/\1/p')
  if [ -z "$pct" ]; then
    echo "coverage FAIL: no coverage result for $pkg ($line)"
    return 1
  fi
  if awk -v v="$pct" -v m="$min" 'BEGIN { exit !(v < m) }'; then
    echo "coverage FAIL: $pkg at ${pct}% (< ${min}%)"
    return 1
  fi
  echo "coverage: $pkg at ${pct}%"
  return 0
}

fail=0
found=0
for p in internal/token internal/score internal/tlog internal/limiter internal/store; do
  if go list "./$p" >/dev/null 2>&1; then
    found=1
    gate "$p" 80 || fail=1
  fi
done
if [ "$found" -eq 0 ]; then
  echo "coverage: 07 §1 gate set (internal/{token,score,tlog,limiter,store}) has no packages yet — vacuous pass"
fi

go test -race -coverprofile=cover.out ./tools/... >/dev/null || fail=1
total=$(go tool cover -func=cover.out 2>/dev/null | awk '/^total:/ {print $3}' | sed 's/%//')
rm -f cover.out
if [ -z "${total:-}" ]; then
  echo "coverage FAIL: no coverage data for ./tools/..."
  fail=1
else
  if awk -v v="$total" 'BEGIN { exit !(v < 80) }'; then
    echo "coverage FAIL: ./tools/... total at ${total}% (< 80%)"
    fail=1
  else
    echo "coverage: ./tools/... total at ${total}%"
  fi
fi
exit "$fail"
