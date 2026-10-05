#!/usr/bin/env bash
# coverage — the 07 §1 coverage gate.
#
# Runs the whole test suite once (-race, with a cover profile), then gates
# statement coverage per package prefix from that profile.
#
# 07 §1 requires >= 80 % on internal/{token,score,tlog,limiter,store}; in
# M-1 none of those packages exist, so that half of the gate is a vacuous
# pass. Until the gate set lands, the gate applies to tools/ (the only
# real code in the repository).
set -uo pipefail

profile="$(mktemp)" || exit 1
trap 'rm -f "$profile"' EXIT

if ! go test -race -coverprofile="$profile" ./...; then
  echo "coverage FAIL: go test failed"
  exit 1
fi
module="$(go list -m)"

gate() { # gate <package-prefix> <minimum-percent>
  local prefix="$1" min="$2" pct
  pct=$(awk -v p="$module/$prefix/" '
    NR == 1 { next }                       # "mode: atomic"
    index($1, p) == 1 {
      split($0, f, " ")                    # <file:range> <statements> <count>
      total += f[2]; if (f[3] > 0) covered += f[2]
    }
    END { if (total > 0) printf "%.1f", 100 * covered / total }
  ' "$profile")
  if [ -z "$pct" ]; then
    echo "coverage FAIL: no coverage data for $prefix/"
    return 1
  fi
  if awk -v v="$pct" -v m="$min" 'BEGIN { exit !(v < m) }'; then
    echo "coverage FAIL: $prefix/ at ${pct}% (< ${min}%)"
    return 1
  fi
  echo "coverage: $prefix/ at ${pct}%"
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

gate tools 80 || fail=1
exit "$fail"
