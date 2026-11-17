#!/usr/bin/env bash
# coverage — the 07 §1 coverage gate.
#
# Usage: tools/coverage.sh [profile]
#
# With no argument, the script runs the whole test suite once (-race, with
# a cover profile). With a profile file as argument, it gates that profile
# and does not run the tests.
#
# The gate computes each package of `go list ./...` on its own. It counts
# only the statements of the files in the package directory. It does not
# count the sub-packages.
#
# The table below has one row for each package: "<package> <floor>". The
# floor is a percentage. The marker "nostmts" is for a package that has no
# statements. 07 §1 requires at least 80 % on internal/{token,score,tlog,
# limiter,store}. Each other floor is the measured coverage minus 2.0.
# A raise of a floor is a change of this table.
#
# The gate fails, with one line that names the package, when:
#   - a package is below its floor;
#   - a package has no row in the table;
#   - a row names a package that `go list ./...` does not list;
#   - a package that has statements has no coverage data;
#   - a row marked nostmts names a package that has statements;
#   - a package of the 07 §1 set has a floor below 80 or the marker.
set -uo pipefail

# Packages of 07 §1. Each must have a floor of at least 80.
required="internal/token internal/score internal/tlog internal/limiter internal/store"

floors='
# package                        floor
bundles/reference                nostmts
cmd/phantom                      95.0
cmd/phantom-verify               95.4
internal/bait                    97.0
internal/bundle                  97.0
internal/bundle/fetch            93.8
internal/config                  96.0
internal/config/configtest       0
internal/egress                  98.0
internal/egress/egresstest       0
internal/event                   96.1
internal/listener                95.3
internal/safefile                93.6
internal/safefile/internal/seam  0
internal/safefile/safefiletest   0
internal/sensortime              97.2
internal/session                 96.1
internal/store                   80
internal/testutil                91.3
internal/tlog                    80
internal/tlog/verifier           87.6
internal/token                   80
internal/verify                  90.9
tools/bundle-sign                92.2
tools/dco                        96.7
tools/mutatepkg                  92.4
tools/stelint                    97.5
tools/trace                      93.5
'

work="$(mktemp -d)" || exit 1
trap 'rm -rf "$work"' EXIT

profile="${1:-}"
if [ -z "$profile" ]; then
  profile="$work/cover.out"
  if ! go test -race -coverprofile="$profile" ./...; then
    echo "coverage FAIL: go test failed"
    exit 1
  fi
elif [ ! -r "$profile" ]; then
  echo "coverage FAIL: cannot read profile $profile"
  exit 1
fi

module="$(go list -m)" || exit 1
go list ./... >"$work/list" || exit 1
printf '%s\n' "$floors" >"$work/floors"

awk -v module="$module" -v required="$required" '
  BEGIN {
    n = split(required, r, " ")
    for (i = 1; i <= n; i++) must[r[i]] = 1
  }
  function rel(path) {                       # import path -> module-relative
    if (path == module) return "."
    return substr(path, length(module) + 2)
  }
  function fail(msg) { print "coverage FAIL: " msg; bad = 1 }
  FILENAME == ARGV[1] {                      # the floor table
    if ($0 ~ /^[ \t]*(#|$)/) next
    if ($1 in floor) fail("two rows for " $1)
    floor[$1] = $2; rows[++nrows] = $1
    next
  }
  FILENAME == ARGV[2] {                      # go list ./...
    listed[rel($1)] = 1; order[++norder] = rel($1)
    next
  }
  FNR == 1 { next }                          # "mode: atomic"
  {                                          # <file:range> <statements> <count>
    file = $1; sub(/:.*/, "", file); sub(/\/[^\/]*$/, "", file)
    pkg = rel(file)
    total[pkg] += $2; if ($3 > 0) covered[pkg] += $2
  }
  END {
    for (i = 1; i <= norder; i++) {
      p = order[i]
      if (!(p in floor)) { fail(p " has no floor row"); continue }
      f = floor[p]
      if ((p in must) && (f == "nostmts" || f + 0 < 80)) {
        fail(p " has a floor of " f " (07 §1 needs at least 80)")
        continue
      }
      if (total[p] == 0) {
        if (f == "nostmts") { print "coverage: " p " has no statements"; continue }
        fail("no coverage data for " p)
        continue
      }
      if (f == "nostmts") { fail(p " is marked nostmts but has statements"); continue }
      pct = 100 * covered[p] / total[p]
      if (pct < f + 0) {
        fail(sprintf("%s at %.1f%% (< %s%%)", p, pct, f))
        continue
      }
      printf "coverage: %s at %.1f%% (floor %s%%)\n", p, pct, f
    }
    for (i = 1; i <= nrows; i++)
      if (!(rows[i] in listed)) fail("stale row " rows[i])
    exit bad
  }
' "$work/floors" "$work/list" "$profile"
