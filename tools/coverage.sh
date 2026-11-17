#!/usr/bin/env bash
# coverage — the 07 §1 coverage gate.
#
# Usage: tools/coverage.sh [profile]
#
# With no argument, the script runs the whole test suite once (-race, with
# a cover profile). With a profile file as argument, it gates that profile
# and does not run the tests.
#
# The gate computes each package of the module on its own. The module
# packages are the packages of `go list -deps ./...` whose import path is the
# module path or starts with "<module>/". The gate counts only the statements
# of the files in the package directory. It does not count the sub-packages.
# It takes the package set and the Go files from the source, and it checks
# each line of the profile.
#
# The table below has one row for each package: "<package> <floor>". The
# floor is a percentage. The marker "nostmts" is for a package that has no Go
# files and no cgo files. 07 §1 requires at least 80 % on internal/{token,
# score,tlog,limiter,store}. Each other floor is the measured coverage minus
# 2.0, or 0 when the result is below 0. A raise of a floor is a change of
# this table.
#
# The gate fails, with one line that names the package, when:
#   - a package is below its floor;
#   - a package has no row in the table;
#   - two rows name the same package;
#   - a row names a package that `go list ./...` does not list;
#   - a module package is in `go list -deps ./...` and `go list ./...` does
#     not list it;
#   - the Go files or cgo files of a package differ with -race and without
#     -race, or a package is listed without -race and not with -race;
#   - a package that has Go files has no coverage data;
#   - a row marked nostmts names a package that has Go files or cgo files;
#   - a package of the 07 §1 set has a floor below 80 or the marker;
#   - a floor is not nostmts or a number from 0 to 100.
# It also fails, with one line that gives the line number, for a profile line
# that is not "mode: set", "mode: count" or "mode: atomic" as line 1, or
# "<module>/<path>.go:<n>.<n>,<n>.<n> <n> <n>" after it.
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
else
  # A name like "-" or "module=x" is a file, not stdin or an awk assignment.
  case "$profile" in
  /* | ./*) ;;
  *) profile="./$profile" ;;
  esac
  if [ ! -r "$profile" ]; then
    echo "coverage FAIL: cannot read profile $profile"
    exit 1
  fi
fi

module="$(go list -m)" || exit 1
fmt='{{.ImportPath}} {{.GoFiles}} {{.CgoFiles}}'
go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... | LC_ALL=C sort -u >"$work/deps" || exit 1
go list -f "$fmt" ./... >"$work/files" || exit 1
go list -race -f "$fmt" ./... >"$work/racefiles" || exit 1
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
    if (NF != 2 || ($2 != "nostmts" && ($2 !~ /^[0-9]+(\.[0-9]+)?$/ || $2 + 0 > 100))) {
      fail("bad floor on the row of " $1 " (nostmts or a number from 0 to 100)")
      badrow[$1] = 1
    }
    next
  }
  FILENAME == ARGV[2] {                      # go list -deps ./...
    if ($1 == module || index($1, module "/") == 1) {
      deps[rel($1)] = 1; order[++norder] = rel($1)
    }
    next
  }
  FILENAME == ARGV[3] {                      # go list ./...: path, GoFiles, CgoFiles
    listed[rel($1)] = 1; files[rel($1)] = substr($0, length($1) + 2)
    next
  }
  FILENAME == ARGV[4] {                      # the same with -race
    raced[rel($1)] = 1; racefiles[rel($1)] = substr($0, length($1) + 2)
    next
  }
  {                                          # the profile
    seen = 1
    if (badprofile) next
    if (FNR == 1) {
      if ($0 !~ /^mode: (set|count|atomic)$/) {
        fail("profile line 1 is not mode: set, mode: count or mode: atomic")
        badprofile = 1
      }
      next
    }
    # <module>/<path>.go:<n>.<n>,<n>.<n> <statements> <count>
    if (index($0, module "/") != 1 ||
        substr($0, length(module) + 2) !~ /^[^ \t\r:]+\.go:[0-9]+\.[0-9]+,[0-9]+\.[0-9]+ [0-9]+ [0-9]+$/) {
      fail("profile line " FNR " is not <module>/<path>.go:<n>.<n>,<n>.<n> <n> <n>")
      badprofile = 1
      next
    }
    file = $1; sub(/:.*/, "", file); sub(/\/[^\/]*$/, "", file)
    pkg = rel(file)
    total[pkg] += $2; if ($3 + 0 > 0) covered[pkg] += $2
  }
  END {
    if (!seen) fail("profile is empty")
    if (badprofile || !seen) exit 1
    for (i = 1; i <= norder; i++) {
      p = order[i]
      if (!(p in listed)) { fail(p " is a module package of go list -deps ./... but go list ./... does not list it"); continue }
      if (!(p in raced)) { fail(p " is listed without -race and not with -race"); continue }
      if (files[p] != racefiles[p]) { fail(p " has other Go files with -race and without -race"); continue }
      if (!(p in floor)) { fail(p " has no floor row"); continue }
      if (p in badrow) continue
      f = floor[p]
      if ((p in must) && f + 0 < 80) {
        fail(p " has a floor of " f " (07 §1 needs at least 80)")
        continue
      }
      if (f == "nostmts") {
        if (files[p] != "[] []") { fail(p " is marked nostmts but has Go files"); continue }
        print "coverage: " p " has no statements"; continue
      }
      if (total[p] == 0) {
        fail("no coverage data for " p)
        continue
      }
      pct = 100 * covered[p] / total[p]
      if (pct < f + 0) {
        fail(sprintf("%s at %.1f%% (< %s%%)", p, pct, f))
        continue
      }
      printf "coverage: %s at %.1f%% (floor %s%%)\n", p, pct, f
    }
    for (p in raced)
      if (!(p in listed)) fail(p " is listed with -race and not without -race")
    for (i = 1; i <= nrows; i++)
      if (!(rows[i] in listed)) fail("stale row " rows[i])
    exit bad
  }
' "$work/floors" "$work/deps" "$work/files" "$work/racefiles" "$profile"
