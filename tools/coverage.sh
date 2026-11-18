#!/usr/bin/env bash
# coverage — the 07 §1 coverage gate.
#
# Usage: tools/coverage.sh [profile]
#
# With no argument, the script runs the whole test suite once (-race, with
# a cover profile). With a profile file as argument, it gates that profile
# and does not run the tests.
#
# The gate computes each package of the module on its own. It counts only
# the statements of the files in the package directory, not the sub-packages.
# The module packages are the packages of `go list -deps ./...` in the module.
#
# The measured build is the -race build of go test, with cgo on. The release
# build is CGO_ENABLED=0 with GOENV=off and GOWORK=off. The two builds must
# have the same module packages. Each package must have the same Go files and
# cgo files in both builds. This holds for each cause: race, cgo, any build
# tag, a file name with a space.
#
# The gate measures the GOOS and GOARCH of the host that runs it. A file only
# for another GOOS or GOARCH has no floor.
#
# The statement counts come from the profile. The gate checks each profile
# line. It cannot find a block that a hand-made profile leaves out. A
# hand-made profile can also add a block or a count in a listed file. A file
# name with a byte that %q escapes, for example a backslash, fails the check.
#
# The table below has one row for each package: "<package> <floor>". The
# floor is a percentage. 07 §1 requires at least 80 % on internal/{token,
# score,tlog,limiter,store}. Each other floor is the measured coverage minus
# 2.0, or 0 when the result is below 0. A raise of a floor is a change of
# this table.
#
# The marker "nostmts" is for a package with no statements. It passes when
# the package has no Go files and no cgo files in both builds. With no
# argument, it also passes when the profile has no line for the package.
#
# The gate fails, with one line that names the package, when:
#   - a package is below its floor;
#   - a package has no row in the table;
#   - two rows name the same package;
#   - a row names a package that `go list ./...` does not list;
#   - a module package is missing from `go list -deps ./...` in one build;
#   - a module package is missing from `go list ./...` in one build;
#   - the Go files or cgo files of a package differ in the two builds;
#   - a package with a number as its floor has no coverage data;
#   - a nostmts row names a package that has Go files, with an argument;
#   - a nostmts row names a package that has a profile line, with no argument;
#   - a package of the 07 §1 set has a floor below 80 or the marker;
#   - a floor is not nostmts or a number from 0 to 100.
# It also fails when the test run fails, the profile file cannot be read,
# or the profile is empty.
# It fails, with one line that gives the line number, when:
#   - line 1 of the profile is not "mode: set", "mode: count" or
#     "mode: atomic";
#   - another line is not "<module>/<path>.go:<n>.<n>,<n>.<n> <n> <n>";
#   - the file of a line is not a Go file or cgo file of a listed package;
#   - the "<file>:<range>" text of a line is in the profile twice. The text
#     "032.2" is not the same text as "32.2".
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
tools/pins                       96.6
tools/stelint                    97.5
tools/trace                      93.5
'

work="$(mktemp -d)" || exit 1
trap 'rm -rf "$work"' EXIT

profile="${1:-}"
given=1
if [ -z "$profile" ]; then
  given=0
  profile="$work/cover.out"
  if ! go test -race -coverprofile="$profile" ./...; then
    echo "coverage FAIL: go test failed"
    exit 1
  fi
else
  # A name like "-" or "module=x" is a file, not stdin or an awk assignment.
  case "$profile" in
  /*) ;;
  *) profile="./$profile" ;;
  esac
  if [ ! -r "$profile" ]; then
    echo "coverage FAIL: cannot read profile $profile"
    exit 1
  fi
fi

module="$(go list -m)" || exit 1
deps='{{if not .Standard}}{{.ImportPath}}{{end}}'
fmt='{{.ImportPath}} {{printf "%q" .GoFiles}} {{printf "%q" .CgoFiles}}'
one='{{range .GoFiles}}{{$.ImportPath}} {{printf "%q" .}}{{"\n"}}{{end}}{{range .CgoFiles}}{{$.ImportPath}} {{printf "%q" .}}{{"\n"}}{{end}}'
release() { GOENV=off GOWORK=off CGO_ENABLED=0 go list "$@"; }
release -deps -f "$deps" ./... | LC_ALL=C sort -u >"$work/rdeps" || exit 1
go list -race -deps -f "$deps" ./... | LC_ALL=C sort -u >"$work/mdeps" || exit 1
release -f "$fmt" ./... >"$work/rlist" || exit 1
go list -race -f "$fmt" ./... >"$work/mlist" || exit 1
go list -race -f "$one" ./... >"$work/mfiles" || exit 1
printf '%s\n' "$floors" >"$work/floors"

awk -v module="$module" -v required="$required" -v given="$given" '
  BEGIN {
    n = split(required, r, " ")
    for (i = 1; i <= n; i++) must[r[i]] = 1
  }
  function rel(path) {                       # import path -> module-relative
    if (path == module) return "."
    return substr(path, length(module) + 2)
  }
  function rest(line, name) { return substr(line, length(name) + 2) }
  function fail(msg) { print "coverage FAIL: " msg; bad = 1 }
  function inmod(path) { return path == module || index(path, module "/") == 1 }
  function check(p, indeps, inlist, build) {
    if (!indeps) { fail(p " is missing from go list -deps ./... of the " build " build"); return 0 }
    if (!inlist) { fail(p " is missing from go list ./... of the " build " build"); return 0 }
    return 1
  }
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
  FILENAME == ARGV[2] {                      # release build: go list -deps
    if (inmod($1)) { rdeps[rel($1)] = 1; order[++norder] = rel($1) }
    next
  }
  FILENAME == ARGV[3] {                      # measured build: go list -deps
    if (inmod($1)) {
      mdeps[rel($1)] = 1
      if (!(rel($1) in rdeps)) order[++norder] = rel($1)
    }
    next
  }
  FILENAME == ARGV[4] {                      # release build: go list
    rlist[rel($1)] = 1; rfiles[rel($1)] = rest($0, $1)
    next
  }
  FILENAME == ARGV[5] {                      # measured build: go list
    mlist[rel($1)] = 1; mfiles[rel($1)] = rest($0, $1)
    next
  }
  FILENAME == ARGV[6] {                      # measured build: one file a line
    allow[rel($1) SUBSEP rest($0, $1)] = 1
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
    file = $1; sub(/:.*/, "", file)
    base = file; sub(/.*\//, "", base)
    dir = file; sub(/\/[^\/]*$/, "", dir)
    pkg = rel(dir)
    if (!((pkg SUBSEP "\"" base "\"") in allow)) {
      fail("profile line " FNR " is not a Go file of a listed package")
      badprofile = 1
      next
    }
    if ($1 in at) {
      fail("profile line " FNR " repeats the block of line " at[$1])
      badprofile = 1
      next
    }
    at[$1] = FNR
    hasline[pkg] = 1
    total[pkg] += $2; if ($3 > 0) covered[pkg] += $2
  }
  END {
    if (!seen) fail("profile is empty")
    if (badprofile || !seen) exit 1
    for (i = 1; i <= norder; i++) {
      p = order[i]
      okm = check(p, p in mdeps, p in mlist, "-race")
      okr = check(p, p in rdeps, p in rlist, "release")
      if (!(okm && okr)) continue
      if (rfiles[p] != mfiles[p]) {
        fail(p " has other Go files or cgo files in the release build than in the -race build")
        continue
      }
      if (!(p in floor)) { fail(p " has no floor row"); continue }
      if (p in badrow) continue
      f = floor[p]
      if ((p in must) && f + 0 < 80) {
        fail(p " has a floor of " f " (07 §1 needs at least 80)")
        continue
      }
      if (f == "nostmts") {
        if (mfiles[p] == "[] []" || (!given && !(p in hasline))) {
          print "coverage: " p " has no statements"; continue
        }
        if (given) fail(p " is marked nostmts but has Go files")
        else fail(p " is marked nostmts but the profile has a line for it")
        continue
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
    for (i = 1; i <= nrows; i++)
      if (!(rows[i] in mlist)) fail("stale row " rows[i])
    exit bad
  }
' "$work/floors" "$work/rdeps" "$work/mdeps" "$work/rlist" "$work/mlist" "$work/mfiles" "$profile"
