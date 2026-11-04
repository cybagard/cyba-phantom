#!/bin/sh
# mutate-go — the go command that "make mutate" puts first in PATH.
#
# It runs the real go command (MUTATE_GO) with the time limit MUTATE_CAP, in
# seconds. When go stops at the limit, it adds a line to the file "capped" in
# MUTATE_RUN.
#
# Some package names are not the end of their directory path, for example
# package main. For a mutant in such a package, gremlins tests the module
# root package. That test run fails at once, and gremlins counts the failure
# as a kill.
# For a "go test" call, this script replaces the last argument with MUTATE_TO.
# It does so only when the last argument is MUTATE_FROM.
# Both are empty if no replacement is needed. tools/mutatepkg finds the two
# values. Each replacement adds a line to the file "replaced" in MUTATE_RUN.
#
# Gremlins also counts exit status 1 as a kill. Go exits 1 when it cannot load
# or build the package, and then no test ran. A go vet failure in go test is
# also a build failure. For a "go test" call, this script keeps the output in
# a file in MUTATE_RUN. The file name has its process ID. Then it copies the
# file to stdout. Sometimes go exits 1, and one output line is the FAIL line
# of a setup or build failure. Then the script exits 2 instead. Gremlins
# counts status 2 as not viable.
n=$#
i=0
for a; do
	i=$((i + 1))
	if [ "$i" -eq "$n" ] && [ "$1" = test ] && [ -n "$MUTATE_FROM" ] && [ "$a" = "$MUTATE_FROM" ]; then
		a=$MUTATE_TO
		echo >>"$MUTATE_RUN/replaced"
	fi
	set -- "$@" "$a"
done
shift "$n"
if [ "$1" = test ]; then
	f="$MUTATE_RUN/test-output.$$"
	timeout -s KILL "$MUTATE_CAP" "$MUTATE_GO" "$@" >"$f" 2>&1
	r=$?
	cat "$f"
	tab=$(printf '\t')
	if [ "$r" -eq 1 ] && grep -Eq "^FAIL${tab}[^ ${tab}]+ \[(setup|build) failed\]\$" "$f"; then
		r=2
	fi
else
	timeout -s KILL "$MUTATE_CAP" "$MUTATE_GO" "$@"
	r=$?
fi
case $r in 124 | 137) echo >>"$MUTATE_RUN/capped" ;; esac
exit $r
