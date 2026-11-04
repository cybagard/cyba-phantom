#!/bin/sh
# mutate-go — the go command that "make mutate" puts first in PATH.
#
# It runs the real go command (MUTATE_GO) with the time limit MUTATE_CAP, in
# seconds. When go stops at the limit, it adds a line to the file "capped" in
# MUTATE_RUN.
#
# Gremlins tests the module root package for a mutant in a package whose name
# is not the end of its directory path (for example package main). So a test
# run would fail at once, and gremlins counts that failure as a kill. For a
# "go test" call, this script replaces the last argument with MUTATE_TO when
# the last argument is MUTATE_FROM. Both are empty if no replacement is
# needed. tools/mutatepkg finds the two values.
n=$#
i=0
for a; do
	i=$((i + 1))
	if [ "$i" -eq "$n" ] && [ "$1" = test ] && [ -n "$MUTATE_FROM" ] && [ "$a" = "$MUTATE_FROM" ]; then
		a=$MUTATE_TO
	fi
	set -- "$@" "$a"
done
shift "$n"
timeout -s KILL "$MUTATE_CAP" "$MUTATE_GO" "$@"
r=$?
case $r in 124 | 137) echo >>"$MUTATE_RUN/capped" ;; esac
exit $r
