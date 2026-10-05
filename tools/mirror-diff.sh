#!/usr/bin/env bash
# mirror-diff — verify the C1–C10 constitution table in AGENTS.md is
# byte-identical to the golden spec/constitution-table.md.
#
# The table syncs verbatim from the canonical spec, and the golden is a
# verbatim copy of it. Any byte difference fails the check; the only
# way a row changes is a constitution change landed as a paired change.
#
# Usage: mirror-diff.sh [agents-md] [golden]
#        (defaults: AGENTS.md, spec/constitution-table.md)
#
# Exit: 0 in sync; 1 on any difference (unified diff on stderr);
#       2 on a missing or malformed table.
set -uo pipefail

AGENTS_MD="${1:-AGENTS.md}"
GOLDEN="${2:-spec/constitution-table.md}"

if [ ! -f "$AGENTS_MD" ]; then
  echo "mirror-diff: no such file: $AGENTS_MD" >&2
  exit 2
fi
if [ ! -f "$GOLDEN" ]; then
  echo "mirror-diff: no such file: $GOLDEN" >&2
  exit 2
fi

tmp="$(mktemp)" || exit 2
trap 'rm -f "$tmp" "$tmp.d"' EXIT

# The table block: the "| Rule | Digest |" header, its separator, and the
# ten C-rows — 12 lines (awk stops after the 12th), LF-normalized
# (.gitattributes pins eol=lf).
sed -e 's/\r$//' "$AGENTS_MD" | awk '
  /^\| Rule \| Digest \|$/ { if (found) exit; found = 1; n = 0 }
  found { print; if (++n == 12) exit }
' > "$tmp"

lines=$(wc -l < "$tmp" | tr -d '[:space:]')
if [ ! -s "$tmp" ]; then
  echo "mirror-diff: no C1–C10 table (\"| Rule | Digest |\" header) in $AGENTS_MD" >&2
  exit 2
fi
if [ "$lines" -ne 12 ]; then
  echo "mirror-diff: table block in $AGENTS_MD has $lines lines, want 12 (header + separator + 10 rows)" >&2
  exit 2
fi
tablelines=$(grep -c '^|' "$tmp" || true)
if [ "$tablelines" -ne 12 ]; then
  echo "mirror-diff: table block in $AGENTS_MD is malformed (only $tablelines of 12 lines are table rows)" >&2
  exit 2
fi

if diff -u "$GOLDEN" "$tmp" > "$tmp.d" 2>&1; then
  echo "mirror-diff: $AGENTS_MD C1–C10 table matches $GOLDEN (12 lines, byte-identical)"
  exit 0
fi
# The diff carries PR-authored bytes. cat -v shows control bytes, and the
# "  > " prefix keeps every line from starting with a runner command
# ("::" or "##["), because the runner trims leading spaces only.
cat -v "$tmp.d" | sed 's/^/  > /' >&2
echo "mirror-diff: C1–C10 table in $AGENTS_MD differs from $GOLDEN (diff above)" >&2
exit 1
