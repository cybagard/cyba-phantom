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
# Exit: 0 in sync; 1 on any difference (differing line numbers on stderr);
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
trap 'rm -f "$tmp"' EXIT

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

if cmp -s "$GOLDEN" "$tmp"; then
  echo "mirror-diff: $AGENTS_MD C1–C10 table matches $GOLDEN (12 lines, byte-identical)"
  exit 0
fi
# Report line numbers only, never table text: the text is PR-controlled,
# and the runner reads "::" at the start of a line and "##[" anywhere in a
# line as commands. Line N is header (1), separator (2), or rule C(N-2).
# At most 12 lines are reported: the table has 12, and a huge golden file
# must not flood the log.
awk 'FILENAME == ARGV[1] { g[FNR] = $0; gn = FNR; next }
     { t[FNR] = $0; tn = FNR }
     END {
       n = (gn > tn) ? gn : tn
       shown = 0
       for (i = 1; i <= n; i++) {
         if (g[i] == t[i]) continue
         if (shown < 12) printf "  line %d differs\n", i
         shown++
       }
       if (shown > 12) printf "  and %d more differing lines\n", shown - 12
     }' "$GOLDEN" "$tmp" >&2
echo "mirror-diff: C1–C10 table in $AGENTS_MD differs from $GOLDEN (line numbers above)" >&2
exit 1
