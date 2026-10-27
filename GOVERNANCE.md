# Governance

This repository is open source, permanently.

## Licensing (ADR-006)

- All code is Apache-2.0, forever. No BSL, no source-available tier, no
  closed code.
- The only proprietary artifacts are **content**: signed `.cbnd` bundles
  (live trap templates, fingerprint tables, scoring rules, token HMAC
  seeds). Content is distributed out-of-repo under a separate content
  license; the open engine loads it only through `internal/bundle`
  (load + Ed25519 verify).
- `bundles/reference/` (from M-2) is a stale, research-grade reference
  bundle committed under Apache-2.0 so the open engine has *something* to
  load. It is not an operational tool: it is documented as a research
  artifact (§202c StGB), and it must stay stale — see C9 in `AGENTS.md`.

## License sign-off

Contributors sign with the Developer Certificate of Origin
(`git commit -s`). CI checks the sign-off on every pull request. The
check passes only for commits with the maintainer noreply address as
author, committer and sign-off address. An outside contributor never
uses this address. The committer can also be the GitHub committer
address, for a commit that GitHub makes. See `CONTRIBUTING.md` for the
full rules and for the path of an outside contributor. A CLA will be adopted before the first
external-corporate contributor; DCO stands until then.

## Writing standard

All prose in this repository follows ASD-STE100 (Simplified Technical
English). Prose is documentation, issue and pull request text, commit
messages, code comments, and text that the software shows to users.
These items are not prose: code identifiers, commands, paths, IDs,
quoted and third-party text, legal text (for example `LICENSE`), names
of standards and products, technical terms, and the synced `spec/`
files. Do not change
the C1–C10 table in `AGENTS.md` for STE100: it is a byte-exact mirror.
An STE100 rewrite must not change what a rule means. If a rewrite can
change the meaning, keep the old text and open an issue. The rule
applies to new text and to all text that a change touches.

These limits apply to prose:

- A sentence in a code comment has at most 20 words.
- A sentence in text that the software shows to users has at most 20
  words. This text is error messages, log messages, and help text.
- A sentence in other prose has at most 25 words.
- A code comment line has at most 80 columns. A tab is 4 columns. The
  count is for the full source line, with the indent. A comment line
  that holds only a URL can be longer.

A sentence ends at `.`, `?` or `!` before a space, a line end or the end
of the text. It also ends at the end of a paragraph, a heading, a list
item and a table cell. A colon that introduces a vertical list also ends
it. A colon in a line, a semicolon, a dash and a parenthesis do not end a
sentence. A code span in backticks is one word. In a Markdown link, only
the link text counts. Code blocks do not count. A trailer line
(`Signed-off-by:` or `Co-authored-by:`) does not count, and it ends the
sentence before it.

`make lint` checks two limits in Go files, except files below `testdata`.
These are the length of a comment line and the words in a code comment
sentence. It checks each comment line that a change adds or edits. It
checks a sentence that has such a line, and a sentence that a deletion
joins. Human review checks all other comments and all other prose. This
includes the word limit for text that the software shows to users, the
word limit for other prose, and the other STE100 rules.

## Maintainers and merges

- This project currently has one maintainer. Every merge into `main` is a
  human decision made by the maintainer; agents prepare, humans merge.
- The maintainer reviews every pull request before merging it. Changes to
  the high review-surface paths listed in `CONTRIBUTING.md` get a more
  careful review.
- If the maintainer count ever grows, branch protection is updated in the
  same change that adds the account.

## Branch protection

These settings apply to `main` from the day the repository is public:

- `main`: the `ci` workflow checks (lint, dco, test, trace, mirror-diff,
  build) must pass. Only the maintainer has write access, so only the
  maintainer merges.
- The maintainer is an admin and can bypass the required checks. This is
  accepted while the project has one maintainer.
- Force-push to and deletion of `main`: disabled. The admin cannot
  bypass this rule.
- No required review by a second account: the project has one
  maintainer, and GitHub counts approvals only from accounts with write
  access. The high review-surface paths in `CONTRIBUTING.md` get a more
  careful review.
