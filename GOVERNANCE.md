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
(`git commit -s`), checked by CI on every pull request (see
`CONTRIBUTING.md`). A CLA will be adopted before the first
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
applies to new text and to all text that a change touches. Human review
checks it; no tool checks it.

## Maintainers and merges

- This project currently has one maintainer. Every merge into `main` is a
  human decision made by the maintainer; agents prepare, humans merge.
- The maintainer reviews every pull request before merging it. Changes to
  the high review-surface paths listed in `CONTRIBUTING.md` get extra
  scrutiny.
- If the maintainer count ever grows, branch protection is updated in the
  same change that adds the account.

## Branch protection

These settings apply to `main` from the day the repository is public:

- `main`: the `ci` workflow checks (lint, dco, test, trace, mirror-diff,
  build) must pass. Only the maintainer has write access, so only the
  maintainer merges.
- The maintainer is an admin and can bypass the required checks. This is
  accepted while the project has one maintainer.
- Force-push to and deletion of `main`: disabled.
- No required review by a second account: the project has one
  maintainer, and GitHub counts approvals only from accounts with write
  access. The maintainer reviews every pull request. The high
  review-surface paths in `CONTRIBUTING.md` get extra scrutiny.
