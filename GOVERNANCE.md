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
  load. It is not an operational tool, and it must stay stale — see C9 in
  `AGENTS.md`.

## License sign-off

Contributors sign with the Developer Certificate of Origin
(`git commit -s`), checked by CI on every pull request (see
`CONTRIBUTING.md`). A CLA will be adopted before the first
external-corporate contributor; DCO stands until then.

## Maintainers and merges

- This project currently has one maintainer. Every merge into `main` is a
  human decision made by the maintainer; agents prepare, humans merge.
- Every pull request requires a review sign-off, including from the
  maintainer on changes to the governance and agent-instruction files
  (`AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING.md`, this file, `spec/**`,
  `.github/**`).
- If the maintainer count ever grows, branch protection is updated in the
  same change that adds the account.

## Branch protection (current state)

- `main`: signed commits required, required status checks (`.github`
  workflows), required review, maintainer-only merge.
- Force-push to `main`: disabled.
