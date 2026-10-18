# Contributing

Read `AGENTS.md` first — it is the contract (licensing, constitution
C1–C10, hard rules, non-choices). This file adds the working agreement.

## Getting changes in

1. Every commit in a pull request must carry a `Signed-off-by` trailer
   under the Developer Certificate of Origin (DCO) 1.1: sign with
   `git commit -s` (see <https://developercertificate.org>). The `dco`
   check of CI also tests the commit identity of every commit in the PR.
   The author, the committer, and every `Signed-off-by` address must be
   the maintainer noreply address
   (`67512030+cybagard@users.noreply.github.com`). The committer can also
   be the GitHub committer address, for a commit that GitHub makes. Every
   address in any other trailer must also be the maintainer noreply
   address. Only a `Co-authored-by` trailer can have the Claude co-author
   address. The name in that trailer is "Claude" or starts with "Claude ",
   and the trailer has no other address. The header comment of
   `tools/dco/main.go` gives the full rules. It also covers the rule for
   the encoding header. A commit that fails one of these rules fails the
   check.
   An outside contributor forks, branches, commits with `git commit -s`,
   and opens a pull request. The `dco` check of that pull request fails.
   This failure is normal. The maintainer reviews the change. The
   maintainer does not merge the outside pull request. The maintainer
   closes it and opens a new pull request. The new pull request has a new
   commit with the maintainer as author and only the maintainer sign-off
   (`git commit -s`). A cherry-pick or an amend keeps the outside author
   and sign-off, so the check fails. The text of the new pull request
   gives the name of the contributor and links the outside pull request.
   The outside commits keep the contributor sign-off there. The text has
   no email address of the contributor.
   We adopt a CLA before the first external-corporate contributor. Until
   then, the DCO is the contribution license.
2. The maintainer reviews every PR and is the final merge gate (see
   `GOVERNANCE.md`). From the day the repository is public, branch
   protection on `main` requires the CI checks and blocks force-push and
   deletion.
   (A DCO sign-off is a commit trailer, not a signed commit.)
3. Make small changes that are easy to review. In the PR body, name the
   constitution rules that the change touches.
4. Write all prose in ASD-STE100 (Simplified Technical English): docs,
   PR and issue text, commit messages, code comments, and user-facing
   strings. Use short sentences, active voice, and one meaning for each
   word. Do not edit the synced `spec/` files. See `GOVERNANCE.md`.

## Spec documents (`spec/`)

`spec/` is a synced, read-only copy of the canonical spec kit (the private
sibling repository is the source of truth): 01, the open sections of 04,
07, and 08. **Do not edit these files
directly.** Spec changes are made in the canonical repository and land
here only via the maintainer's sync PR, which also rotates the
`manifest.json` stamp. CI verifies the sync on every PR:

- `tools/trace` regenerates `spec/08-traceability.md` from `01` + `07` and
  requires a byte-exact match (C10), then re-hashes the directory against
  the stamp.
- `tools/mirror-diff.sh` checks the C1–C10 table in `AGENTS.md` against
  the golden `spec/constitution-table.md`.

## High review-surface paths

Changes to `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`,
`LICENSE`, `spec/**`, `.github/**`, `Makefile`, or `go.mod` get a more
careful review. Most of these files steer the coding agents that work
in this repository and its sibling, so they are prompt-injection
surface.
`LICENSE` and `GOVERNANCE.md` set the legal and governance terms.

## Code

- Format: `gofmt` (CI checks); `go vet` clean (CI checks).
- Standard library only in M-1. A new dependency needs a justification in
  the PR body (supply-chain and size budget, C2).
- Memory: nothing unbounded on a request path (C2). Attach a
  `go test -bench -benchmem` diff to any hot-path change.
- Proprietary artifacts (live trap templates, fingerprint tables, scoring
  rules, token HMAC seeds) never go in the repository. They ship only as
  signed bundles (C7). Content enters the system only through
  `internal/bundle`.
  `bundles/reference/` is a stale research-grade artifact (C9); keep it
  stale.

## Developing locally

The build runs Go 1.27.2 exactly: `go.mod` sets the minimum and the
`Makefile`/CI pin the release via `GOTOOLCHAIN` (Go downloads it with
checksum verification when your local toolchain differs). If you do not
have Go at all, use the devcontainer — it runs the same pinned toolchain
as CI:

```sh
docker build -t cyba-phantom-dev -f .devcontainer/Dockerfile .devcontainer
docker run --rm -v "$PWD":/src -w /src cyba-phantom-dev make all
```

(Or open the folder with the Dev Containers extension, which uses
`.devcontainer/devcontainer.json`.) `make all` runs build, lint, tests
(`-race`), the C10 trace check, and the constitution-table mirror.
`make perf` and `make coverage` are the extra gates; `make dco
BASE=<sha> HEAD=<sha>` checks the sign-off and the commit identity
locally.
