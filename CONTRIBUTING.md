# Contributing

Read `AGENTS.md` first — it is the contract (licensing, constitution
C1–C10, hard rules, non-choices). This file adds the working agreement.

## Getting changes in

1. Fork, branch, and open a pull request. Every commit must carry a
   sign-off under the Developer Certificate of Origin (DCO) 1.1: sign
   with `git commit -s` (see <https://developercertificate.org>). CI
   checks every commit in each PR, and an unsigned commit fails. We
   adopt a CLA before the first external-corporate contributor. Until
   then, the DCO is the contribution license.
2. The maintainer reviews every PR and is the final merge gate (see
   `GOVERNANCE.md`). From the day the repository is public, branch
   protection on `main` requires the CI checks and blocks force-push.
   Required review lands with the second approver account. (DCO sign-off is a commit trailer, not a signed commit.)
3. Make small changes that are easy to review. In the PR body, name the
   constitution rules that the change touches.
4. Write all prose in ASD-STE100 (Simplified Technical English): docs,
   PR and issue text, commit messages, code comments, and user-facing
   strings. Use short sentences, active voice, and one meaning for each
   word. Do not edit the synced `spec/` files. See `GOVERNANCE.md`.

## Spec documents (`spec/`)

`spec/` is a synced, read-only copy of the canonical spec kit (the private
sibling repository is the source of truth). **Do not edit these files
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
`LICENSE`, `spec/**`, `.github/**`, `Makefile`, or `go.mod` get extra
scrutiny. Most of these files steer the coding agents that work in this
repository and its sibling, so they are prompt-injection surface.
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

The build runs Go 1.27.1 exactly: `go.mod` sets the minimum and the
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
BASE=<sha> HEAD=<sha>` re-checks sign-off locally.
