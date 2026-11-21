# Contributing

Read `AGENTS.md` first — it is the contract (licensing, constitution
C1–C10, hard rules, non-choices). This file adds the working agreement.

## Getting changes in

1. Sign every commit with `git commit -s`. This adds a `Signed-off-by`
   trailer under the Developer Certificate of Origin (DCO) 1.1 (see
   <https://developercertificate.org>). The `dco` check of CI tests the
   sign-off and the commit identity of every commit in a pull request.
   The check passes only for a commit with the maintainer noreply address
   (`67512030+cybagard@users.noreply.github.com`) as author, committer
   and `Signed-off-by` address. An outside contributor never uses this
   address (see the path for an outside contributor below). The committer
   can also be the GitHub committer address, for a commit that GitHub
   makes. For the check to pass, every address in any other trailer is
   also the maintainer noreply address. The Claude co-author address is
   allowed only on a `Co-authored-by` line for Claude, in a trailer or in
   the text. On that line, the key starts at column 1 and ":" follows it
   directly. The name is "Claude" or starts with "Claude ". The line has
   no other address. The check also reads the whole commit message
   (subject, body, every paragraph and line). The message may hold only
   printable ASCII, TAB, line ends (LF, or CR before LF), and the
   characters U+00A7, U+2014, U+2013, U+2026 and U+00B7. Each "@" in the
   message must be one of four uses. It is inside the maintainer address.
   It is inside the Claude address on a Claude co-author line. It starts a
   mention: `@context`, `@dependabot` or `@cybagard`, and no other name.
   Or it comes before a version such as `x@v1.2.3` or
   `actions/checkout@v5.1.0`. After a mention or a version, a "." and a
   word fail the "@", also after spaces or one line break. A byte that is
   not ASCII cannot follow the maintainer address, a mention or a version.
   Any other "@" fails the check. The author name and the committer name
   follow the same character list and hold no "@". The check also reads
   the header of the commit object. The permitted keys are `tree`,
   `parent`, `author`, `committer`, `gpgsig` and `gpgsig-sha256`. Their
   count and order are fixed, and the `author` and `committer` lines
   have only the name, the address, the time and the time zone. A
   signature holds only armor lines. An `encoding` header fails, also
   with an empty value. The header comment of `tools/dco/main.go` gives
   the full rules, with the forms that fail by design and the known
   limits. A commit that fails one of these rules fails the check.
   An outside contributor forks, branches, commits with `git commit -s`,
   and opens a pull request. An outside contributor commits with their
   own name and address, never with the maintainer address. The `dco`
   check of that pull request fails. This failure is normal. The
   maintainer reviews the change. The maintainer does not merge the
   outside pull request. The maintainer closes it and opens a new pull
   request. The new pull request has a new commit with the maintainer as
   author and only the maintainer sign-off (`git commit -s`). A
   cherry-pick or an amend keeps the outside author and sign-off, so the
   check fails. The text of the new pull request gives the name of the
   contributor and links the outside pull request. The commits in the
   outside pull request keep the contributor sign-off. The text of the
   new pull request must not contain an email address of the
   contributor. This keeps the address of the contributor out of the
   public history.
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
   strings. Use active voice and one meaning for each word. Keep a
   sentence to at most 20 words in a code comment and in text that the
   software shows to users. This text is error messages, log messages,
   and help text. Keep a sentence to at most 25 words in other prose.
   Keep a code comment line to at most 80 columns, with a tab as 4
   columns. The count is for the full source line, with the indent. A
   comment line that holds only a URL can be longer. The command
   `make lint` checks the two comment limits in Go files, except files
   below `testdata`. It checks the lines that you change, and each
   sentence that has a changed line or that a deletion joins. Review
   checks all other comments and prose. Do not edit the synced `spec/`
   files. See `GOVERNANCE.md`.

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
- `tools/trace tests` checks the exit criteria table in section 5 of
  `spec/07-test-plan.md`. A test ID is in one milestone row only. Each
  test ID in the rows from the top of the table down to the
  `TRACE_MILESTONE` row (in the `Makefile`) needs one of two things. The
  first is a top-level Go test in a `*_test.go` file. Its name starts with
  `Test` and the ID without dashes, with no digit after it (of any script):
  T-S-16 gives `TestTS16...`. Files that `go test -race` does not build
  do not count. A build line or file header that does not parse gives a
  finding. The second is a marker line
  `# trace-test: <ID> <target>` in the `Makefile`. The tool checks only
  that a line starts with `<target>:` and that the rest of the line is not
  a variable assignment. A line that ends in an odd number of backslashes
  continues in the next line. Review checks that the target checks the ID.
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
- Prefer the standard library. A new dependency needs a justification in
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

The build runs Go 1.27.3 exactly. `go.mod` sets the minimum, and the
`Makefile` and CI pin the release via `GOTOOLCHAIN`. When your local
toolchain differs, Go downloads that release with checksum verification.
If you do not have Go at all, use the devcontainer — it runs the same
pinned toolchain as CI:

```sh
docker build -t cyba-phantom-dev -f .devcontainer/Dockerfile \
  --build-arg VULNDB_FETCHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)" .devcontainer
docker run --rm -v "$PWD":/src -w /src cyba-phantom-dev make all
```

(Or open the folder with the Dev Containers extension, which uses
`.devcontainer/devcontainer.json`. To fetch a new vulnerability database
copy there, rebuild the container without the build cache.) `make all` runs build, lint,
`go mod tidy -diff`, the coverage gate and `make perf`. The coverage gate runs
the tests with `-race`. Then `make all` runs the C10 trace check and the
constitution-table mirror. The lint step needs the ref `origin/main`, or
`BASE=<sha>`. `make all` does not run two checks of the ci workflow:

- `make fill` needs a small tmpfs.
- `make dco BASE=<sha> HEAD=<sha>` needs BASE and HEAD. It checks the
  sign-off and the commit identity.

The reader oracle test needs GNU tar 1.35 and Python 3.13. Without them it
skips, but in the devcontainer and in CI it fails.
