# spec — synced spec mirror

This directory is a synced, read-only copy of the canonical spec documents
in the private sibling repository (in the multi-root workspace both are
open, and the canonical copy wins on any disagreement).

| File | What it is |
|------|------------|
| `01-prd.md` | Product requirements: goals G1–G5, FR, NFR, SEC (ID conventions per the spec kit) |
| `07-test-plan.md` | Test plan: every T-ID and what it covers |
| `08-traceability.md` | The C10 traceability matrix (requirement → design → tests) |
| `constitution-table.md` | The C1–C10 table exactly as it appears in the public `AGENTS.md` — the golden for `tools/mirror-diff.sh` |
| `manifest.json` | The sync stamp: sha256 of every file in this directory (except itself) + the sync date |

Rules:

- Do not edit these files directly. Spec changes are made in the
  canonical repository and land here only via the maintainer's sync PR,
  which also rotates the `manifest.json` stamp.
- CI verifies the sync on every PR: `tools/trace` regenerates
  `08-traceability.md` from `01` + `07` and requires a byte-exact match,
  then re-hashes this directory against the stamp.
- `constitution-table.md` is a verbatim copy of the C1–C10 table in the
  internal `AGENTS.md` (D2): both instruction files carry a byte-identical
  table, and the internal repo's CI runs the same check in the other
  direction, so the three (internal table, public table, golden) cannot
  drift apart.
