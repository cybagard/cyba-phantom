# Agent instructions — cyba-phantom

**Agent Canary** — a self-hosted sensor that plants prompt-injection bait on decoy vhosts, fingerprints every session, scores traffic into `human` / `crawler` / `agent-likely` / `agent-confirmed`, alerts within 60 s, and records every event in a tamper-evident Merkle log with Ed25519-signed checkpoints. Target host: 1 vCPU / 512 MB / 20 GB, Ubuntu 24.04.

The full spec kit lives in the private sibling repository (documentation-only, canonical). This file mirrors its core constraints so the repo is self-contained; in the multi-root workspace both are visible and the spec kit wins on any disagreement.

## Licensing (ADR-006) — read first

- All code in this repo is Apache-2.0, forever. No BSL, no source-available, no closed code.
- The only proprietary artifacts are **content**: signed `.cbnd` bundles (live trap templates, fingerprint tables, scoring rules, token HMAC seeds), distributed out-of-repo under a content license.
- Never commit live or production-grade traps, fingerprint tables, scoring rules, or token seeds. `bundles/reference/` holds a *stale* research-grade reference bundle only (C9: nothing in the open repo is a turnkey attack kit).
- Code review rule: no proprietary constants in `internal/`. The open engine loads content from a bundle; `internal/bundle` (load + Ed25519 verify, open code) is the only path content enters the system.

## Constitution (C1–C10)

These rules override any requirement, ticket, or convenience; a PR that breaks one is rejected even if all tests pass. Normative text: the constitution in the private sibling repo. This table is a mirror — if the internal constitution changes, update this table in the same change.

| Rule | Digest |
|------|--------|
| C1 | One statically linked Go process. No sidecars, Docker, reverse proxy, or external DB daemon. |
| C2 | 512 MB ceiling: steady-state RSS ≤ 60 MB; every request-path allocation is bounded by config. |
| C3 | Under overload, degrade fidelity, never availability. OOM-kill is a P0. |
| C4 | The sensor is passive: it never acts on request-derived content and never contacts a visiting IP; outbound is allow-listed (ACME, alerts, checkpoints, bundle). |
| C5 | Every alert is backed by an event whose hash is in the Merkle log before the alert is sent. |
| C6 | Honest attribution: bands `human` / `crawler` / `agent-likely` / `agent-confirmed`; callbacks are never presented as compromises. |
| C7 | Verification open; live traps, tables, token scheme internals, and raw data closed and shipped as signed bundles. |
| C8 | Privacy: raw IPs 7 days then HMAC-hashed; raw events 30 days then aggregates only; bodies to 4 KB. |
| C9 | The open repo is never a turnkey attack kit; reference traps are stale and documented as research artifacts. |
| C10 | Every requirement has a test ID and every test a requirement ID; the traceability matrix must never contain orphans. |

## Layout

| Path | Role (open code; content marked ◆ arrives via bundle) |
|------|--------------------------------------------------------|
| `cmd/canary` | main: config, wiring, run loop |
| `cmd/canary-verify` | verifier CLI: inclusion proof against a checkpoint |
| `internal/listener` | TLS via certmagic (ACME); ClientHello capture for JA4 |
| `internal/limiter` | conn cap, per-IP token bucket, body/header/path caps |
| `internal/bait` | decoy vhosts, template rendering, per-session token injection, callback surfaces, JS beacon |
| `internal/bundle` | bundle load + Ed25519 verify, hot-reload — the only path to content |
| `internal/token` | mint/verify canary tokens (◇ code; HMAC ◆ seeds from bundle) |
| `internal/fp` | JA4, HTTP/2, header-order, beacon, cadence collectors (tables ◆) |
| `internal/score` | rule-based band engine (rules ◆) |
| `internal/event` | event types, canonical JSON, hashing, bounded queue |
| `internal/store` | modernc SQLite (CGO-free), WAL, batched single writer, migrations, retention |
| `internal/tlog` | tiled Merkle log (`sumdb/tlog`), checkpoint signing, publish queue |
| `internal/alert` | webhook/syslog/SMTP with HMAC, retry, storm control |
| `internal/ops` | dashboard, /metrics, /healthz, /proof on the localhost-only ops listener |
| `internal/safe` | escaping layer for all user-controlled strings (SEC-07) |
| `internal/export` | nightly aggregate export, no IPs |
| `internal/config` | one YAML file + env overrides, `--check` |
| `sdk/` | Go + TS: read checkpoints, verify proofs |
| `tools/` | `trace` (traceability check), `bundle-sign` |
| `bundles/reference/` | stale reference bundle (Apache-2.0, in-repo) |
| `test/` | simulator personas, fixtures, chaos (test IDs per the spec kit) |

## Hard rules

- One process, static, CGO-free (`CGO_ENABLED=0`; modernc SQLite, not mattn). TLS terminates in-process so the ClientHello is visible for JA4.
- Memory: `GOMEMLIMIT=256MiB`, systemd `MemoryMax=300M`. No unbounded allocation on the request path; attach a `go test -bench -benchmem` diff to any hot-path PR; no per-request goroutines beyond net/http's own.
- Ordering invariant (C5, ADR-005): tlog append succeeds before an event is observable; the alerter consumes only sessions whose events have leaf indices. A failed tlog write stops alerts and fires an ops alert — fail closed on evidence, never on availability.
- Bands move only upward past `agent-likely` (no downgrade after an alert; evidence must stay stable). Score change writes a `score_change` event.
- Overload path: drop to per-IP counters, count `dropped_events`, keep serving and keep alerting (≤ 60 s).
- Outbound is the C4 allow-list only. A feature needing another outbound destination breaks C4 and is redesigned or dropped.
- Detection is rule tables over discrete signals, loaded from the bundle (ADR-004). No in-process ML; alerts must remain explainable.
- Fingerprint signals are limited to S1–S8 in the detection spec — no IP reputation, geo, ASN, or any outbound lookup at request time (C4 + C8).

## Spec loop

- The spec kit (private sibling repo) defines reading order and ID conventions. Each task names the requirement IDs it satisfies and the test IDs that must pass.
- Definition of done per task: named tests pass (`go test -race`, coverage threshold held); no new per-request goroutines (bench diff attached); `tools/trace` green; constitution checklist (C1–C10) answered in the PR template; `docs/` updated when an interface changes.
- No requirement without a test ID, no test without a requirement ID (C10).

## Commands

The `Makefile` and CI (lint, `go test -race`, cgroup perf job, `tools/trace`) land with milestone task 1.1. Until they exist, the floor is: `go build ./...`, `go vet ./...`, `go test -race ./...`.

## Non-choices (explicit — do not reintroduce)

nginx/Caddy (second process, hides ClientHello), Postgres, Python/Node, Docker, packet capture, LLM-generated decoy responses, ML fingerprinting, blocking/tarpitting (the sensor observes; blocking is the customer's WAF job).
