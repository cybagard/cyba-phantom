# 07 — Test plan

## 1. Strategy
Five layers, each gating the next. Everything runs in CI except soak, which runs nightly on the reference VPS.

| Layer | Tooling | Runs | Gate |
|-------|---------|------|------|
| Unit (`T-U`) | `go test -race`, table-driven, fuzz targets | every push | 100 % pass, coverage ≥ 80 % on `internal/{token,score,tlog,limiter,store}` |
| Integration (`T-I`) | `go test` with real listener on ephemeral ports, real SQLite in tmpdir, Pebble ACME test CA | every push | 100 % pass |
| Performance (`T-P`) | `vegeta`/`oha` against binary in a 1 vCPU / 512 MB cgroup (`systemd-run -p MemoryMax=512M -p CPUQuota=100%`) | nightly + release | NFR targets |
| Security (`T-S`) | fuzzers, `gosec`, `govulncheck`, egress test, unit-file lint | every push (static) / nightly (dynamic) | zero high findings |
| Acceptance (`T-A`) | agent simulator harness against installed sensor on reference VPS | release candidate | PRD goals G1–G5 |
| Chaos (`T-C`) | fault injection scripts on reference VPS | release candidate | C3 holds |

## 2. Environments
- **CI:** GitHub Actions ubuntu-24.04 runner, cgroup-limited job for T-P.
- **Reference VPS:** Ubuntu 24.04, 1 vCPU, 512 MB, 20 GB, public IP, DNS `canary-test.<domain>`; rebuilt from `ops/install.sh` before every T-A run.
- **Simulator host:** separate machine so load generation doesn't share the 1 vCPU.

## 3. Test cases

### Unit
| ID | Covers | Test |
|----|--------|------|
| T-U-01 | FR-03, SEC-08, C7 | Tokens: uniqueness over 1 M mints, 128-bit entropy check, verify(mint(x)) = x, verify rejects 1-bit flips |
| T-U-02 | FR-06 | Scoring table-driven: each rule in 05 with boundary values; band monotonic upward past `agent-likely` |
| T-U-03 | FR-05 | JA4 computation matches published vectors (≥ 20 known ClientHellos) |
| T-U-04 | FR-05 | H2 fingerprint from recorded SETTINGS frames of Chrome/Firefox/curl/Go/Python-httpx |
| T-U-05 | FR-05 | Header-order hash stable across header casing, sensitive to order |
| T-U-06 | FR-07 | Canonical JSON: JCS compliance vectors; hash stable across field insertion order |
| T-U-07 | FR-07 | tlog append + inclusion proof + consistency proof verify; fuzz random sizes 1..10 000 |
| T-U-08 | FR-02, SEC-05 | Bundle loader: valid, bad sig, expired, wrong min_engine, malformed manifest, template parse error → correct rejection code; running bundle untouched |
| T-U-09 | SEC-02 | Limiter: token bucket math, conn cap, header/body caps (property-based) |
| T-U-10 | FR-12 | Config: every key validated; unknown key error names the key; env override precedence |
| T-U-11 | FR-11 | Retention SQL on synthetic 100-day dataset: ip NULLed at 7 d, bodies at 30 d, aggregates present, cap eviction oldest-first |
| T-U-12 | FR-09 | Checkpoint note format round-trips through `golang.org/x/mod/sumdb/note`; wrong key fails |
| T-U-13 | FR-08, SEC-06 | Alert payload schema validation; HMAC header correct; retry with backoff on 5xx, no retry on 4xx |
| T-U-14 | FR-04 | Callback attribution from token alone (session row deleted) still yields trap id |
| T-U-15 | C8 | ip_hmac rotates with day key; same IP different days ≠ equal |
| T-U-16 | SEC-07 | Escaping: fuzz UA/path with ANSI, `<script>`, CRLF into log line, syslog SD, dashboard cell → no raw control chars / HTML |
| T-U-17 | SEC-15, C2, C3, NFR-08 | Event queue: concurrent producers with a stopped writer → enqueue never blocks, lane depths and the byte cap of each lane (bulk 24 MiB, evidence 8 MiB) are never exceeded, each drop is counted one time in `dropped_events` and in the counter of its key; evidence events are accepted while the bulk lane is full by count, and while maximum-size bulk events fill the bulk byte cap (at depth 4096 and 8192); the counter map stays ≤ 4096 keys plus the overflow bucket under 10^6 distinct IPv6 addresses; enqueue after close does not panic |

### Integration
| ID | Covers | Test |
|----|--------|------|
| T-I-01 | FR-01 | Start against Pebble ACME; cert obtained ≤ 120 s; renewal triggered when validity < 30 d (clock skew injected) |
| T-I-02 | FR-03 | Fetch decoy page twice with new sessions; all trap slots declared in the running bundle are present, tokens differ, HTML validates |
| T-I-03 | NFR-05 | Cold start with cached cert → `/healthz` 200 ≤ 2 s |
| T-I-04 | FR-04 | Present token on each of the 4 callback surfaces → `callback` event with correct `surface` within 250 ms |
| T-I-05 | FR-05 | Real TLS client (Go, curl, Chrome via headless) → fingerprint record populated per client |
| T-I-06 | FR-06, FR-08 | Simulated instruction-following session → `agent-confirmed`, alert at all three sinks (mock webhook, mock syslog, MailHog) ≤ 60 s |
| T-I-07 | FR-07, ADR-002, C5 | Kill writer mid-batch (panic injection): no evidence-kind event visible in SQLite without a tlog leaf (request/beacon events store without a leaf); restart recovers |
| T-I-08 | FR-09 | Two checkpoints; consistency proof verifies; after manual tile corruption, `/healthz` 503 and consistency fails |
| T-I-09 | FR-09, SEC-17 | Publisher down for 3 intervals → 3 queued checkpoints published in order on recovery |
| T-I-10 | FR-08, threat: alert storm | 5 000 callbacks in one session → exactly 1 `agent-confirmed` alert + summary; sink calls ≤ 10/min |
| T-I-11 | FR-10, SEC-04 | Dashboard unreachable on decoy vhost; 401 without auth; binds only configured interface |
| T-I-12 | FR-14 | SIGHUP with new bundle: no dropped requests during swap (continuous 200 rps load) |
| T-I-13 | FR-11 | Retention job with clock advanced 91 days; DB size ≤ cap; aggregates intact |
| T-I-14 | FR-16, SEC-18 | `canary-verify` accepts event + checkpoint from T-I-06; rejects modified event |
| T-I-15 | FR-15, NFR-08 | `/metrics` exposes `canary_dropped_events_total`, `canary_queue_depth`, `canary_band_sessions{band=}`, `canary_tlog_write_failed_total` |

### Performance (cgroup: 1 CPU, 512 MB)
| ID | Covers | Load | Pass |
|----|--------|------|------|
| T-P-01 | NFR-01, C2, G3 | idle 10 min | RSS ≤ 60 MB |
| T-P-02 | NFR-02, NFR-03 | 500 rps mixed decoy pages, 10 min | p99 ≤ 25 ms, 0 errors |
| T-P-03 | NFR-01, NFR-02 | ramp to 3 000 rps | ≥ 3 000 rps sustained 5 min, RSS ≤ 150 MB |
| T-P-04 | NFR-06, C3 | 10 000 rps from 50 IPs + 5 rps legit agent session | sensor up; `dropped_events_total` > 0; agent alert ≤ 60 s; RSS ≤ 150 MB; no OOM |
| T-P-05 | NFR-01, C2, SEC-02 | 2 000 idle keep-alive conns + slowloris 500 | RSS ≤ 150 MB; slow conns closed at timeout |
| T-P-06 | NFR-04, G3 | 1 M req/day replay ×30 days (accelerated) | DB ≤ 10 GB, tlog ≤ 0.5 GB |
| T-P-07 | NFR-07, C1 | build | binary ≤ 25 MB, `CGO_ENABLED=0`, reproducible hash across two builds |
| T-P-08 | NFR-01, C2 | 72 h at 100 rps on reference VPS | no RSS growth > 10 %, no restarts |

### Security
| ID | Covers | Test |
|----|--------|------|
| T-S-01 | FR-02, SEC-05 | Bundle MITM: serve tampered bundle from fetch_url → rejected, old bundle serves, `bundle_rejected` event |
| T-S-02 | SEC-03 | Path traversal / template injection fuzz (`../`, `{{`, null bytes) on every route → 404/400, no disk read outside allow-list (strace assert) |
| T-S-03 | SEC-07 | Log/alert injection fuzz end-to-end (webhook body, syslog line, dashboard HTML) |
| T-S-04 | SEC-01, threat A2 | Core dump disabled; `/proc/<pid>/maps` not readable by other users; no key material in journald |
| T-S-05 | SEC-08, C7 | 10 000 tokens → NIST SP 800-22 subset (frequency, runs); no correlation with session id |
| T-S-06 | FR-14, rotation | Bundle past `expires` → `/healthz` degraded warning, ops alert; traps still served (availability over rotation) |
| T-S-07 | SEC-01 | `systemd-analyze security agent-canary` score ≤ 2.0 ("OK"); unit lint in CI |
| T-S-08 | C4 | Egress test: during 1 h simulated traffic, `nftables` counters show outbound only to allow-listed destinations |
| T-S-09 | SEC-09 | `gosec`, `govulncheck`, `staticcheck` clean; SBOM generated |
| T-S-10 | SEC-11, SEC-13, FR-12 | Config parser: fuzz plus fixed cases (alias expansion, > 64 KiB, deep nesting, duplicate key, second document, custom tag, YAML 1.1 boolean, octal integer, `${…}` value, unknown `CANARY_*` variable) → non-zero exit naming the key, bounded time and memory; a known secret marker never appears in `--check` output, errors, or logs; config file writable by other → rejected |
| T-S-11 | SEC-12, SEC-13, SEC-02, SEC-04, SEC-06, C2, C4, C8 | Config bounds: for each row of the 04 §3 bounds table, the minimum and maximum pass and one value past each edge fails naming the key; public `ops.listen`, `http` URL, URL with user information, link-local host, bad `tlog.origin`, unset or short secret variable → rejected; loader allow-list equals the configured endpoints |
| T-S-12 | SEC-14, FR-07, C8 | Event record and encoder: fuzz plus fixed cases (invalid UTF-8, lone surrogate escape, duplicate member name, float, `-0`, integer past 2^53−1, `<>&`, U+2028, non-BMP member names) → an error or the exact RFC 8785 bytes, never a repaired value; output is stable when encoded again; an IP and an `ip_hmac` marker in each constructor input never appear in the canonical bytes; `request` and `beacon` records cannot be hashed; an unknown kind is an error; the largest record is ≤ the fixed maximum size |
| T-S-13 | SEC-16, SEC-17, FR-07, FR-09, C4 | tlog, signer and publisher: a one-leaf log has the root SHA-256(0x00 ‖ event hash); a changed, short or missing tile, or a tile symlink out of the state directory → open fails and a proof is never returned; the signer refuses a smaller tree, the same size with another root, and a tree with no consistency proof to the last signed checkpoint; a key file that is a symlink, has group or other bits, has another owner, or has a key name that is not the origin → error; a missing key on a log with a signed checkpoint → error and no new key; the publisher does not follow a redirect, does not use a proxy from the environment, and sends a spooled checkpoint only after its signature verifies; a key marker and a token marker never appear in logs or errors |
| T-S-14 | SEC-18, FR-16, C5 | Verifier: fuzz plus fixed cases. A real log and real signed checkpoints → verified, with the proof printed. A changed event byte, event bytes that are not canonical, a checkpoint signed by another key, a key name that is not the origin, a note with two signature lines, an input past its size cap, a proof file with a duplicate, unknown or wrong-case member, a non-canonical or short hash, too many hashes, or a size past 2^48 → refused with exit 1 or 2 and no panic. Consistency: a larger tree with a valid proof updates the state; a forked tree, the same size with another root, and an older tree with no proof → refused, and the state does not change; a size-0 state or prior is accepted with no proof, and a size-0 note with another root is refused; checkpoints that are not adjacent verify; a proof at a smaller size with a consistency proof to the checkpoint verifies. A state file that is changed, a symlink, or signed by another key → exit 2, and the state does not change. A control-character and bidirectional-character marker in the event never appears raw in the output. The verifier opens no network connection |

### Acceptance (installed sensor, simulator harness `test/simulator`)
| ID | Covers | Test |
|----|--------|------|
| T-A-01 | FR-06, G1 | 200 `agent-instruction` sessions → ≥ 190 `agent-confirmed` |
| T-A-02 | FR-06, G2, C6 | 20 000 `browser-human` + `verified-crawler` + `dumb-scraper` sessions → ≤ 2 `agent-likely`, 0 `agent-confirmed` |
| T-A-03 | FR-06, G1, G2, C6 | 200 `agent-noninstruction` sessions → 0 `agent-confirmed`; report `agent-likely` rate (informational) |
| T-A-04 | G5, NFR-09 | Timed install from `ops/install.sh` on fresh VPS by someone other than the author → decoy over TLS ≤ 10 min |
| T-A-05 | FR-08 | Analyst receives alert in Slack (real webhook) with proof; opens dashboard session page; runs `canary-verify` → OK |
| T-A-06 | FR-16, G4, C5 | Third party (no sensor access) verifies inclusion using only public checkpoint + alert JSON |
| T-A-07 | FR-13 | Nightly aggregate export contains no IPs, validates against schema, matches dashboard totals |
| T-A-08 | C7, C9, ADR-003 | Open-source build with reference bundle passes T-I-02..06 (with reference traps) |
| T-A-09 | C8 | 8 days after install: no raw IP in DB (sqlite query) |

### Chaos (reference VPS)
| ID | Covers | Fault | Expect |
|----|--------|-------|--------|
| T-C-01 | C2, C3, NFR-01 | `stress-ng --vm 1 --vm-bytes 300M` alongside | sensor RSS stays under MemoryMax; kernel OOM picks stress-ng, not canary (OOMScoreAdjust) |
| T-C-02 | NFR-04, C3 | fill disk to 92 % | writes stop, `/healthz` 503, decoy still serves, no crash; recovers when space freed |
| T-C-03 | FR-07 | `kill -9` during load, 10× | restart ≤ 5 s; no partial batches; tlog consistent |
| T-C-04 | FR-09 | DNS failure for publisher 2 h | checkpoints queue; ops alert; catch-up on recovery |
| T-C-05 | FR-01 | ACME CA unreachable at renewal time | existing cert keeps serving; retry backoff; ops alert at 14 d left |
| T-C-06 | C8 | clock jump +2 d / −2 d | no retention over-deletion (monotonic guard); token windows tolerate ±1 h |

## 4. Test data & fixtures
- `test/fixtures/clienthello/*.bin` — captured ClientHellos with expected JA4.
- `test/fixtures/h2/*.json` — SETTINGS/priority captures.
- `test/fixtures/bundles/{valid,badsig,expired,minengine,malformed}.cbnd`.
- `test/fixtures/events/*.json` + expected hashes.
- `test/simulator/personas/*.yaml` — persona behaviour definitions.

## 5. Exit criteria per milestone
| Milestone | Must pass |
|-----------|-----------|
| M-1 | T-U-06..12, T-U-17, T-I-01, T-I-03, T-P-07, T-S-10, T-S-11, T-S-12, T-S-13, T-S-14 |
| M-2 | + T-U-01, T-U-08, T-U-14, T-I-02, T-I-04, T-I-12, T-S-01, T-S-02 |
| M-3 | + T-U-02..05, T-U-13, T-U-16, T-I-05..10, T-I-14, T-S-03 |
| M-4 | + T-U-11, T-U-15, T-I-11, T-I-13, T-I-15, T-S-04..09, T-A-04, T-A-09 |
| M-5 (RC) | everything incl. T-P-01..08, T-A-01..08, T-C-01..06 |

## 6. Defect severity
SEV-0 memory/disk unbounded, evidence inconsistency, key leak → blocks release. SEV-1 NFR miss, false `agent-confirmed` → blocks release. SEV-2 functional gap with workaround. SEV-3 cosmetic.
