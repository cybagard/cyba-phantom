# 01 — Product requirements: Phantom sensor v1

## Problem statement
Organisations cannot tell whether AI browsing agents are hitting their web properties, nor whether those agents follow instructions planted in page content. Existing bot management blocks or scores traffic but does not test agent behaviour, and none of it produces evidence a third party can verify. A security team that suspects rogue or malicious agents today has nothing to deploy.

## Target users
- **Primary:** security engineer / SOC analyst at a mid-market or enterprise company with public web properties. Runs the sensor on a small VPS or in a DMZ.
- **Secondary:** researcher running the public observatory network (same binary, different bundle and publishing target).

## Goals
| ID | Goal | Measure |
|----|------|---------|
| G1 | Detect agents acting on planted instructions | ≥ 95 % of simulated instruction-following agents reach `agent-confirmed` in the acceptance harness |
| G2 | Keep false alerts rare | < 1 `agent-likely` alert per 10 000 human/crawler sessions in the harness |
| G3 | Run on the minimum VPS | Steady-state RSS ≤ 60 MB; 30 days of traffic at 1 M req/day fits in 10 GB |
| G4 | Produce verifiable evidence | Every alert carries a Merkle inclusion proof that the open verifier accepts |
| G5 | Install in under 10 minutes | Fresh Ubuntu 24.04 → first decoy page served over TLS in ≤ 10 min by a competent admin |

## Non-goals (v1)
- **Blocking or tarpitting traffic.** The sensor observes; blocking is the customer's WAF's job. Mixing them would poison the data.
- **LLM-generated dynamic responses.** Galah-style decoys need a model call per request; violates C1/C2 and adds nothing to instruction-following detection.
- **Multi-node clustering or central management UI.** One sensor, one config. Fleet management is v2.
- **SSH/email/MCP honeypots.** HTTP only in v1; the v1 hashed event format is closed at `v:1` — protocol extension is designed in FR-17 (P2).
- **ML-based fingerprinting.** Rule tables are cheaper, explainable, and updatable via bundle.

## User stories (priority order)
1. As a security engineer, I want to deploy a decoy site that looks like part of our estate so that agents targeting us encounter it.
2. As a security engineer, I want an alert within 60 s when an agent acts on a planted instruction so that I can respond while the session is live.
3. As a SOC analyst, I want each alert to include the fingerprint, the trap that fired, and an inclusion proof so that I can hand it to IR or legal.
4. As a security engineer, I want to update traps without redeploying so that agents can't learn our corpus.
5. As a researcher, I want aggregate stats exported nightly so that the observatory can publish per-family results.
6. As a DPO, I want raw IPs to disappear after 7 days so that logging stays within legitimate interest.
7. As an admin, I want the sensor to keep serving under a 10 000 req/s scan so that a scanner can't blind it.

## Functional requirements

### P0
| ID | Requirement | Acceptance criteria |
|----|-------------|---------------------|
| FR-01 | Serve one or more decoy vhosts over HTTPS with automatic ACME certificates | Given a DNS A record and ports 80/443 open, when the service starts, then a valid cert is obtained within 120 s and renewed ≥ 30 days before expiry |
| FR-02 | Load traps from a signed bundle and reject unsigned/tampered bundles | Given a bundle with a bad signature, when loaded, then the sensor keeps the previous bundle and logs `bundle_rejected` |
| FR-03 | Inject per-session canary tokens into every trap surface (hidden text, HTML comment, fake API link, robots.txt, `.well-known`, meta tag, link `rel`) | Given two requests from different sessions, when pages are compared, then tokens differ and are unpredictable (≥ 128 bit) |
| FR-04 | Record a canary callback when a token is presented on any callback surface (URL path, header, query, POST body) | Given a session S received token T, when any request presents T, then a `callback` event is written linking to S within 250 ms |
| FR-05 | Fingerprint every session (JA4, HTTP/2 SETTINGS/priority fingerprint, header order, UA, Accept-*, JS-execution beacon, request cadence) | Given any TLS session, when the first request completes, then a fingerprint record with all available signals exists |
| FR-06 | Score sessions into bands `human`, `crawler`, `agent-likely`, `agent-confirmed` per `05-detection-spec.md` | Harness thresholds in G1/G2 met |
| FR-07 | Write every event to SQLite; evidence events are appended to the Merkle log before any alert fires | Given an alert, when its inclusion proof is checked against the latest checkpoint, then it verifies |
| FR-08 | Emit alerts for `agent-likely` and `agent-confirmed` via webhook (JSON), syslog (RFC 5424), and SMTP | Given a confirmed session, when scored, then all configured sinks receive the alert within 60 s |
| FR-09 | Publish an Ed25519-signed checkpoint (tree size, root hash, timestamp) at a configurable interval (default 1 h) to ≥ 1 configured target | Given the publisher is unreachable, when the interval passes, then checkpoints queue locally and publish when reachable, in order |
| FR-10 | Local ops dashboard (server-rendered HTML) on a separate listener with basic auth showing sessions by band, recent alerts, bundle version, queue depth, disk/RAM use | Dashboard never served on the decoy vhost; returns 401 without credentials |
| FR-11 | Retention: raw IP → HMAC after 7 d; raw events → aggregates after 30 d; DB size cap with oldest-first eviction | Given DB at cap, when the nightly job runs, then size ≤ cap and aggregates for evicted days remain |
| FR-12 | Configuration from one YAML file plus env overrides; `--check` validates without starting | Invalid config exits non-zero with the offending key |

### P1
| ID | Requirement |
|----|-------------|
| FR-13 | Aggregate export (JSON, nightly) of per-band, per-fingerprint-family counts without IPs |
| FR-14 | Hot-reload bundle on SIGHUP or on-schedule fetch from bundle server |
| FR-15 | Prometheus-style `/metrics` on the ops listener |
| FR-16 | CLI verifier `phantom-verify` (open) that checks an event against a checkpoint. It refuses a checkpoint that is not consistent with the last checkpoint that it accepted for the same key |

### P2 (design for, do not build — exempt from C10 in v1: no v1 tests, no 08 rows)
| ID | Requirement |
|----|-------------|
| FR-17 | Additional protocols (SSH, SMTP, MCP) sharing the event pipeline |
| FR-18 | Fleet mode: many sensors, one aggregator |
| FR-19 | Web Bot Auth / signed-agent header verification as an extra signal |

## Non-functional requirements
| ID | Requirement | Target |
|----|-------------|--------|
| NFR-01 | Memory | RSS ≤ 60 MB idle, ≤ 150 MB at 2 000 concurrent connections; never OOM-killed under T-P tests |
| NFR-02 | Throughput on 1 vCPU | ≥ 3 000 req/s of decoy pages with full fingerprinting; graceful degradation beyond |
| NFR-03 | Latency | p99 ≤ 25 ms for decoy pages at 500 req/s (ACME/TLS handshake excluded) |
| NFR-04 | Disk | 30 days at 1 M req/day ≤ 10 GB; log rotation; never fills the disk (stops writing at 90 %) |
| NFR-05 | Startup | Ready to serve ≤ 2 s after process start (cert already cached) |
| NFR-06 | Overload | At 10 000 req/s from ≤ 50 IPs, sensor stays up, alerts for other sessions still fire ≤ 60 s |
| NFR-07 | Binary | Static, CGO-free (modernc SQLite), ≤ 25 MB, reproducible build |
| NFR-08 | Observability | Structured JSON logs to journald; every dropped event is counted |
| NFR-09 | Installability | Single `.deb` or tarball; no network access needed after install except C4 list |

## Security requirements
| ID | Requirement |
|----|-------------|
| SEC-01 | Runs as unprivileged user; systemd hardening per `ops/phantom.service` |
| SEC-02 | Request body cap 64 KB; header cap 64 headers / 16 KB; path cap 2 KB; connection cap 2 000; per-IP token bucket |
| SEC-03 | No request-derived data is ever used in a filesystem path, shell, SQL text, or outbound URL |
| SEC-04 | Ops listener binds only to localhost or a configured private interface |
| SEC-05 | Bundle signature (Ed25519) verified against a pinned public key compiled into the binary; key rotation via dual-signed transition bundle |
| SEC-06 | Alert webhooks use TLS and an HMAC-SHA256 signature header |
| SEC-07 | Log injection: all user-controlled strings are escaped in logs, alerts, and dashboard (no raw HTML, no ANSI) |
| SEC-08 | Canary tokens are not derivable from session data without the bundle secret |
| SEC-09 | Static analysis (gosec, govulncheck, staticcheck) clean; SBOM generated per release |
| SEC-11 | The config loader fails closed. It reads one YAML document of ≤ 64 KiB. It rejects anchors, aliases, merge keys, custom tags, duplicate keys, more than one document, and non-canonical scalars. On an error, the sensor does not start. `--check` opens no network connection (04 §3, ADR-013) |
| SEC-12 | Config can only make a constitution or `SEC-nn` value stricter. Every numeric key and duration key has a minimum and a maximum (04 §3 bounds table). Retention cannot exceed C8. Configured paths are absolute and clean. Outbound endpoints are the C4 allow-list and use TLS (04 §3, ADR-013) |
| SEC-13 | Secrets never appear in the config file. A `*_env` key names an environment variable that holds the secret. `--check` output, error messages, and logs never contain a secret value or URL credentials. The loader rejects a config file or htpasswd file that other users can write (04 §3, ADR-013) |
| SEC-14 | The hashed event record is the RFC 8785 (JCS) form of a closed field set. It never contains a raw IP, `ip_hmac`, body bytes, cookie values or header values. The encoder rejects invalid UTF-8, lone surrogates, duplicate member names, non-integer numbers, `-0` and integers outside ±(2^53−1). It never repairs a value. Only evidence kinds are hashed (03, ADR-007, ADR-015) |
| SEC-15 | Enqueue of an event never blocks the request path. Evidence events have their own queue lane, so a flood of `request` events cannot drop them. Each lane has a count bound from config and its own byte bound: 24 MiB for the bulk lane and 8 MiB for the evidence lane. The overflow counters key IPv6 by /64 prefix and hold at most 4096 keys. Every dropped event is counted (02, ADR-015, ADR-019) |
| SEC-16 | The tlog leaf hash is SHA-256(0x00 ‖ event hash); the event hash is never a leaf hash. The sensor reads tile hashes only through a check against a trusted tree head. A changed or missing tile stops the tlog, and the sensor never repairs it. The sensor never signs a checkpoint that is not consistent with the last checkpoint that it signed. The signing key is a regular file with mode 0600, owned by the sensor user, at a fixed path; a missing key on a log that has a signed checkpoint stops the signer. tlog files, the key and the checkpoint spool open below the state directory and do not follow a symlink out of it. The key never appears in a log, an error, or `--check` output (04 §5, ADR-020) |
| SEC-17 | The checkpoint publisher connects only to the configured `tlog.publish` URLs. It follows no redirect, uses no proxy from the environment, and verifies TLS. Each publish has a timeout and a cap on the response size. Retries use bounded backoff. The local spool holds a bounded number of checkpoints, and checkpoints publish in order for each target. The publish token is never in a URL, a log, or an error (04 §5, ADR-020) |
| SEC-18 | `phantom-verify` takes the log key only from a file that the user gives, never from the checkpoint, proof or event input. It parses each checkpoint with the strict note rules of 04 §5. It reads each input with a size cap before it parses it, parses proof files strictly, and hashes the event bytes that it received; event bytes that are not in canonical form are refused. It keeps the last accepted checkpoint for each key as a signed note. It refuses a checkpoint without a valid consistency proof to that state or to a given prior checkpoint, and a state file that does not verify. It opens no network connection. Text from the input is escaped in its output, and error text holds no input bytes (04 §7, ADR-021) |

## Success metrics
- **Leading (30 days):** G1/G2 harness pass rate in CI; time-to-first-page in install tests; number of external verifications of published checkpoints.
- **Lagging (6 months):** sensors deployed; agent-confirmed events per sensor-month; zero OOM incidents reported.

## Open questions
| Q | Owner | Blocking? |
|---|-------|-----------|
| Which HTTP/2 fingerprint algorithm to standardise on (Akamai-style vs JA4H2) | Eng | No — start with Akamai-style, keep pluggable |
| Checkpoint publishing target for enterprise customers who refuse GitHub (S3? own witness?) | Product | No |
| Does storing 4 KB of POST body exceed legitimate interest for EU customers? | Legal | Yes for EU GA, not for beta |
| Bundle license terms and rotation cadence | Product | Before paid tier |

## Phasing
- **M-1** skeleton + log + config; **M-2** traps + tokens + callbacks; **M-3** fingerprinting + scoring + alerts; **M-4** retention, dashboard, hardening, install; **M-5** perf/soak on target VPS and release candidate. See `09-implementation-plan.md`.
