| Rule | Digest |
|------|--------|
| C1 | One statically linked Go process. No sidecars, Docker, reverse proxy, or external DB daemon. A feature needing a second process is redesigned or dropped. |
| C2 | 512 MB ceiling: steady-state RSS ≤ 60 MB; every request-path allocation is bounded by config. Unbounded growth is a P0. |
| C3 | Under overload, degrade fidelity (drop to per-IP counters), never availability. Restart is acceptable; OOM-kill is not. |
| C4 | The sensor is passive: it never executes, evaluates, proxies, or fetches request-derived content, and never contacts a visiting IP. Outbound is allow-listed: ACME, alert sinks, checkpoint publisher, bundle server. |
| C5 | Every alert is backed by an event whose hash is in the Merkle log *before* the alert is sent; a third party verifies inclusion from checkpoint + event alone. |
| C6 | Honest attribution: bands `human` / `crawler` / `agent-likely` / `agent-confirmed`; `agent-confirmed` requires a callback via an instruction-only surface. Callbacks are never presented as compromises. |
| C7 | Verification open (Apache-2.0: log format, schema, SDK, verifier, skeleton, token scheme); live trap templates, fingerprint tables, scoring rules, and token HMAC seeds are closed, shipped as signed bundles. Raw data never ships (ADR-008). |
| C8 | Privacy by default: raw IPs live 7 days, then HMAC-hash (rotating daily key); raw events live 30 days, then aggregates only. Bodies stored to 4 KB. |
| C9 | Nothing in the open repo is a turnkey attack kit: reference traps are stale, documented as research artifacts (§202c). |
| C10 | No requirement without a test ID, no test without a requirement ID. CI regenerates the traceability matrix and fails on orphans. |
