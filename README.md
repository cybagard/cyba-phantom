# Agent Canary

> **Pre-release.** This project is under active development. It is not ready for production use. Interfaces, file formats, and configuration can change without notice until `v1.0.0-rc1`.

Agent Canary is a self-hosted sensor that detects AI agents. It serves decoy sites with prompt-injection bait, fingerprints each session, and scores the traffic as `human`, `crawler`, `agent-likely`, or `agent-confirmed`.

Goals for v1 (not all built yet):

- **Alerts** within 60 seconds of a confirmed agent.
- **Evidence** in a tamper-evident Merkle log with Ed25519-signed checkpoints. A third party can verify an event from the event and a checkpoint alone.
- **Small footprint:** one static Go binary for a 1 vCPU / 512 MB host.
- **Privacy by default:** raw IP addresses are kept for 7 days, then hashed.

## Build

```sh
make all
```

The build uses Go 1.27.2 (pinned in the `Makefile`).

## Open and closed parts

All code in this repository is Apache-2.0. Live trap templates, fingerprint tables, and scoring rules are content. They are not in this repository; they ship as signed bundles.

## Contributing

Read [`AGENTS.md`](AGENTS.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md). Each commit needs a DCO sign-off (`git commit -s`).

## License

[Apache-2.0](LICENSE)
