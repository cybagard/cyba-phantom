# 04 — Interfaces

§1 (decoy listener) and §4 (bundle format) hold closed content (C7, C9). They are not in this file. The section numbers do not change.

## 2. Ops listener (`127.0.0.1:9443`, TLS with self-signed or configured cert, basic auth)
| Route | Purpose |
|-------|---------|
| `GET /` | dashboard (bands last 24 h, alerts, bundle version, queue depth, drops, RSS, disk) |
| `GET /sessions?band=&since=` | table, paginated 100 |
| `GET /session/{id}` | signals, events, proof link |
| `GET /proof/{event_id}` | JSON inclusion proof + latest checkpoint |
| `GET /metrics` | Prometheus text (FR-15) |
| `GET /healthz` | 200 if writer, tlog and listener healthy; 503 otherwise. Each tile-read error stops the tlog: a changed, short or missing tile, and also a mode error or an I/O error. The tlog stays not healthy until the operator opens the log again (SEC-16) |
| `POST /reload` | bundle reload (also SIGHUP) |

## 3. Config (`/etc/phantom/config.yaml`)
```yaml
listen: { http: ":80", https: ":443" }
ops:    { listen: "127.0.0.1:9443", basic_auth_htpasswd: "/etc/phantom/htpasswd" }
acme:   { email: "sec@example.com", ca: "letsencrypt", cache_dir: "/var/lib/phantom/certs", names: [ "decoy.example.com" ] }
bundle: { path: "/var/lib/phantom/bundle/current.cbnd", fetch_url: "", fetch_interval: "6h" }
limits: { max_conns: 2000, body_bytes: 65536, header_bytes: 16384, per_ip_rps: 50, per_ip_burst: 200, queue_depth: 4096 }
store:  { path: "/var/lib/phantom/events.db", max_bytes: 10737418240, retention_days: { ip: 7, raw: 30, events: 90 } }
tlog:   { dir: "/var/lib/phantom/tlog", origin: "phantom/<install_id>", checkpoint_interval: "1h",
          publish: [ { type: "https-put", url: "https://…", token_env: "CKPT_TOKEN" } ] }
alerts:
  min_band: agent-likely
  sinks:
    - { type: webhook, url: "https://…", hmac_secret_env: "ALERT_HMAC" }
    - { type: syslog, addr: "tls://logs.example.com:6514" }
    - { type: smtp, host: "smtps://mail.example.com:465", from: "…", to: ["…"] }
privacy: { store_body_prefix: true, include_ip: false }
```
`phantom --check config.yaml` validates; unknown keys are errors.

ADR-013 defines the rules below (SEC-11, SEC-12, SEC-13).

**Parse.** The file is UTF-8 and ≤ 64 KiB. It contains exactly one YAML document. The loader rejects anchors, aliases, merge keys (`<<`), tags other than the core schema, duplicate keys, and nesting deeper than 8 levels. A boolean is `true` or `false` only. An integer is a decimal literal only. A duration is a Go duration string (for example `6h`). The loader does not expand `${…}` or other variables in values. A missing, empty, or unreadable file is an error. The sensor reads the config one time at start. SIGHUP and `POST /reload` reload the bundle, not the config.

**Environment overrides.** Precedence: default < file < environment. Each scalar leaf key has one variable name: `PHANTOM_` + the key path in upper case, with `.` changed to `_` (for example `PHANTOM_LIMITS_BODY_BYTES`, `PHANTOM_STORE_RETENTION_DAYS_IP`). The loader makes the names from its key table and compares them exactly. List keys (`acme.names`, `tlog.publish`, `alerts.sinks`, `alerts.sinks[].to`) have no override. A `PHANTOM_*` variable that is not in the key table is an error. An override value goes through the same parse and bounds rules as a file value.

**Secrets.** A key that ends in `_env` holds the name of an environment variable, not a secret. The variable name must not start with `PHANTOM_`. At start and in `--check`, the variable must be set. A webhook `hmac_secret_env` value must be ≥ 32 bytes (SEC-06). No secret value, no htpasswd content, and no URL user information goes to `--check` output, an error message, or a log.

**Files.** The config file and the htpasswd file must be regular files after symlink resolution. They must not be writable by group or other. Their owner must be root or the user that runs the sensor. The htpasswd file must not be readable by other.

**Errors.** An error names the key path (for example `limits.body_bytes`) and its source (file line, or the environment variable name). An error for a `*_env` key names the key path and the file line only. It never shows the variable name or the variable value, because an operator can paste a secret in place of a name (SEC-13). An error shows a value only for a non-secret key, escaped (SEC-07) and cut to 64 bytes. The loader does not pass parser error text through unchanged.

**Bounds.** A value outside its range is an error. The loader never clamps a value.

| Key | Default | Rule |
|-----|---------|------|
| `listen.http`, `listen.https` | `:80`, `:443` | `host:port`, port 1–65535; the two addresses differ |
| `ops.listen` | `127.0.0.1:9443` | IP literal, loopback or private (RFC 1918, RFC 4193); not unspecified; not the same as a `listen` address (SEC-04) |
| `ops.basic_auth_htpasswd` | `/etc/phantom/htpasswd` | absolute path; file rules above |
| `acme.email` | — (required) | one address; no CR or LF |
| `acme.ca` | `letsencrypt` | `letsencrypt`, `letsencrypt-staging`, or an `https` URL. The ACME client connects only to the host and port of this directory, also for a retry (SEC-21, ADR-025) |
| `acme.names` | — (required) | 1–16 entries; no duplicate. Each entry is a DNS name in lower case, ≤ 253 bytes, with at least two labels; each label has 1–63 bytes of `a–z 0–9 -` and does not start or end with `-`. No wildcard, no IP literal, no trailing dot. Not `localhost`, and not a name below `localhost`, `local`, `internal` or `home.arpa`. The listener gets certificates only for these names (SEC-21, ADR-025) |
| `acme.cache_dir` | `/var/lib/phantom/certs` | absolute, clean, no NUL; under `/var/lib/phantom` after symlink resolution; not `/var/lib/phantom` itself; in the path text, below `/var/lib/phantom`, each path part has only `A–Z a–z 0–9 . _ -`; not in or above `tlog.dir`, the directory of `bundle.path`, `keys/` or `checkpoints/`. The loader checks the path text only; the listener checks the directories when it opens them (SEC-21, ADR-025) |
| `bundle.path`, `tlog.dir` | as in the example | absolute, clean, no NUL; under `/var/lib/phantom` after symlink resolution |
| `store.path` | `/var/lib/phantom/events.db` | absolute, clean, no NUL; under `/var/lib/phantom` after symlink resolution; in the path text, below `/var/lib/phantom`, each path part has only `A–Z a–z 0–9 . _ -` (thus no `?`, `#` or `..`); not in `tlog.dir`, `acme.cache_dir`, the directory of `bundle.path`, `keys/` or `checkpoints/`; not `checkpoint.state`, `checkpoint.state.tmp` or `writer.stop`. The loader checks the path text only; the store checks the files when it opens them (SEC-20, ADR-022) |
| `bundle.fetch_url` | `""` (off) | empty, or an `https` URL |
| `bundle.fetch_interval` | `6h` | 15m–7d, also when `bundle.fetch_url` is empty |
| `limits.max_conns` | 2000 | 1–2000 (SEC-02) |
| `limits.body_bytes` | 65536 | 1–65536 (SEC-02) |
| `limits.header_bytes` | 16384 | 8192–16384 (SEC-02; the decoy listener answers 431 to a request head over this size, SEC-22) |
| `limits.per_ip_rps` | 50 | 1–1000 |
| `limits.per_ip_burst` | 200 | `per_ip_rps`–5000 |
| `limits.queue_depth` | 4096 | 1–8192 (C2: queue memory stays in the 150 MB load budget, NFR-01) |
| `store.max_bytes` | 10737418240 | ≥ 268435456; the disk guard (NFR-04) is the upper control |
| `store.retention_days.ip` | 7 | 1–7 (C8) |
| `store.retention_days.raw` | 30 | 1–30 (C8) |
| `store.retention_days.events` | 90 | `raw`–90 (FR-11) |
| `tlog.origin` | — (required) | 1–128 bytes of `A–Z a–z 0–9 . _ / -` |
| `tlog.checkpoint_interval` | `1h` | 1m–24h |
| `tlog.publish` | — (required) | 1–4 entries (FR-09); `type: https-put`; `url` is `https`; `token_env` per the secrets rule |
| `alerts.min_band` | `agent-likely` | `agent-likely` or `agent-confirmed` |
| `alerts.sinks` | `[]` | 0–8 entries; `type` is `webhook`, `syslog`, or `smtp` |
| webhook sink | — | `url` is `https`; `hmac_secret_env` required (SEC-06) |
| syslog sink | — | `addr` is `tls://` + `host:port`, or `udp://` or `tcp://` + a loopback `host:port`. A loopback host is an IP literal in `127.0.0.0/8` or `::1` (for example `udp://127.0.0.1:514`, `tcp://[::1]:514`). A host name (also `localhost`) is not loopback: the loader does not resolve names. |
| smtp sink | — | `host` is `smtp://` + `host:port` (STARTTLS required, no plain fallback) or `smtps://` + `host:port` (implicit TLS); `from` and 1–16 `to` addresses; no CR or LF in a value |
| `privacy.store_body_prefix` | `true` | boolean; the prefix size is 4 KB and is not a key (C8) |
| `privacy.include_ip` | `false` | boolean |

Every URL: no user information, no fragment, host not link-local or unspecified. The set of `acme.ca`, `bundle.fetch_url`, `tlog.publish[].url`, and sink endpoints is the C4 outbound allow-list. Each entry of the set has the scheme of its value; an smtp sink has `smtp` or `smtps`. The loader gives this set to the egress test (T-S-08). A loopback sink endpoint is in the set, but it is not egress: traffic to it does not leave the host. Thus plain `udp://` and `tcp://` syslog to loopback agrees with the TLS rule of SEC-12; a local relay sends the messages on with TLS. The loader checks only the shape of an smtp value; the alert sinks enforce TLS at run time. No config value comes from request data (SEC-03).

## 5. Checkpoint (signed note)
```
phantom/<install_id>
<tree_size>
<base64 root hash>

— phantom/<install_id> <base64 sig>
```
Same format as Go sumdb notes so `note.Open` and existing witnesses work.

Rules (SEC-16, SEC-17, ADR-020):

- **Body.** Exactly three lines, each with a newline: the origin (`tlog.origin`), the tree size in decimal with no leading zero, and the root hash in standard base64 with padding. No extension lines and no timestamp. The time when the sensor signs is the `created_at` of the `checkpoint` row in the database. The writer stores that row before the note goes to the spool; `created_at` is the time when the writer stores the row. When the writer has stopped (it reports that it is not healthy) or there is no writer, the note goes to the spool with no row. There is no row for the size-0 note (ADR-022). This is the C2SP tlog-checkpoint format. `tlog.FormatTree` writes another first line, so the sensor does not use it.
- **Signature.** Ed25519 (note signature type 0x01). The key name is the origin. The origin of a log does not change after its first checkpoint.
- **Leaf.** The 32-byte event hash is the record data of a leaf. The leaf hash is SHA-256(0x00 ‖ event hash) (RFC 6962 §2.1). The root hash is the RFC 6962 root over these leaf hashes. Tiles have height 8.
- **Sign guard.** The sensor signs a new checkpoint only if the tree size changed and the new tree is consistent with the last checkpoint that it signed. Else it does not sign and reports the tlog as not healthy. The signer state is the last signed note, in the fixed file `checkpoint.state` below the state directory. When the sensor makes the key on the first start, it also writes a signed checkpoint of the empty tree (size 0) as the signer state. A missing signer state while the key exists is a fault: the sensor does not sign, reports the tlog as not healthy, and makes no new state. The operator decides.
- **State files.** The sensor opens `/var/lib/phantom` one time as an `os.Root`. Tiles, the tree head, the signer state, `keys/` and `checkpoints/` open through it and do not follow a symlink out of it. File names come from integers or fixed names.
- **Signing key.** `keys/checkpoint.key`: the `note` signer key text, a regular file, owned by the sensor user, mode 0600, ≤ 1 KiB. `keys/checkpoint.vkey`: the public key text. The sensor makes the key only on the first start of an empty log. A missing key on a log that has a signed checkpoint or leaves stops the signer. The key never goes to a log, an error, or `--check` output.
- **Publish.** Each signed note is a file `checkpoints/<tree size>.note`. The spool holds at most 1025 notes; when it is full, the oldest note is deleted and counted as skipped. For each `tlog.publish` target, the publisher sends the notes in increasing tree size: an HTTPS `PUT` of the note to `url`, with `Authorization: Bearer <token>` from `token_env`. A 2xx response is a success; any other result, a redirect, or a timeout is a failure. The publisher follows no redirect, uses no proxy from the environment, verifies TLS, and refuses a resolved address that is unspecified, link-local or multicast. Each publish has a timeout of 30 s and reads ≤ 4 KiB of the response. After a failure, the next try waits with backoff from 30 s up to the smaller of `tlog.checkpoint_interval` and 1 h, with jitter. The token, the URL and the response text never go to a log.

## 6. Alert payload (webhook)
```json
{ "v":1, "sensor":"<install_id>", "session":"…", "band":"agent-confirmed", "score":92, "family":"…",
  "signals":{"ja4":"…","h2":"…","hdr":"…","beacon":false,"cadence_ms_p50":140},
  "trap":{"id":"t-…","surface":"path","instruction_class":"…"},
  "evidence":{"event_id":123,"hash":"…","leaf_index":98765,"tree_size":98800,"proof":["…"],"checkpoint_pending":true},
  "ip_hmac":"…", "ip": "<only if within 7d and privacy.include_ip=true>", "ts":"…" }
```
Headers: `X-Phantom-Signature: sha256=<hmac>`, `X-Phantom-Sensor`.
Syslog: RFC 5424, structured-data `[phantom@0 session="…" band="…" trap="…" leaf="…"]`.

## 7. Verifier (`phantom-verify`)

```
phantom-verify --key <vkey file> --checkpoint <note file>
              [--event <event file> --proof <proof file>]
              [--prior <note file>] [--consistency <proof file>]…
              [--state <dir>]
```

Rules (SEC-18, ADR-021, ADR-024):

- **Key.** `--key` is required. The file holds the `note` verifier key text (`keys/checkpoint.vkey` of the sensor). The key name is the origin. The verifier never takes a key or an origin from another input.
- **Checkpoint.** Each note is parsed with the strict parser of 04 §5: ≤ 1 KiB, three body lines, exactly one signature line, origin equal to the key name. A note with more than one signature line is refused.
- **Event.** ≤ `MaxRecordBytes` (24 KiB). The hash is SHA-256 of the received bytes. The bytes must be equal to their RFC 8785 form. Without `--event`, the verifier checks only the checkpoint and its consistency.
- **Inclusion proof file.** One JSON object, ≤ 16 KiB, no duplicate or unknown members:
  ```json
  { "index": 98765, "tree_size": 98800, "hashes": ["<base64>", "…"],
    "root": "<base64>", "consistency": ["<base64>", "…"] }
  ```
  `hashes` is the inclusion proof at `tree_size` (≤ 48 hashes). If `tree_size` is equal to the checkpoint size, `root` and `consistency` are absent. If `tree_size` is smaller, `root` is the root at `tree_size` and `consistency` is the proof from `tree_size` to the checkpoint size (≤ 96 hashes). A larger `tree_size` is refused.
- **Consistency proof file.** `{ "old_size": 98800, "new_size": 99000, "hashes": ["<base64>", "…"] }`, with the same parse rules, ≤ 96 hashes. The verifier uses the file whose sizes match the check that it must do.
- **Hashes and sizes.** Each hash is canonical standard base64 of 32 bytes. Each size is an integer from 0 to 2^48.
- **State.** The state of a key is the last accepted signed note, in the file `<key hash>.note` in the state directory. The key hash is the 8 hexadecimal digits of the verifier key. The default directory is `phantom-verify` in the user state directory (`$XDG_STATE_HOME`, else `~/.local/state`). The directory opens as an `os.Root`; the file has mode 0600 and is written with a temporary file, `fsync`, and `rename`. A run holds an exclusive lock (`flock`) on the state directory from the load of the state to the rename, so two runs at the same time cannot move the state back to an older checkpoint. The kernel releases the lock when the process ends. The verifier reads the state again before the rename and refuses the write if the state changed. A state that does not parse with the key is a fault (exit 2); the verifier does not replace it.
- **Consistency.** For a prior checkpoint (`--prior`) and for the state, with size S, and the checkpoint with size N: N > S needs a proof from S to N; N = S needs the same root; N < S needs a proof from N to S. Size 0 needs no proof, and its root must be the root of the empty tree. Sizes do not have to be adjacent. Only N > S against the state changes the state. The state changes when the checkpoint is accepted, also when the event check fails. With no state, the checkpoint becomes the state, and the output says that no earlier checkpoint was known.
- **Network.** The verifier opens no network connection.
- **Output.** On success, the verifier prints the origin, the size and the root of the checkpoint, the event hash, the leaf index, and each proof hash in base64. Text from the input is printed with each control character, bidirectional format character and invalid byte escaped. Error text is fixed and holds no input bytes.
- **Exit codes.** 0: verified. 1: not verified (hash, signature, proof, or consistency). A consistency failure between two signed checkpoints (`--prior` or the state) is reported as "not consistent: a fork of the log, or a bad consistency proof". A consistency failure in an inclusion proof file (a proof at a smaller size) is a bad proof, not a fork: the root at the proof size comes from the proof file, which has no signature. 2: usage error, input error, or state fault.
