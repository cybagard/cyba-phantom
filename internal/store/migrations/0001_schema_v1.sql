CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE session (
  id            TEXT PRIMARY KEY,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  ip            TEXT,
  ip_hmac       TEXT NOT NULL,
  ja4           TEXT, h2_fp TEXT, ua TEXT, hdr_order_hash TEXT,
  beacon_seen   INTEGER NOT NULL DEFAULT 0,
  req_count     INTEGER NOT NULL DEFAULT 0,
  band          TEXT NOT NULL CHECK (band IN ('human','crawler','agent-likely','agent-confirmed')),
  score         INTEGER NOT NULL DEFAULT 0,
  family        TEXT,
  alerted_at    INTEGER
);
CREATE INDEX session_band_last ON session(band, last_seen);
CREATE INDEX session_iphmac ON session(ip_hmac);
CREATE TABLE event (
  id            INTEGER PRIMARY KEY,
  ts            INTEGER NOT NULL,
  session_id    TEXT REFERENCES session(id),
  kind          TEXT NOT NULL CHECK (kind IN ('request','callback','beacon','score_change','bundle_load','bundle_rejected','alert_sent','retention')),
  vhost TEXT, method TEXT, path TEXT, status INTEGER,
  trap_id       TEXT,
  token_id      TEXT,
  surface       TEXT,
  body_prefix   BLOB,
  hash          BLOB,
  leaf_index    INTEGER,
  detail        TEXT,
  record        BLOB,
  CHECK ((kind IN ('request','beacon') AND hash IS NULL AND leaf_index IS NULL AND record IS NULL)
      OR (kind NOT IN ('request','beacon')
          AND hash IS NOT NULL AND typeof(hash) = 'blob' AND length(hash) = 32
          AND leaf_index IS NOT NULL AND typeof(leaf_index) = 'integer' AND leaf_index >= 0))
);
CREATE INDEX event_session ON event(session_id);
CREATE INDEX event_ts ON event(ts);
CREATE INDEX event_kind_ts ON event(kind, ts);
CREATE UNIQUE INDEX event_leaf ON event(leaf_index) WHERE leaf_index IS NOT NULL;
CREATE TABLE token (
  token_id      TEXT PRIMARY KEY,
  session_id    TEXT NOT NULL,
  trap_id       TEXT NOT NULL,
  issued_at     INTEGER NOT NULL,
  first_cb_at   INTEGER,
  cb_count      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE aggregate_day (
  day TEXT NOT NULL, vhost TEXT NOT NULL, band TEXT NOT NULL, family TEXT,
  sessions INTEGER NOT NULL, requests INTEGER NOT NULL, callbacks INTEGER NOT NULL,
  PRIMARY KEY (day, vhost, band, family)
);
CREATE TABLE ip_counter (
  day TEXT NOT NULL, ip_hmac TEXT NOT NULL, requests INTEGER NOT NULL, dropped INTEGER NOT NULL,
  PRIMARY KEY (day, ip_hmac)
);
CREATE TABLE checkpoint (
  tree_size INTEGER PRIMARY KEY CHECK (tree_size >= 1),
  root_hash BLOB NOT NULL CHECK (typeof(root_hash) = 'blob' AND length(root_hash) = 32),
  signed_note TEXT NOT NULL, created_at INTEGER NOT NULL
);
