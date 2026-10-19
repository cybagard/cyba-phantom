ALTER TABLE event RENAME TO event_old;
CREATE TABLE event (
  id            INTEGER PRIMARY KEY,
  ts            INTEGER NOT NULL,
  session_id    TEXT REFERENCES session(id),
  kind          TEXT NOT NULL CHECK (kind IN ('request','refused','callback','beacon','score_change','bundle_load','bundle_rejected','alert_sent','retention')),
  vhost TEXT, method TEXT, path TEXT, status INTEGER,
  trap_id       TEXT,
  token_id      TEXT,
  surface       TEXT,
  body_prefix   BLOB,
  hash          BLOB,
  leaf_index    INTEGER,
  detail        TEXT,
  record        BLOB,
  CHECK ((kind IN ('request','refused','beacon') AND hash IS NULL AND leaf_index IS NULL AND record IS NULL)
      OR (kind NOT IN ('request','refused','beacon')
          AND hash IS NOT NULL AND typeof(hash) = 'blob' AND length(hash) = 32
          AND leaf_index IS NOT NULL AND typeof(leaf_index) = 'integer' AND leaf_index >= 0))
);
INSERT INTO event (id, ts, session_id, kind, vhost, method, path, status, trap_id, token_id, surface, body_prefix, hash, leaf_index, detail, record)
  SELECT id, ts, session_id, kind, vhost, method, path, status, trap_id, token_id, surface, body_prefix, hash, leaf_index, detail, record FROM event_old;
DROP TABLE event_old;
CREATE INDEX event_session ON event(session_id);
CREATE INDEX event_ts ON event(ts);
CREATE INDEX event_kind_ts ON event(kind, ts);
CREATE UNIQUE INDEX event_leaf ON event(leaf_index) WHERE leaf_index IS NOT NULL;
