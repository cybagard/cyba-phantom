CREATE TABLE mint (
  set_id        BLOB,
  unit          INTEGER,
  first         INTEGER,
  count         INTEGER,
  session_id    TEXT,
  issued_at     INTEGER,
  PRIMARY KEY (set_id, unit, first)
) WITHOUT ROWID;
