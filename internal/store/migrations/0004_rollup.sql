CREATE TABLE rollup_seen (
  day TEXT NOT NULL, vhost TEXT NOT NULL, band TEXT NOT NULL, family TEXT NOT NULL,
  session_id TEXT NOT NULL,
  PRIMARY KEY (day, vhost, band, family, session_id)
) WITHOUT ROWID;
