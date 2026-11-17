CREATE INDEX event_raw_ts ON event(ts) WHERE body_prefix IS NOT NULL OR detail IS NOT NULL OR record IS NOT NULL;
DELETE FROM meta WHERE key = 'retention_raw_done';
