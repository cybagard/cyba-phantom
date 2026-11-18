CREATE TABLE clock_jump (
  id INTEGER PRIMARY KEY,
  event_from INTEGER NOT NULL, event_to INTEGER NOT NULL,
  session_from INTEGER NOT NULL, session_to INTEGER NOT NULL,
  j INTEGER NOT NULL,
  at INTEGER NOT NULL
);
DELETE FROM meta WHERE key IN ('retention_check', 'retention_mint_done');
