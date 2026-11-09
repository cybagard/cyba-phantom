CREATE INDEX session_ip_first ON session(first_seen) WHERE ip IS NOT NULL;
CREATE INDEX token_first_cb ON token(first_cb_at);
