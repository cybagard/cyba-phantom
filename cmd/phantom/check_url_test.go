package main

import (
	"strings"
	"testing"
)

// TestTS11_CheckURLRules checks that --check refuses a bad URL host and a URL
// with a query. It does this for each URL key, with exit 1. The error names
// the key and does not show the host (T-S-11, SEC-13).
func TestTS11_CheckURLRules(t *testing.T) {
	body := validBody(t)
	hook := func(u string) string {
		return body + "alerts:\n  sinks:\n    - {type: webhook, url: \"" + u + "\", hmac_secret_env: ALERT_HMAC}\n"
	}
	for _, u := range []string{
		"https://a..b/", "https://.example.com/", "https://169.254.169.254;/", "https://-h.example/", "https://h_x.example/",
		"https://h.example/p?t=x", "https://h.example/p?",
	} {
		host, _, _ := strings.Cut(strings.TrimPrefix(u, "https://"), "/")
		for _, c := range []struct{ key, file, env string }{
			{"acme.ca", body, "PHANTOM_ACME_CA=" + u},
			{"bundle.fetch_url", body, "PHANTOM_BUNDLE_FETCH_URL=" + u},
			{"tlog.publish[0].url", strings.Replace(body, "https://ckpt.example.invalid/put", u, 1), ""},
			{"alerts.sinks[0].url", hook(u), ""},
		} {
			env := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32), "ALERT_HMAC=" + strings.Repeat("h", 32)}
			if c.env != "" {
				env = append(env, c.env)
			}
			var so, se strings.Builder
			code := run([]string{"--check", writeFile(t, c.file)}, env, &so, &se)
			if code != 1 || !strings.Contains(se.String(), "config: "+c.key+" at ") {
				t.Errorf("%s %s: exit %d, stderr %q", c.key, u, code, se.String())
			}
			if strings.Contains(se.String(), host) {
				t.Errorf("%s %s: stderr shows the URL host: %q", c.key, u, se.String())
			}
		}
	}
}

// TestTS11_CheckEgressLiterals checks that --check refuses an IP literal that
// the egress rule refuses. It does this for each URL key and an smtp host,
// with exit 1. One URL key is a tls syslog address. The error names the key.
// A global literal and a loopback udp address pass (T-S-11, SEC-26).
func TestTS11_CheckEgressLiterals(t *testing.T) {
	body := validBody(t)
	sink := func(item string) string { return body + "alerts:\n  sinks:\n    - " + item + "\n" }
	check := func(file, env string) (int, string) {
		e := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32), "ALERT_HMAC=" + strings.Repeat("h", 32)}
		if env != "" {
			e = append(e, env)
		}
		var so, se strings.Builder
		return run([]string{"--check", writeFile(t, file)}, e, &so, &se), se.String()
	}
	files := func(host string) [][3]string {
		return [][3]string{
			{"acme.ca", body, "PHANTOM_ACME_CA=https://" + host + "/d"},
			{"bundle.fetch_url", body, "PHANTOM_BUNDLE_FETCH_URL=https://" + host + "/b"},
			{"tlog.publish[0].url", strings.Replace(body, "https://ckpt.example.invalid/put", "https://"+host+"/p", 1), ""},
			{"alerts.sinks[0].url", sink(`{type: webhook, url: "https://` + host + `/h", hmac_secret_env: ALERT_HMAC}`), ""},
			{"alerts.sinks[0].addr", sink(`{type: syslog, addr: "tls://` + host + `:6514"}`), ""},
			{"alerts.sinks[0].host", sink(`{type: smtp, host: "smtp://` + host + `:25", from: a@b.example, to: [c@d.example]}`), ""},
		}
	}
	for _, host := range []string{
		"127.0.0.1", "10.0.0.1", "100.100.100.200", "169.254.169.254", "224.0.0.1", "[fd00:ec2::254]",
		"[64:ff9b::a9fe:a9fe]", "[::169.254.169.254]", "[::ffff:10.0.0.1]", "[fec0::1]", "[2001:db8::1]",
	} {
		for _, c := range files(host) {
			code, se := check(c[1], c[2])
			// Only alerts.sinks[0].host is a string key, not a URL key.
			// The loader shows its value after ": value".
			detail, _, _ := strings.Cut(se, ": value")
			bare := strings.Trim(host, "[]")
			if code != 1 || !strings.Contains(se, "config: "+c[0]+" at ") || !strings.Contains(se, "egress rule") || strings.Contains(detail, bare) {
				t.Errorf("%s %s: exit %d, stderr %q", c[0], host, code, se)
			}
		}
	}
	for _, host := range []string{"8.8.8.8", "[2606:4700::1111]"} {
		for _, c := range files(host) {
			if code, se := check(c[1], c[2]); code != 0 {
				t.Errorf("%s %s: exit %d, stderr %q", c[0], host, code, se)
			}
		}
	}
	if code, se := check(sink(`{type: syslog, addr: "udp://127.0.0.1:514"}`), ""); code != 0 {
		t.Errorf("loopback udp: exit %d, stderr %q", code, se)
	}
}
