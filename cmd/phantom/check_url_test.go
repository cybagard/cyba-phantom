package main

import (
	"strings"
	"testing"

	"github.com/cybagard/cyba-phantom/internal/config/configtest"
)

// TestTS11_CheckURLRules checks that --check refuses a bad URL host and a URL
// with a query. It does this for each URL key, with exit 1. The error names
// the key and does not show the host (T-S-11, SEC-13).
func TestTS11_CheckURLRules(t *testing.T) {
	body := validBody(t)
	hook := func(u string) string {
		return body + "alerts:\n  sinks:\n    - {type: webhook, url: \"" + u + "\", hmac_secret_env: ALERT_HMAC}\n"
	}
	for _, bad := range configtest.BadURLs {
		u := bad.URL
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

// TestTS11_CheckLiteralHostList checks six endpoint keys. A literal host
// passes --check with exit 0 if the list of its own item holds it. With the
// list on another item only, the exit is 1. The exit is also 1 for a
// never-list host, with its class in the list. The error names the key and
// shows no part of the host (T-S-11, T-S-26).
func TestTS11_CheckLiteralHostList(t *testing.T) {
	body := validBody(t)
	priv := func(l string) string {
		if l == "" {
			return ""
		}
		return ", private: [" + l + "]"
	}
	hook := func(h, l string) string {
		return `{type: webhook, url: "https://` + h + `/h", hmac_secret_env: ALERT_HMAC` + priv(l) + `}`
	}
	mail := func(h, l string) string {
		return `{type: smtp, host: "smtp://` + h + `:25", from: a@b.example, to: [c@d.example]` + priv(l) + `}`
	}
	sinks := func(items ...string) string {
		return body + "alerts:\n  sinks:\n    - " + strings.Join(items, "\n    - ") + "\n"
	}
	bundle := func(h, l string) string {
		out := body + "bundle:\n  fetch_url: \"https://" + h + "/b\"\n"
		if l != "" {
			out += "  fetch_private: [" + l + "]\n"
		}
		return out
	}
	okPub := `{type: https-put, url: "https://ckpt.example.invalid/put", token_env: CKPT_TOKEN}`
	pubs := func(h, l string) string {
		it := `{type: https-put, url: "https://` + h + `/p", token_env: CKPT_TOKEN` + priv(l) + `}`
		return strings.Replace(body, okPub, it+"\n    - "+okPub, 1)
	}
	// file returns the file and the environment. The list is on the item of
	// the host if own is true, else on another item.
	kinds := []struct {
		key  string
		file func(host, list string, own bool) (string, string)
	}{
		{"acme.ca", func(h, l string, own bool) (string, string) {
			env := "PHANTOM_ACME_CA=https://" + h + "/d"
			if own {
				ca := "  ca: \"https://ca.example.invalid\"\n"
				return strings.Replace(body, ca, ca+"  ca_private: ["+l+"]\n", 1), env
			}
			return bundle("b.example", l), env
		}},
		{"bundle.fetch_url", func(h, l string, own bool) (string, string) {
			if own {
				return bundle(h, l), ""
			}
			return bundle(h, "") + "alerts:\n  sinks:\n    - " + hook("hook.example", l) + "\n", ""
		}},
		{"tlog.publish[0].url", func(h, l string, own bool) (string, string) {
			if own {
				return pubs(h, l), ""
			}
			return strings.Replace(pubs(h, ""), okPub, strings.TrimSuffix(okPub, "}")+priv(l)+"}", 1), ""
		}},
		{"alerts.sinks[0].url", func(h, l string, own bool) (string, string) {
			if own {
				return sinks(hook(h, l), mail("mail.example", "")), ""
			}
			return sinks(hook(h, ""), mail("mail.example", l)), ""
		}},
		{"alerts.sinks[0].addr", func(h, l string, own bool) (string, string) {
			sys := func(l string) string {
				return `{type: syslog, addr: "tls://` + h + `:6514"` + priv(l) + `}`
			}
			if own {
				return sinks(sys(l), hook("hook.example", "")), ""
			}
			return sinks(sys(""), hook("hook.example", l)), ""
		}},
		{"alerts.sinks[0].host", func(h, l string, own bool) (string, string) {
			if own {
				return sinks(mail(h, l), hook("hook.example", "")), ""
			}
			return sinks(mail(h, ""), hook("hook.example", l)), ""
		}},
	}
	for _, k := range kinds {
		for _, r := range []struct {
			name, host, list string
			own, passes      bool
		}{
			{"own list", "10.1.2.3", "10.0.0.0/8", true, true},
			{"list on another item", "10.1.2.3", "10.0.0.0/8", false, false},
			{"never-list host", "100.100.100.200", "100.64.0.0/10", true, false},
		} {
			t.Run(k.key+"/"+r.name, func(t *testing.T) {
				file, extra := k.file(r.host, r.list, r.own)
				env := []string{"CKPT_TOKEN=" + strings.Repeat("t", 32), "ALERT_HMAC=" + strings.Repeat("h", 32)}
				if extra != "" {
					env = append(env, extra)
				}
				var so, se strings.Builder
				code := run([]string{"--check", writeFile(t, file)}, env, &so, &se)
				if r.passes {
					if code != 0 {
						t.Errorf("exit %d, stderr %q", code, se.String())
					}
					return
				}
				// A parse error of the smtp host key shows the value
				// after ": value".
				detail, _, _ := strings.Cut(se.String(), ": value")
				if code != 1 || !strings.Contains(se.String(), "config: "+k.key+" at ") || strings.Contains(detail, r.host) {
					t.Errorf("exit %d, stderr %q", code, se.String())
				}
			})
		}
	}
}

// TestTS11_CheckEgressLiterals checks that --check refuses an IP literal that
// the egress rule refuses. It does this for each URL key and for an smtp and
// an smtps host, with exit 1. One URL key is a tls syslog address. The error
// names the key. A global literal and a loopback udp address pass (T-S-11,
// SEC-26).
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
			{"alerts.sinks[0].host", sink(`{type: smtp, host: "smtps://` + host + `:465", from: a@b.example, to: [c@d.example]}`), ""},
		}
	}
	for _, host := range configtest.EgressLiterals {
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
	for _, host := range configtest.GlobalLiterals {
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
