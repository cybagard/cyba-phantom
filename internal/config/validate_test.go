package config

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/config/configtest"
	"github.com/cybagard/cyba-phantom/internal/egress"
)

type row struct {
	name, in, want string // want is "" for an accepted value, or a part of the detail.
}

func runRows(t *testing.T, rows []row, check func(string) string) {
	t.Helper()
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := check(r.in)
			if (r.want == "") != (got == "") || !strings.Contains(got, r.want) {
				t.Errorf("check(%q) = %q, want %q", r.in, got, r.want)
			}
		})
	}
}

// TestTU10_Listen checks host:port and port bounds for listen.http and listen.https.
func TestTU10_Listen(t *testing.T) {
	runRows(t, []row{
		{"default http", ":80", ""},
		{"ip", "192.0.2.1:8080", ""},
		{"ipv6", "[2001:db8::1]:443", ""},
		{"host name", "example.com:443", ""},
		{"port 1", ":1", ""},
		{"port 65535", ":65535", ""},
		{"port 0", ":0", "range"},
		{"port 65536", ":65536", "range"},
		{"port huge", ":99999999999999999999", "range"},
		{"port name", ":http", "decimal"},
		{"port sign", ":+80", "decimal"},
		{"port leading zero", ":080", "decimal"},
		{"no port", "example.com", "host:port"},
		{"empty", "", "host:port"},
		{"bare ipv6", "::1:80", "host:port"},
		{"bad host", "ex ample:80", "host name"},
		{"empty label", "a..b:80", "host name"},
		{"leading dot", ".a:80", "host name"},
		{"trailing dot", "a.:80", "host name"},
		{"numeric name", "999.1.1.1:80", "host name"},
		{"numeric last label", "a.1:80", "host name"},
		{"single digit", "0:80", "host name"},
		{"digits in a label", "a1.b2:80", ""},
		{"hex last label", "127.0.0.0x1:80", "host name"},
		{"hex name", "0xcafe.example.com:80", ""},
		{"url", "http://h:80", "host"},
		{"underscore", "h_x.example:80", "host name"},
		{"bracketed IPv4", "[127.0.0.1]:80", "brackets"},
		{"bracketed name", "[example.com]:80", "brackets"},
		{"empty brackets", "[]:80", "brackets"},
		{"bracketed IPv6 with zone", "[fe80::1%eth0]:80", ""},
	}, func(s string) string { return checkListen(nil, s) })
}

// TestTU10_ListenEmptyBrackets checks that "[]:80" fails on the bracket rule
// for listen.http and for listen.https, and not as a wildcard host.
func TestTU10_ListenEmptyBrackets(t *testing.T) {
	useTestKeys(t)
	for _, k := range []string{"http", "https"} {
		t.Run(k, func(t *testing.T) {
			err := wantLoad(t, "listen:\n  "+k+": \"[]:80\"\n", "config: listen."+k+" at ")
			if err != nil && !strings.Contains(err.Error(), "in brackets must be an IPv6 address") {
				t.Errorf("got %v, want the bracket rule", err)
			}
		})
	}
}

// TestTS11_HostRules checks that the URL host rule and the host:port host rule
// give one result (T-S-11).
func TestTS11_HostRules(t *testing.T) {
	for _, h := range []string{
		"ok.example", "a-b.example", "0x0.st", "a.", "a.example.", "h_x.example", "a..b", ".example.com", "-h.example",
		"a-.example", "a.1", "192.0.2.1.", "1.2.3.4.5", "2852039166", "a;b.example", "h.example:",
	} {
		_, urlDetail := parseURL("https://"+h+"/", "https")
		_, hostDetail := parseHostPort(h + ":443")
		if (urlDetail == "") != (hostDetail == "") {
			t.Errorf("%q: URL rule %q, host:port rule %q", h, urlDetail, hostDetail)
		}
	}
}

// TestTS11_BelowFloor checks that the error names the key that the operator
// changed (T-S-11).
func TestTS11_BelowFloor(t *testing.T) {
	const hi, lo = "store.retention_days.events", "store.retention_days.raw"
	set := Value{Int: 20, Source: "file", Line: 3}
	rows := []struct {
		name    string
		hi      Value
		wantKey string
	}{
		{"high at default", Value{Int: 10, Source: "default"}, lo},
		{"high set", Value{Int: 10, Source: "file", Line: 5}, hi},
		{"no error", Value{Int: 20, Source: "default"}, ""},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			k, v, d := belowFloor(map[string]Value{hi: r.hi, lo: set}, hi, lo)
			if k != r.wantKey || (k == "") != (d == "") || (k == lo && v.Line != 3) {
				t.Errorf("got %q, %+v, %q", k, v, d)
			}
		})
	}
}

// TestTU10_ListenDiffer checks that listen.http and listen.https differ.
func TestTU10_ListenDiffer(t *testing.T) {
	useTestKeys(t)
	rows := []struct{ name, file, want string }{
		{"default", "", ""},
		{"same", "listen:\n  http: \":8443\"\n  https: \":8443\"\n", "listen.https"},
		{"same host", "listen:\n  http: \"192.0.2.1:80\"\n  https: \"192.0.2.1:80\"\n", "listen.https"},
		{"wildcard host", "listen:\n  http: \":80\"\n  https: \"192.0.2.1:80\"\n", "listen.https"},
		{"other host", "listen:\n  http: \"192.0.2.1:80\"\n  https: \"192.0.2.2:80\"\n", ""},
		{"name and IP, same port", "listen:\n  http: \"localhost:8080\"\n  https: \"127.0.0.1:8080\"\n", "listen.https"},
		{"IP and name, same port", "listen:\n  http: \"127.0.0.1:8080\"\n  https: \"localhost:8080\"\n", "listen.https"},
		{"two names, same port", "listen:\n  http: \"a.example:8080\"\n  https: \"b.example:8080\"\n", "listen.https"},
		{"name and IP, other port", "listen:\n  http: \"localhost:8080\"\n  https: \"127.0.0.1:8081\"\n", ""},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) { wantLoad(t, r.file, r.want) })
	}
}

// wantLoad loads base and file. It reports an error unless the load error
// holds want ("" means no error). It returns the load error.
func wantLoad(t *testing.T, file, want string) error {
	t.Helper()
	_, err := loadTest(writeConfig(t, base+file), nil)
	if (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
		t.Errorf("got %v, want %q", err, want)
	}
	return err
}

// TestTU10_OpsListen checks the ops.listen address rules (SEC-04).
func TestTU10_OpsListen(t *testing.T) {
	runRows(t, []row{
		{"default", "127.0.0.1:9443", ""},
		{"loopback v6", "[::1]:9443", ""},
		{"rfc1918 10", "10.1.2.3:9443", ""},
		{"rfc1918 172", "172.16.0.1:9443", ""},
		{"rfc1918 192", "192.168.1.1:9443", ""},
		{"rfc4193", "[fd00::1]:9443", ""},
		{"rfc4193 fc", "[fc00::1]:9443", ""},
		{"v4 mapped private", "[::ffff:10.0.0.1]:9443", ""},
		{"public", "192.0.2.1:9443", "loopback or private"},
		{"just outside 172.16/12", "172.32.0.1:9443", "loopback or private"},
		{"public v6", "[2001:db8::1]:9443", "loopback or private"},
		{"link-local v6", "[fe80::1]:9443", "loopback or private"},
		{"inside fe80::/10", "[fe81::]:9443", "loopback or private"},
		{"link-local v4", "169.254.1.1:9443", "loopback or private"},
		{"v4 mapped public", "[::ffff:192.0.2.1]:9443", "loopback or private"},
		{"unspecified v4", "0.0.0.0:9443", "unspecified"},
		{"unspecified v6", "[::]:9443", "unspecified"},
		{"empty host", ":9443", "IP literal"},
		{"host name", "localhost:9443", "IP literal"},
		{"zone", "[fd00::1%eth0]:9443", "zone"},
		{"port 0", "127.0.0.1:0", "range"},
		{"no port", "[fd00::1]", "host:port"},
	}, func(s string) string { return checkOpsListen(nil, s) })
}

// TestTU10_OpsListenOverlap checks that ops.listen is not equal to or inside a listen address.
// A row with a text also checks the detail text.
func TestTU10_OpsListenOverlap(t *testing.T) {
	useTestKeys(t)
	rows := []struct{ name, file, want, text string }{
		{"default", "", "", ""},
		{"equal to http", "listen:\n  http: \"127.0.0.1:9443\"\n", "ops.listen", ""},
		{"equal to https", "listen:\n  https: \"127.0.0.1:9443\"\n", "ops.listen", ""},
		{"inside empty host", "listen:\n  https: \":9443\"\n", "ops.listen", ""},
		{"inside unspecified host", "listen:\n  https: \"0.0.0.0:9443\"\n", "ops.listen", ""},
		{"empty host, other port", "listen:\n  https: \":8443\"\n", "", ""},
		{"same port, other IP", "listen:\n  https: \"192.0.2.1:9443\"\n", "", ""},
		{"ops on port 443", "ops:\n  listen: \"127.0.0.1:443\"\n", "ops.listen", "the address overlaps the listen.https address"},
		{"ops on port 80", "ops:\n  listen: \"[::1]:80\"\n", "ops.listen", "the address overlaps the listen.http address"},
		{"mapped unspecified", "listen:\n  https: \"[::ffff:0.0.0.0]:9443\"\n", "ops.listen", ""},
		{"mapped unspecified, other port", "listen:\n  https: \"[::ffff:0.0.0.0]:8443\"\n", "", ""},
		{"host name, same port", "listen:\n  http: \"localhost:9443\"\n", "ops.listen", "that host is a name"},
		{"host name https, same port", "listen:\n  https: \"example.com:9443\"\n", "ops.listen", ""},
		{"numeric host, same port", "listen:\n  http: \"0:9443\"\n", "listen.http", ""},
		{"zoned unspecified http", "listen:\n  http: \"[::%lo0]:9443\"\n", "ops.listen", ""},
		{"zoned unspecified https", "listen:\n  https: \"[::%lo0]:9443\"\n", "ops.listen", ""},
		{"zoned unspecified, other port", "listen:\n  https: \"[::%lo0]:8443\"\n", "", ""},
		{"host name, other port", "listen:\n  http: \"localhost:8443\"\n", "", ""},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			err := wantLoad(t, r.file, r.want)
			if r.text != "" && (err == nil || !strings.Contains(err.Error(), r.text)) {
				t.Errorf("got %v, want the text %q", err, r.text)
			}
		})
	}
}

// TestTU10_CrossCheckFailedKey checks that a key whose value failed is not in the cross check.
func TestTU10_CrossCheckFailedKey(t *testing.T) {
	useTestKeys(t)
	for _, file := range []string{
		"listen:\n  http: \":443\"\n  https: bad\n",
		"listen:\n  http: \":443\"\n  https: \":99999\"\n",
	} {
		_, err := loadTest(writeConfig(t, base+file), nil)
		if err == nil || !strings.Contains(err.Error(), "listen.https") {
			t.Fatalf("got %v", err)
		}
		if strings.Contains(err.Error(), "default") || strings.Contains(err.Error(), "must differ") {
			t.Errorf("a stale default is in the cross check: %v", err)
		}
	}
	_, err := loadTest(writeConfig(t, base), []string{"PHANTOM_LISTEN_HTTP=:9443", "PHANTOM_OPS_LISTEN=0.0.0.0:9443"})
	if err == nil || strings.Count(err.Error(), "\n") != 0 || !strings.Contains(err.Error(), "ops.listen at PHANTOM_OPS_LISTEN") {
		t.Errorf("got %v", err)
	}
}

// TestTU10_CrossCheckText checks that each cross-check detail is short and has no "be or be".
func TestTU10_CrossCheckText(t *testing.T) {
	useTestKeys(t)
	for _, file := range []string{
		"listen:\n  http: \"127.0.0.1:9443\"\n",
		"listen:\n  https: \":9443\"\n",
		"listen:\n  http: \"localhost:9443\"\n",
		"listen:\n  https: \":80\"\n",
	} {
		_, err := loadTest(writeConfig(t, base+file), nil)
		if err == nil {
			t.Fatalf("no error for %q", file)
		}
		for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
			d := e.(*Error).Detail
			if n := len(strings.Fields(d)); n > 20 || strings.Contains(d, "be inside") || strings.Contains(d, "be or") {
				t.Errorf("the detail %q is not a short, simple sentence", d)
			}
		}
	}
}

// TestTU10_Email checks that acme.email is exactly one address.
func TestTU10_Email(t *testing.T) {
	runRows(t, []row{
		{"plain", "sec@example.com", ""},
		{"plus", "ops+canary@corp.example", ""},
		{"empty", "", "one address"},
		{"two with a space", "a@example.com, b@example.com", emailRule},
		{"two", "a@example.com,b@example.com", "one address"},
		{"display name", "Sec <sec@example.com>", emailRule},
		{"display name without a space", "Sec<sec@example.com>", "one address"},
		{"angle only", "<sec@example.com>", "one address"},
		{"no domain", "sec", "one address"},
		{"space padding", " sec@example.com", emailRule},
		{"LF", "sec@example.com\n", emailRule},
		{"CR", "sec@example.com\r", emailRule},
		{"CRLF header", "a@example.com\r\nBcc: b@example.com", emailRule},
		{"LF in middle", "a@example.com\nb@example.com", emailRule},
		{"NEL", "a@example.com" + string(rune(0x85)), emailRule},
		{"C1 control", "a@example.com" + string(rune(0x9f)), emailRule},
		{"SOH", "a@example.com\x01", emailRule},
		{"DEL", "a@example.com\x7f", emailRule},
		{"no-break space", "a@example.com" + string(rune(0xa0)), emailRule},
		{"right-to-left override", "a@example.com" + string(rune(0x202e)), emailRule},
		{"line separator", "a@example.com" + string(rune(0x2028)), emailRule},
		{"paragraph separator", "a@example.com" + string(rune(0x2029)), emailRule},
		{"ideographic space", "a@example.com" + string(rune(0x3000)), emailRule},
		{"variation selector", "a@example.com" + string(rune(0xfe0f)), emailRule},
		{"non-ASCII letter", "a@ex\xc3\xa4mple.com", emailRule},
		{"invalid UTF-8", "a@example.com\xff", emailRule},
		{"space inside", "a b@example.com", emailRule},
		{"lowest allowed character", "!@example.com", ""},
		{"highest allowed character", "~@example.com", ""},
	}, func(s string) string { return checkEmail(nil, s) })
}

// TestTS11_EmailMarks checks that acme.email, smtp from, and smtp to refuse
// each of the characters in configtest.EmailMarks. The error names the key and
// gives the rule. It does not hold the character (T-S-11).
func TestTS11_EmailMarks(t *testing.T) {
	smtp := func(from, to string) string {
		return snk(`{type: smtp, host: "smtp://mail.example:587", from: "` + from + `", to: ["` + to + `"]}`)
	}
	smtp2 := func(to string) string {
		return snk(`{type: smtp, host: "smtp://mail.example:587", from: "a@b.example", to: ["c@d.example", "` + to + `"]}`)
	}
	for _, mr := range configtest.EmailMarks {
		m := string(mr)
		// A double-quoted YAML scalar reads this escape.
		esc := strconv.QuoteToASCII(m)
		esc = esc[1 : len(esc)-1]
		for _, r := range []struct {
			key, file string
			env       []string
		}{
			{"acme.email", strings.Replace(base, "sec@example.com", `"a@b.example`+esc+`"`, 1), nil},
			{"acme.email", base, []string{"PHANTOM_ACME_EMAIL=a@b.example" + m}},
			{"alerts.sinks[0].from", smtp("a@b.example"+esc, "c@d.example"), nil},
			{"alerts.sinks[0].to[0]", smtp("a@b.example", "c@d.example"+esc), nil},
			{"alerts.sinks[0].to[1]", smtp2("e@f.example" + esc), nil},
		} {
			name := r.key + " " + esc
			if r.env != nil {
				name += " from the environment"
			}
			t.Run(name, func(t *testing.T) {
				_, err := loadProd(t, r.file, append(r.env, listEnv...)...)
				if err == nil || !strings.Contains(err.Error(), "config: "+r.key+" at ") {
					t.Fatalf("got %v, want an error that names %s", err, r.key)
				}
				if !strings.Contains(err.Error(), emailRule) {
					t.Errorf("the error does not give the rule: %q", err)
				}
				// Each error text has spaces, so the check skips the space.
				if m != " " && strings.Contains(err.Error(), m) {
					t.Errorf("the error holds the character: %q", err)
				}
			})
		}
	}
}

// TestTU10_URL checks the URL helper with the allowed schemes of the caller.
func TestTU10_URL(t *testing.T) {
	rows := []struct {
		name, in string
		schemes  []string
		want     string
	}{
		{"https", "https://acme.example/dir", []string{"https"}, ""},
		{"port", "https://acme.example:14000/dir", []string{"https"}, ""},
		{"ipv4", "https://8.8.8.8/dir", []string{"https"}, ""},
		{"ipv6", "https://[2606:4700::1111]/dir", []string{"https"}, ""},
		{"caller schemes", "tcp://h:514", []string{"udp", "tcp"}, ""},
		{"tcp not allowed", "tcp://h:443", []string{"https"}, "scheme"},
		{"http not allowed", "http://h/", []string{"https"}, "scheme"},
		{"no scheme", "acme.example/dir", []string{"https"}, "scheme"},
		{"parse error", "https://h/%zz", []string{"https"}, "not a valid URL"},
		{"parse error host", "https://[::1", []string{"https"}, "not a valid URL"},
		{"control byte", "https://h/\x01", []string{"https"}, "not a valid URL"},
		{"opaque", "https:acme.example", []string{"https"}, "opaque"},
		{"mailto opaque", "mailto:a@example.com", []string{"mailto"}, "opaque"},
		{"no host", "https:///dir", []string{"https"}, "host"},
		{"empty host with port", "https://:443/", []string{"https"}, "host"},
		{"user", "https://user@h/", []string{"https"}, "user information"},
		{"user and password", "https://user:pw@h/", []string{"https"}, "user information"},
		{"empty user", "https://@h/", []string{"https"}, "user information"},
		{"fragment", "https://h/#x", []string{"https"}, "fragment"},
		{"empty fragment", "https://h/#", []string{"https"}, "fragment"},
		// parseURL accepts a literal that the egress rule refuses.
		// literalCheck refuses it (TestTS11_EgressLiterals).
		{"link-local v4", "https://169.254.169.254/", []string{"https"}, ""},
		{"link-local v6", "https://[fe80::1]/", []string{"https"}, ""},
		{"inside fe80::/10", "https://[fe81::]/", []string{"https"}, ""},
		{"top of fe80::/10", "https://[febf::1]/", []string{"https"}, ""},
		{"outside fe80::/10", "https://[fec0::1]/", []string{"https"}, ""},
		{"v4 mapped link-local", "https://[::ffff:169.254.169.254]/", []string{"https"}, ""},
		{"zone", "https://[fe80::1%25eth0]/", []string{"https"}, "zone"},
		{"zone on global", "https://[2001:db8::1%25eth0]/", []string{"https"}, "zone"},
		{"unspecified v4", "https://0.0.0.0/", []string{"https"}, ""},
		{"unspecified v6", "https://[::]/", []string{"https"}, ""},
		{"port 0", "https://h:0/", []string{"https"}, "port"},
		{"port 65536", "https://h:65536/", []string{"https"}, "port"},
		{"port leading zero", "https://example.com:0443/", []string{"https"}, "decimal"},
		{"port sign", "https://example.com:+443/", []string{"https"}, "not a valid URL"},
		{"empty port", "https://h:/", []string{"https"}, "port is empty"},
		{"empty port ipv6", "https://[2001:db8::1]:/", []string{"https"}, "port is empty"},
		{"number host", "https://2852039166/", []string{"https"}, "number"},
		{"hex host", "https://0xa9fea9fe/", []string{"https"}, "number"},
		{"octal dotted host", "https://0251.0376.0251.0376/", []string{"https"}, "number"},
		{"short dotted host", "https://169.254.43518/", []string{"https"}, "number"},
		{"zero host", "https://0/", []string{"https"}, "number"},
		{"hex first label", "https://0x7f.1/", []string{"https"}, "number"},
		{"numeric last label", "https://a.1/", []string{"https"}, "number"},
		{"numeric host with dot at end", "https://2852039166./", []string{"https"}, "not an IP address or a host name"},
		{"hex last label", "https://169.254.169.0xfe/", []string{"https"}, "number"},
		{"hex last label loopback", "https://127.0.0.0x1/", []string{"https"}, "number"},
		{"hex last label upper case", "https://10.0.0.0XA/", []string{"https"}, "number"},
		{"hex last label, empty hex part", "https://10.0.0.0x/", []string{"https"}, "number"},
		{"hex name 0x0.st", "https://0x0.st/", []string{"https"}, ""},
		{"hex name 0x.org", "https://0x.org/", []string{"https"}, ""},
		{"hex name 0xcafe", "https://0xcafe.example.com/", []string{"https"}, ""},
		{"digit name", "https://1password.com/", []string{"https"}, ""},
		{"full-width digits and dots", "https://１６９．２５４．１６９．２５４/", []string{"https"}, "ASCII"},
		{"ideographic full stop", "https://169。254。169。254/", []string{"https"}, "ASCII"},
		{"full-width unspecified", "https://０．０．０．０/", []string{"https"}, "ASCII"},
		{"percent-encoded full-width", "https://%EF%BC%91%EF%BC%96%EF%BC%99.254.169.254/", []string{"https"}, "ASCII"},
		{"non-ASCII name", "https://例え.jp/", []string{"https"}, "ASCII"},
		{"name with digits", "https://a1.example/", []string{"https"}, ""},
		{"upper case name", "https://CA.Example:443/", []string{"https"}, ""},
		{"name with dot at end", "https://h.example./", []string{"https"}, "host name"},
		{"address with dot at end", "https://192.0.2.1./", []string{"https"}, "not an IP address or a host name"},
		{"five labels, numeric last", "https://1.2.3.4.5/", []string{"https"}, "last label of the URL host is a number"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, got := parseURL(r.in, r.schemes...)
			if (r.want == "") != (got == "") || !strings.Contains(got, r.want) {
				t.Errorf("parseURL(%q) = %q, want %q", r.in, got, r.want)
			}
		})
	}
	runRows(t, badURLRows(), func(s string) string { _, d := parseURL(s, "https"); return d })
}

// badURLRows returns the entries of configtest.BadURLs as rows for runRows.
// TestTU10_URL uses these rows.
func badURLRows() []row {
	var rows []row
	for _, b := range configtest.BadURLs {
		rows = append(rows, row{b.Name, b.URL, b.Detail})
	}
	return rows
}

// TestTU10_CA checks the acme.ca values and the allow-list.
func TestTU10_CA(t *testing.T) {
	runRows(t, []row{
		{"letsencrypt", "letsencrypt", ""},
		{"staging", "letsencrypt-staging", ""},
		{"https", "https://ca.example/dir", ""},
		{"https port", "https://8.8.8.8:14000/dir", ""},
		// literalCheck refuses the loopback and link-local rows.
		{"loopback", "https://127.0.0.1:14000/dir", ""},
		{"tcp", "tcp://ca.example:443", "scheme"},
		{"http", "http://ca.example/dir", "scheme"},
		{"other name", "zerossl", "scheme"},
		{"case", "Letsencrypt", "scheme"},
		{"empty", "", "scheme"},
		{"link-local", "https://[fe81::]/dir", ""},
		{"user", "https://u:p@ca.example/dir", "user information"},
		{"port leading zero", "https://ca.example:0443/dir", "decimal"},
		{"number host", "https://2852039166/dir", "number"},
		{"full-width host", "https://１６９．２５４．１６９．２５４/dir", "ASCII"},
	}, func(s string) string { return checkCA(nil, s) })
}

// ckptEndpoint is the endpoint of the publisher in base.
var ckptEndpoint = Endpoint{"https", "ckpt.example", "443"}

// TestTU10_AllowList checks that AllowList returns the acme.ca endpoint, then the publisher endpoint of base.
func TestTU10_AllowList(t *testing.T) {
	useTestKeys(t)
	rows := []struct {
		name, file string
		want       []Endpoint
	}{
		{"default", "", []Endpoint{{"https", "acme-v02.api.letsencrypt.org", "443"}}},
		{"staging", "acme:\n  ca: letsencrypt-staging\n", []Endpoint{{"https", "acme-staging-v02.api.letsencrypt.org", "443"}}},
		{"url", "acme:\n  ca: https://ca.example:14000/dir\n", []Endpoint{{"https", "ca.example", "14000"}}},
		{"url default port", "acme:\n  ca: https://ca.example/dir\n", []Endpoint{{"https", "ca.example", "443"}}},
		{"ipv6", "acme:\n  ca: \"https://[2606:4700::1111]:8443/\"\n", []Endpoint{{"https", "2606:4700::1111", "8443"}}},
		{"ipv6 long form", "acme:\n  ca: \"https://[2001:4860:0::8888]/\"\n", []Endpoint{{"https", "2001:4860::8888", "443"}}},
		{"ipv4-mapped", "acme:\n  ca: \"https://[::ffff:8.8.8.8]/\"\n", []Endpoint{{"https", "8.8.8.8", "443"}}},
		{"upper case host", "acme:\n  ca: https://CA.Example:14000/dir\n", []Endpoint{{"https", "ca.example", "14000"}}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			body := "acme:\n  email: sec@example.com\n" + acmeNames
			if r.file != "" {
				body += strings.TrimPrefix(r.file, "acme:\n")
			}
			c, err := loadTest(writeConfig(t, body+tlogOrigin), nil)
			if err != nil {
				t.Fatal(err)
			}
			if want := append(r.want, ckptEndpoint); !reflect.DeepEqual(c.AllowList(), want) {
				t.Errorf("got %+v, want %+v", c.AllowList(), want)
			}
		})
	}
}

// TestTU10_PathForm checks the path helper.
func TestTU10_PathForm(t *testing.T) {
	runRows(t, []row{
		{"absolute", "/var/lib/phantom/certs", ""},
		{"root", "/", ""},
		{"relative", "certs", "absolute"},
		{"dot", ".", "absolute"},
		{"empty", "", "absolute"},
		{"dot dot", "/var/lib/../lib/x", "clean"},
		{"dot segment", "/var/./lib", "clean"},
		{"double slash", "/var//lib", "clean"},
		{"trailing slash", "/var/lib/", "clean"},
		{"NUL", "/var/lib/a\x00b", "NUL"},
	}, checkPathForm)
}

// tree makes a state root with an outside directory, and a loader for them.
type tree struct {
	l             *loader
	root, outside string
}

func newTree(t *testing.T) tree {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := tree{root: filepath.Join(d, "state"), outside: filepath.Join(d, "outside")}
	for _, p := range []string{tr.root, tr.root + "-evil", tr.outside} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tr.l = &loader{stateRoot: tr.root, euid: os.Geteuid()}
	return tr
}

// TestTU10_StatePath checks that acme.cache_dir stays under the state root after symlink resolution.
func TestTU10_StatePath(t *testing.T) {
	tr := newTree(t)
	link := func(name, target string) string {
		if err := os.Symlink(target, filepath.Join(tr.root, name)); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(tr.root, name)
	}
	if err := os.Mkdir(filepath.Join(tr.root, "certs"), 0o700); err != nil {
		t.Fatal(err)
	}
	inside := link("inside", filepath.Join(tr.root, "certs"))
	leaf := link("leaf", tr.outside)
	evilLeaf := link("evil", tr.root+"-evil")
	dangling := link("dangling", filepath.Join(tr.outside, "missing"))
	loop := link("loop", filepath.Join(tr.root, "loop"))
	rel := link("rel", "../outside")

	const outsideDetail = "not under the state directory"
	runRows(t, []row{
		{"root", tr.root, ""},
		{"existing dir", filepath.Join(tr.root, "certs"), ""},
		{"missing dir", filepath.Join(tr.root, "new", "sub"), ""},
		{"symlink inside", inside, ""},
		{"below symlink inside", filepath.Join(inside, "x"), ""},
		{"sibling with the root as prefix", tr.root + "-evil", outsideDetail},
		{"below sibling with the root as prefix", filepath.Join(tr.root+"-evil", "certs"), outsideDetail},
		{"parent of root", filepath.Dir(tr.root), outsideDetail},
		{"outside", tr.outside, outsideDetail},
		{"symlinked leaf to outside", leaf, outsideDetail},
		{"below symlinked leaf", filepath.Join(leaf, "certs"), outsideDetail},
		{"missing below symlinked leaf", filepath.Join(leaf, "a", "b"), outsideDetail},
		{"symlinked leaf to sibling", evilLeaf, outsideDetail},
		{"relative symlink to outside", rel, outsideDetail},
		{"dangling symlink to outside", dangling, "cannot resolve"},
		{"below dangling symlink", filepath.Join(dangling, "x"), "cannot resolve"},
		{"symlink loop", loop, "cannot resolve"},
		{"not clean", tr.root + "/certs/../../outside", "clean"},
		{"relative", "state/certs", "absolute"},
		{"NUL", tr.root + "/a\x00b", "NUL"},
	}, func(s string) string { return checkStatePath(tr.l, s) })

	if _, err := os.Lstat(filepath.Join(tr.root, "new")); !os.IsNotExist(err) {
		t.Errorf("the check created a directory: %v", err)
	}
}

// TestTU10_Htpasswd checks the htpasswd file rules and that the error detail is fixed text.
func TestTU10_Htpasswd(t *testing.T) {
	tr := newTree(t)
	file := func(name string, mode os.FileMode) string {
		p := filepath.Join(tr.outside, name)
		if err := os.WriteFile(p, []byte("u:hash\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	symlink := func(name, target string) string {
		p := filepath.Join(tr.outside, name)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := file("good", 0o600)
	dir := filepath.Join(tr.outside, "dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rows := []row{
		{"0600", good, ""},
		{"0400", file("r", 0o400), ""},
		{"0640", file("g-read", 0o640), ""},
		{"0660 group write", file("gw", 0o660), "writable by group"},
		{"0620 group write", file("gw2", 0o620), "writable by group"},
		{"0602 other write", file("ow", 0o602), "writable by other"},
		{"0604 other read", file("or", 0o604), "readable by other"},
		{"0644 other read", file("or2", 0o644), "readable by other"},
		{"0666", file("rw", 0o666), "writable by"},
		{"symlink to good file", symlink("l-good", good), ""},
		{"symlink to bad file", symlink("l-bad", file("bad", 0o644)), "readable by other"},
		{"symlink to dir", symlink("l-dir", dir), "not a regular file"},
		{"dir", dir, "not a regular file"},
		{"missing", filepath.Join(tr.outside, "missing"), "cannot be resolved"},
		{"dangling symlink", symlink("l-dangling", filepath.Join(tr.outside, "missing")), "cannot be resolved"},
		{"relative", "htpasswd", "absolute"},
		{"not clean", tr.outside + "/../outside/good", "clean"},
		{"NUL", good + "\x00", "NUL"},
	}
	runRows(t, rows, func(s string) string { return checkHtpasswd(tr.l, s) })

	// The detail is fixed text. It never holds the path.
	for _, r := range rows {
		if d := checkHtpasswd(tr.l, r.in); d != "" && strings.Contains(d, tr.outside) {
			t.Errorf("%s: the detail %q holds the path", r.name, d)
		}
	}

	t.Run("owner", func(t *testing.T) {
		other := &loader{stateRoot: tr.root, euid: os.Geteuid() + 1}
		got := checkHtpasswd(other, good)
		if os.Geteuid() == 0 {
			if got != "" {
				t.Errorf("root owner: got %q", got)
			}
			return
		}
		if !strings.Contains(got, "owner") {
			t.Errorf("got %q, want an owner error", got)
		}
	})
}

// TestTU10_HtpasswdOpen checks that the check opens the file one time, and reads the rules from the open file.
func TestTU10_HtpasswdOpen(t *testing.T) {
	tr := newTree(t)
	fifo := filepath.Join(tr.outside, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := checkHtpasswd(tr.l, fifo); !strings.Contains(got, "not a regular file") {
		t.Errorf("fifo: got %q", got)
	}
	if os.Geteuid() == 0 {
		t.Skip("root can open a file that has no read permission")
	}
	p := filepath.Join(tr.outside, "write-only")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o200); err != nil {
		t.Fatal(err)
	}
	if got := checkHtpasswd(tr.l, p); !strings.Contains(got, "cannot be opened") {
		t.Errorf("file with no read permission: got %q", got)
	}
}

// TestTU10_HtpasswdValueOnly checks three things (T-U-10). The Value field
// holds the full path. Error() cuts the path to 64 bytes. The detail is fixed
// text.
func TestTU10_HtpasswdValueOnly(t *testing.T) {
	useTestKeys(t)
	p := filepath.Join(t.TempDir(), strings.Repeat("n", 90))
	_, err := loadTest(writeConfig(t, base+"ops:\n  basic_auth_htpasswd: "+p+"\n"), nil)
	if err == nil {
		t.Fatal("no error")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("got %T", err)
	}
	if e.Detail != "the htpasswd file cannot be resolved" || e.Value != p {
		t.Errorf("got detail %q, value %q", e.Detail, e.Value)
	}
	s := err.Error()
	if strings.Contains(s, p) || strings.Contains(s, strings.Repeat("n", 65)) {
		t.Errorf("the error shows more than 64 bytes of the path: %s", s)
	}
	if !strings.Contains(s, ": the htpasswd file cannot be resolved: value \"") {
		t.Errorf("the error has no value: %s", s)
	}
}

// TestTU10_FileThroughLoad checks that an htpasswd error shows through Load with the key and the file.
func TestTU10_FileThroughLoad(t *testing.T) {
	useTestKeys(t)
	p := filepath.Join(testDir, "wide")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err := loadTest(writeConfig(t, base+"ops:\n  basic_auth_htpasswd: "+p+"\n"), nil)
	if err == nil || !strings.Contains(err.Error(), "ops.basic_auth_htpasswd") || !strings.Contains(err.Error(), "writable by group") {
		t.Errorf("got %v", err)
	}
}

// TestTU10_URLOutput checks that a URL-kind value that fails is not printed, and that
// the loader still prints an acme.email that holds an "@".
func TestTU10_URLOutput(t *testing.T) {
	useTestKeys(t)
	const secret = "s3cr3t_marker"
	for _, ca := range []string{
		"https://user:" + secret + "@ca.example/dir",
		"https://" + secret + "@ca.example/dir",
		"https://ca.example/dir#" + secret,
		"https://ca.example/%zz" + secret,
		"https://[" + secret,
		"tcp://" + secret + ".example:443",
		"https:" + secret,
		"http://" + secret + ".example/",
		secret,
		"https://[fe81::" + secret + "]/",
	} {
		t.Run(ca, func(t *testing.T) {
			_, err := loadTest(writeConfig(t, "acme:\n  email: sec@example.com\n  ca: \""+ca+"\"\n"+tlogOrigin), nil)
			if err == nil || !strings.Contains(err.Error(), "acme.ca") {
				t.Fatalf("got %v", err)
			}
			for _, part := range []string{secret, "ca.example", "user:", "REDACTED", `value "`} {
				if strings.Contains(err.Error(), part) {
					t.Errorf("the error shows %q: %v", part, err)
				}
			}
		})
	}
	t.Run("env", func(t *testing.T) {
		_, err := loadTest(writeConfig(t, base), []string{"PHANTOM_ACME_CA=https://u:" + secret + "@h/"})
		if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "PHANTOM_ACME_CA") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("email keeps the at sign", func(t *testing.T) {
		_, err := loadTest(writeConfig(t, "acme:\n  email: \"ops@corp.example, b@corp.example\"\n"+tlogOrigin), nil)
		if err == nil || !strings.Contains(err.Error(), `value "ops@corp.example, b@corp.example"`) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("valid email passes", func(t *testing.T) {
		if _, err := loadTest(writeConfig(t, "acme:\n  email: ops@corp.example\n"+acmeNames+tlogOrigin), nil); err != nil {
			t.Error(err)
		}
	})
}

// loadProd loads file with the production key table. The default htpasswd path does not exist
// on a test host, so the call sets it through the environment.
func loadProd(t *testing.T, file string, env ...string) (*Config, error) {
	t.Helper()
	const htpasswdEnv = "PHANTOM_OPS_BASIC_AUTH_HTPASSWD"
	// The loader rejects a variable that is in env two times.
	// So the default is set only if the caller does not set it.
	if !slices.ContainsFunc(env, func(kv string) bool { return strings.HasPrefix(kv, htpasswdEnv+"=") }) {
		env = append([]string{htpasswdEnv + "=" + filepath.Join(testDir, "htpasswd")}, env...)
	}
	return loadTest(writeConfig(t, file), env)
}

// TestTS10_LoadCRLF checks that a full valid config with CRLF line ends loads.
// It gives the same values as the config with LF line ends. The load refuses
// the config if one line end is a lone CR (T-S-10).
func TestTS10_LoadCRLF(t *testing.T) {
	lf, err := loadProd(t, base, listEnv...)
	if err != nil {
		t.Fatal(err)
	}
	crlf, err := loadProd(t, strings.ReplaceAll(base, "\n", "\r\n"), listEnv...)
	if err != nil {
		t.Fatalf("CRLF line ends: got %v", err)
	}
	for _, key := range []string{"acme.email", "acme.names[0]", "tlog.origin"} {
		a, aok := lf.Get(key)
		b, bok := crlf.Get(key)
		if !aok || !bok || a.Str == "" || a.Str != b.Str {
			t.Errorf("%s: LF %q (%v), CRLF %q (%v)", key, a.Str, aok, b.Str, bok)
		}
	}
	lone := strings.Replace(strings.ReplaceAll(base, "\n", "\r\n"), "\r\n", "\r", 1)
	if _, err := loadProd(t, lone, listEnv...); err == nil || !strings.Contains(err.Error(), crRule) {
		t.Errorf("lone CR: got %v", err)
	}
}

// TestTS11_ConflictFoldsStateRoot checks that storeConflict and cacheConflict
// fold the letters of the state directory too. The default state directory has
// lower case letters only, so --check cannot test this (T-S-11).
func TestTS11_ConflictFoldsStateRoot(t *testing.T) {
	l := &loader{stateRoot: "/Srv/Phantom"}
	runRows(t, []row{
		{"keys", "/srv/phantom/keys/e.db", "the keys directory"},
		{"checkpoints", "/srv/phantom/checkpoints/e.db", "the checkpoints directory"},
		{"checkpoint.state", "/srv/phantom/checkpoint.state", "must not be checkpoint.state"},
		{"checkpoint.state.tmp", "/srv/phantom/checkpoint.state.tmp", "must not be checkpoint.state.tmp"},
		{"writer.stop", "/srv/phantom/writer.stop", "must not be writer.stop"},
	}, func(p string) string { return storeConflict(l.stateRoot, nil, p) })
	runRows(t, []row{
		{"keys", "/srv/phantom/keys/c", "the keys directory"},
		{"checkpoints", "/srv/phantom/checkpoints/c", "the checkpoints directory"},
	}, func(p string) string { return cacheConflict(l.stateRoot, nil, p) })
}

// bound is one row of the 04 section 3 bounds table: values that pass, values that fail,
// and the other variables that the row needs. The test sets a value by its PHANTOM_ variable.
type bound struct {
	key        string
	pass, fail []string
	with       []string
}

var (
	longOrigin = strings.Repeat("a", 128)
	fetchURL   = "PHANTOM_BUNDLE_FETCH_URL=https://bundle.example/current"
	// groupWritable is a file in a temp dir with mode 0660. The other bad values of the htpasswd row
	// are a relative path, an unclean path, and a missing file. All of them go through the PHANTOM_ variable.
	groupWritable = func() string {
		p := filepath.Join(testDir, "group-writable")
		err := os.WriteFile(p, nil, 0o600)
		if err == nil {
			err = os.Chmod(p, 0o660)
		}
		if err != nil {
			panic(err)
		}
		return p
	}()
)

// scalarBounds mirrors the bounds table for each scalar key (min and max pass; min-1 and max+1 fail).
var scalarBounds = []bound{
	{key: "listen.http", pass: []string{":1", ":65535"}, fail: []string{":0", ":65536", "x", "[]:80"}},
	{key: "listen.https", pass: []string{":1", ":65535"}, fail: []string{":0", ":65536", ":80", "[]:80"}},
	{key: "ops.listen", pass: []string{"127.0.0.1:1", "[::1]:65535", "10.0.0.1:9443"}, fail: []string{"127.0.0.1:0", "127.0.0.1:65536", "0.0.0.0:9443", "8.8.8.8:9443", "localhost:9443"}},
	{key: "ops.basic_auth_htpasswd", pass: []string{filepath.Join(testDir, "htpasswd")}, fail: []string{"htpasswd", testDir + "/./htpasswd", filepath.Join(testDir, "missing"), groupWritable}},
	{key: "acme.email", pass: []string{"a@b.example"}, fail: []string{"a@b.example\nBcc: c@d.example", "a@b.example, c@d.example", ""}},
	{key: "acme.ca", pass: []string{"letsencrypt", "letsencrypt-staging", "https://ca.example/dir"}, fail: []string{"http://ca.example/dir", "https://u:p@ca.example/", "https://169.254.169.254/"}},
	{key: "acme.cache_dir", pass: []string{"/var/lib/phantom/certs"}, fail: []string{"/var/lib/other", "var/lib/phantom", "/var/lib/phantom/../x"}},
	{key: "bundle.path", pass: []string{"/var/lib/phantom/bundle/current.cbnd"}, fail: []string{"/etc/current.cbnd", "bundle.cbnd", "/var/lib/phantom/b/../../x"}},
	{key: "bundle.fetch_url", pass: []string{"", "https://bundle.example:8443/b"}, fail: []string{"http://bundle.example/b", "https://u:p@bundle.example/b", "https://bundle.example/b#f", "https://169.254.169.254/b", "https://0.0.0.0/b", "ftp://bundle.example/b"}},
	{key: "bundle.fetch_interval", pass: []string{"15m", "168h"}, fail: []string{"14m59s", "168h1s", "0s", "-1h"}, with: []string{fetchURL}},
	{key: "bundle.fetch_interval", pass: []string{"15m", "168h"}, fail: []string{"14m59s", "168h1s", "1s", "0s", "-1h"}}, // The bounds apply also if the fetch is off.
	{key: "limits.max_conns", pass: []string{"1", "2000"}, fail: []string{"0", "2001", "-1"}},
	{key: "limits.body_bytes", pass: []string{"1", "65536"}, fail: []string{"0", "65537"}},
	{key: "limits.header_bytes", pass: []string{"8192", "16384"}, fail: []string{"8191", "16385", "1", "0"}},
	{key: "limits.per_ip_rps", pass: []string{"1", "1000"}, fail: []string{"0", "1001"}, with: []string{"PHANTOM_LIMITS_PER_IP_BURST=5000"}},
	// The default burst is 200. A larger rate fails on limits.per_ip_rps:
	// see the row "burst below rps" in TestTS11_CrossChecks.
	{key: "limits.per_ip_rps", pass: []string{"200"}},
	{key: "limits.per_ip_burst", pass: []string{"100", "5000"}, fail: []string{"99", "5001", "0"}, with: []string{"PHANTOM_LIMITS_PER_IP_RPS=100"}},
	{key: "limits.per_ip_burst", pass: []string{"1"}, fail: []string{"0"}, with: []string{"PHANTOM_LIMITS_PER_IP_RPS=1"}},
	{key: "limits.queue_depth", pass: []string{"1", "8192"}, fail: []string{"0", "8193"}},
	{key: "store.path", pass: []string{"/var/lib/phantom/events.db"}, fail: []string{"/tmp/events.db", "events.db"}},
	{key: "store.max_bytes", pass: []string{"268435456", "9223372036854775807"}, fail: []string{"268435455", "0", "9223372036854775808"}},
	{key: "store.retention_days.ip", pass: []string{"1", "7"}, fail: []string{"0", "8"}},
	{key: "store.retention_days.raw", pass: []string{"1", "30"}, fail: []string{"0", "31"}},
	{key: "store.retention_days.events", pass: []string{"30", "90"}, fail: []string{"29", "91", "0"}},
	{key: "store.retention_days.events", pass: []string{"5"}, fail: []string{"4"}, with: []string{"PHANTOM_STORE_RETENTION_DAYS_RAW=5"}},
	{key: "tlog.dir", pass: []string{"/var/lib/phantom/tlog"}, fail: []string{"/var/tlog", "tlog"}},
	{key: "tlog.origin", pass: []string{"a", longOrigin, "phantom/abc_1.2-x"}, fail: []string{"", longOrigin + "a", "phantom/<install_id>", "a b", "a\nb", "é"}},
	{key: "tlog.checkpoint_interval", pass: []string{"1m", "24h"}, fail: []string{"59s", "24h0m1s", "0s", "-1m"}},
	{key: "alerts.min_band", pass: []string{"agent-likely", "agent-confirmed"}, fail: []string{"human", "crawler", "", "Agent-Likely"}},
	{key: "privacy.store_body_prefix", pass: []string{"true", "false"}, fail: []string{"on", "yes", "1", "True"}},
	{key: "privacy.include_ip", pass: []string{"true", "false"}, fail: []string{"on", "yes", "1", "True"}},
}

// TestTS11_ScalarBounds runs the bounds table through Load, one value per PHANTOM_ variable.
func TestTS11_ScalarBounds(t *testing.T) {
	for _, b := range scalarBounds {
		env := envName(b.key)
		try := func(v string) error {
			_, err := loadProd(t, base, append([]string{env + "=" + v}, b.with...)...)
			return err
		}
		for _, v := range b.pass {
			if err := try(v); err != nil {
				t.Errorf("%s=%q: %v", b.key, v, err)
			}
		}
		for _, v := range b.fail {
			if err := try(v); err == nil || !strings.Contains(err.Error(), b.key+" at "+env) {
				t.Errorf("%s=%q: got %v, want an error that names the key and the variable", b.key, v, err)
			}
		}
	}
}

// TestTS11_CrossChecks checks the bounds that depend on a second key, for file values, and
// that a bound error names the key and the line of the key that fails.
func TestTS11_CrossChecks(t *testing.T) {
	rows := []struct{ name, file, want string }{
		{"burst below rps", "limits:\n  per_ip_rps: 300\n", "limits.per_ip_rps at " + cfg[len(cfg)-64:] + ":6: the value must not be more than limits.per_ip_burst"},
		{"burst set below rps", "limits:\n  per_ip_rps: 300\n  per_ip_burst: 250\n", "limits.per_ip_burst at " + cfg[len(cfg)-64:] + ":7: the value must not be less than limits.per_ip_rps"},
		{"burst equals rps", "limits:\n  per_ip_rps: 200\n", ""},
		{"events below raw", "store:\n  retention_days:\n    raw: 91\n", "store.retention_days.raw"}, // The raw bound fails first.
		{"events below raw 2", "store:\n  retention_days:\n    raw: 30\n    events: 29\n", "store.retention_days.events at " + cfg[len(cfg)-64:] + ":8: the value must not be less than"},
		{"interval, fetch off", "bundle:\n  fetch_interval: 1s\n", "bundle.fetch_interval at " + cfg[len(cfg)-64:] + ":6: the duration must be in the range"},
		{"interval, fetch on", "bundle:\n  fetch_url: https://b.example/x\n  fetch_interval: 14m\n", "bundle.fetch_interval at " + cfg[len(cfg)-64:] + ":7: the duration must be in the range"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := loadProd(t, base+r.file)
			if (r.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), r.want)) {
				t.Errorf("got %v, want %q", err, r.want)
			}
		})
	}
}

// TestTS11_StorePathText checks the store.path rules for the path text below the state directory (SEC-20).
func TestTS11_StorePathText(t *testing.T) {
	tr := newTree(t)
	in := func(s string) string { return tr.root + "/" + s }
	const partDetail = "each path part below the state directory"
	runRows(t, []row{
		{"file", in("events.db"), ""},
		{"nested", in("db/events-2.db"), ""},
		{"all permitted marks", in("a.B_c-9/E_1.db"), ""},
		{"dots inside a part", in("a..b"), ""},
		{"question mark", in("events.db?mode=ro"), partDetail},
		{"question mark in a parent", in("a?/events.db"), partDetail},
		{"hash", in("events.db#x"), partDetail},
		{"space", in("my events.db"), partDetail},
		{"non-ASCII letter", in("évents.db"), partDetail},
		{"colon", in("events:db"), partDetail},
		{"backslash", in(`a\b`), partDetail},
		{"dot dot part", in("a/../events.db"), "clean"}, // The rule that runs first refuses the part.
		{"state root", tr.root, "the path text must be below the state directory"},
		{"sibling of the root", tr.root + "-evil/events.db", "not under the state directory"},
		{"outside", tr.outside + "/events.db", "not under the state directory"},
		{"relative", "events.db", "absolute"},
	}, func(s string) string { return checkStorePath(tr.l, s) })
	// The rule applies only below the state directory: it does not check the parts of the root.
	spaced := &loader{stateRoot: tr.root + "/a b?", euid: os.Geteuid()}
	if d := checkStorePath(spaced, spaced.stateRoot+"/events.db"); d != "" {
		t.Errorf("state root with a space: %q", d)
	}
}

// tlogLines returns the number of line breaks that the load error has. The
// store.path error can be "in tlog.dir". Then tlog.dir is in or above
// store.path, and it has its own error.
func tlogLines(want string) int {
	if want == "in tlog.dir" {
		return 1
	}
	return 0
}

// TestTS11_StorePathLoad checks that the load refuses a store.path in a
// directory of another key, or a state file. The error names store.path.
// A path in tlog.dir also gives an error on tlog.dir. Each row runs with
// the other key at its default and set (SEC-20).
func TestTS11_StorePathLoad(t *testing.T) {
	const s = "/var/lib/phantom/"
	rows := []struct {
		name, path string
		with       []string
		want       string // want is "" for a path that loads.
	}{
		{"default", s + "events.db", nil, ""},
		{"nested file", s + "db/events-2.db", nil, ""},
		{"name that starts like tlog", s + "tlog2/events.db", nil, ""},
		{"question mark", s + "events.db?mode=rwc", nil, "each path part"},
		{"hash", s + "events.db#x", nil, "each path part"},
		{"space", s + "my events.db", nil, "each path part"},
		{"non-ASCII letter", s + "évents.db", nil, "each path part"},
		{"dot dot", s + "a/../events.db", nil, "must be clean"},
		{"state root", "/var/lib/phantom", nil, "below the state directory"},
		{"tlog.dir default", s + "tlog/e.db", nil, "in tlog.dir"},
		{"tlog.dir itself", s + "tlog", nil, "in tlog.dir"},
		{"tlog.dir set", s + "t2/e.db", []string{"PHANTOM_TLOG_DIR=" + s + "t2"}, "in tlog.dir"},
		{"tlog.dir set, itself", s + "t2", []string{"PHANTOM_TLOG_DIR=" + s + "t2"}, "in tlog.dir"},
		{"acme.cache_dir default", s + "certs/e.db", nil, "in acme.cache_dir"},
		{"acme.cache_dir itself", s + "certs", nil, "in acme.cache_dir"},
		{"acme.cache_dir set", s + "c2/e.db", []string{"PHANTOM_ACME_CACHE_DIR=" + s + "c2"}, "in acme.cache_dir"},
		{"bundle dir default", s + "bundle/e.db", nil, "directory of bundle.path"},
		{"bundle dir set", s + "b2/e.db", []string{"PHANTOM_BUNDLE_PATH=" + s + "b2/current.cbnd"}, "directory of bundle.path"},
		{"keys", s + "keys/e.db", nil, "keys directory"},
		{"keys itself", s + "keys", nil, "keys directory"},
		{"checkpoints", s + "checkpoints/e.db", nil, "checkpoints directory"},
		{"checkpoints itself", s + "checkpoints", nil, "checkpoints directory"},
		{"checkpoint.state", s + "checkpoint.state", nil, "must not be checkpoint.state"},
		{"checkpoint.state.tmp", s + "checkpoint.state.tmp", nil, "must not be checkpoint.state.tmp"},
		{"writer.stop", s + "writer.stop", nil, "must not be writer.stop"},
		{"tlog.dir in other case", s + "TLOG/e.db", nil, "in tlog.dir"},
		{"tlog.dir itself in other case", s + "Tlog", nil, "in tlog.dir"},
		{"tlog.dir set, in other case", s + "Logs/e.db", []string{"PHANTOM_TLOG_DIR=" + s + "logs"}, "in tlog.dir"},
		{"acme.cache_dir in other case", s + "CERTS/e.db", nil, "in acme.cache_dir"},
		{"acme.cache_dir set, in other case", s + "Cache/e.db", []string{"PHANTOM_ACME_CACHE_DIR=" + s + "cache"}, "in acme.cache_dir"},
		{"bundle dir in other case", s + "Bundle/e.db", nil, "directory of bundle.path"},
		{"bundle dir set, in other case", s + "A/events.db", []string{"PHANTOM_BUNDLE_PATH=" + s + "a/x.cbnd"}, "directory of bundle.path"},
		{"bundle dir set, nested in other case", s + "A/b/events.db", []string{"PHANTOM_BUNDLE_PATH=" + s + "a/x.cbnd"}, "directory of bundle.path"},
		{"keys in other case", s + "Keys/e.db", nil, "keys directory"},
		{"checkpoints in other case", s + "CHECKPOINTS/e.db", nil, "checkpoints directory"},
		{"checkpoint.state in other case", s + "Checkpoint.State", nil, "must not be checkpoint.state"},
		{"checkpoint.state.tmp in other case", s + "CHECKPOINT.STATE.TMP", nil, "must not be checkpoint.state.tmp"},
		{"writer.stop in other case", s + "WRITER.STOP", nil, "must not be writer.stop"},
		{"tlog.dir set in other case", s + "logs/e.db", []string{"PHANTOM_TLOG_DIR=" + s + "LOGS"}, "in tlog.dir"},
		{"acme.cache_dir set in other case", s + "cache/e.db", []string{"PHANTOM_ACME_CACHE_DIR=" + s + "CACHE"}, "in acme.cache_dir"},
		{"bundle dir set in other case", s + "b/e.db", []string{"PHANTOM_BUNDLE_PATH=" + s + "B/x.cbnd"}, "directory of bundle.path"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := loadProd(t, base, append([]string{"PHANTOM_STORE_PATH=" + r.path}, r.with...)...)
			switch {
			case r.want == "" && err != nil, r.want != "" && err == nil:
				t.Fatalf("got %v, want %q", err, r.want)
			case err == nil:
			case !strings.Contains(err.Error(), "store.path at PHANTOM_STORE_PATH: ") || !strings.Contains(err.Error(), r.want):
				t.Errorf("got %v, want an error on store.path with %q", err, r.want)
			case strings.Count(err.Error(), "\n") != tlogLines(r.want):
				t.Errorf("got %v, want no error on another key but tlog.dir", err)
			}
		})
	}
	// The bundle file is in its own directory: the load gives one error for each key, and each error names its key.
	t.Run("bundle file in its dir", func(t *testing.T) {
		_, err := loadProd(t, base, "PHANTOM_STORE_PATH="+s+"b2/current.cbnd", "PHANTOM_BUNDLE_PATH="+s+"b2/current.cbnd")
		if err == nil {
			t.Fatal("got no error")
		}
		for _, want := range []string{
			"store.path at PHANTOM_STORE_PATH: the path must not be in the directory of bundle.path",
			"bundle.path at PHANTOM_BUNDLE_PATH: the path must not be store.path",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("got %v, want an error with %q", err, want)
			}
		}
		if strings.Count(err.Error(), "\n") != 1 {
			t.Errorf("got %v, want exactly two errors", err)
		}
	})
	// store.path is above tlog.dir: only tlog.dir has an error.
	t.Run("store.path above tlog.dir", func(t *testing.T) {
		_, err := loadProd(t, base, "PHANTOM_STORE_PATH="+s+"a", "PHANTOM_TLOG_DIR="+s+"a/t")
		if err == nil || !strings.Contains(err.Error(), "tlog.dir at PHANTOM_TLOG_DIR: the path must not be in or above store.path") || strings.Contains(err.Error(), "store.path at ") {
			t.Errorf("got %v, want one error on tlog.dir", err)
		}
	})
	t.Run("moved tlog dir, default store", func(t *testing.T) {
		if _, err := loadProd(t, base, "PHANTOM_TLOG_DIR="+s+"t2"); err != nil {
			t.Error(err)
		}
	})
}

// TestTS11_StorePathFailedKey checks that a tlog.dir that failed its own check is not in the store.path rules.
func TestTS11_StorePathFailedKey(t *testing.T) {
	_, err := loadProd(t, base, "PHANTOM_TLOG_DIR=/elsewhere", "PHANTOM_STORE_PATH=/var/lib/phantom/tlog/e.db")
	if err == nil || strings.Contains(err.Error(), "store.path") || !strings.Contains(err.Error(), "tlog.dir") {
		t.Errorf("got %v", err)
	}
}

// TestTS11_TLogDirText checks that tlog.dir has the path rules of store.path.
// The load gives one error that names tlog.dir. This is also true for the
// state directory and for a link that leads below it (SEC-11).
func TestTS11_TLogDirText(t *testing.T) {
	tr := newTree(t)
	if err := os.Mkdir(tr.root+"/tlog", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(tr.root+"/tlog", tr.outside+"/ln"); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct{ name, dir, want string }{
		{"below the root", tr.root + "/tlog", ""},
		{"state directory", tr.root, "the path text must be below the state directory"},
		{"link that leads below the root", tr.outside + "/ln", "the path text must be below the state directory"},
		{"space", tr.root + "/t l", "each path part"},
		{"question mark", tr.root + "/t?", "each path part"},
	} {
		t.Run(r.name, func(t *testing.T) {
			env := []string{
				"PHANTOM_OPS_BASIC_AUTH_HTPASSWD=" + filepath.Join(testDir, "htpasswd"),
				tokenVar + "=" + strings.Repeat("t", 32),
				"PHANTOM_ACME_CACHE_DIR=" + tr.root + "/certs",
				"PHANTOM_BUNDLE_PATH=" + tr.root + "/bundle/current.cbnd",
				"PHANTOM_STORE_PATH=" + tr.root + "/events.db",
				"PHANTOM_TLOG_DIR=" + r.dir,
			}
			_, err := tr.l.load(writeConfig(t, base), env, keys, testNet)
			switch {
			case r.want == "" && err != nil:
				t.Errorf("got %v", err)
			case r.want != "" && (err == nil || !strings.Contains(err.Error(), "tlog.dir at PHANTOM_TLOG_DIR: "+r.want) || strings.Contains(err.Error(), "\n")):
				t.Errorf("got %v, want one error on tlog.dir with %q", err, r.want)
			}
		})
	}
}

// TestTS11_TLogDirLoad checks that the load refuses a tlog.dir in or above the
// path of another key. It also refuses a state file. The compare folds A-Z.
// The error names tlog.dir (SEC-11).
func TestTS11_TLogDirLoad(t *testing.T) {
	const s = "/var/lib/phantom/"
	rows := []struct {
		name, dir string
		with      []string
		want      string // want is "" for a value that loads.
	}{
		{"default", s + "tlog", nil, ""},
		{"name that starts like keys", s + "keys2", nil, ""},
		{"name that starts like writer.stop", s + "writer.stop2", nil, ""},
		{"acme.cache_dir", s + "certs", nil, "in or above acme.cache_dir"},
		{"in acme.cache_dir", s + "certs/t", nil, "in or above acme.cache_dir"},
		{"above acme.cache_dir", s + "a", []string{"PHANTOM_ACME_CACHE_DIR=" + s + "a/c"}, "in or above acme.cache_dir"},
		{"bundle directory", s + "bundle", nil, "in or above the directory of bundle.path"},
		{"above the bundle directory", s + "b", []string{"PHANTOM_BUNDLE_PATH=" + s + "b/x/current.cbnd"}, "in or above the directory of bundle.path"},
		{"store.path", s + "events.db", nil, "in or above store.path"},
		{"above store.path", s + "d", []string{"PHANTOM_STORE_PATH=" + s + "d/e.db"}, "in or above store.path"},
		{"keys", s + "keys", nil, "in or above the keys directory"},
		{"in keys", s + "keys/t", nil, "in or above the keys directory"},
		{"checkpoints", s + "checkpoints", nil, "in or above the checkpoints directory"},
		{"checkpoint.state", s + "checkpoint.state", nil, "must not be checkpoint.state"},
		{"checkpoint.state.tmp", s + "checkpoint.state.tmp", nil, "must not be checkpoint.state.tmp"},
		{"writer.stop", s + "writer.stop", nil, "must not be writer.stop"},
		{"keys in other case", s + "Keys", nil, "in or above the keys directory"},
		{"writer.stop in other case", s + "WRITER.STOP", nil, "must not be writer.stop"},
		{"in checkpoints in other case", s + "CHECKPOINTS/x", nil, "in or above the checkpoints directory"},
		{"writer.stop with a capital", s + "Writer.Stop", nil, "must not be writer.stop"},
		{"acme.cache_dir in other case", s + "CERTS", nil, "in or above acme.cache_dir"},
		{"above acme.cache_dir in other case", s + "A", []string{"PHANTOM_ACME_CACHE_DIR=" + s + "a/c"}, "in or above acme.cache_dir"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := loadProd(t, base, append([]string{"PHANTOM_TLOG_DIR=" + r.dir}, r.with...)...)
			switch {
			case r.want == "" && err != nil:
				t.Errorf("got %v", err)
			case r.want != "" && (err == nil || !strings.Contains(err.Error(), "tlog.dir at PHANTOM_TLOG_DIR: the path must not be "+strings.TrimPrefix(r.want, "must not be "))):
				t.Errorf("got %v, want an error on tlog.dir with %q", err, r.want)
			}
		})
	}
	// The state directory fails its own check.
	// So no other key names it in an error.
	t.Run("state directory", func(t *testing.T) {
		_, err := loadProd(t, base, "PHANTOM_TLOG_DIR=/var/lib/phantom")
		if err == nil || !strings.Contains(err.Error(), "tlog.dir at ") || strings.Count(err.Error(), "\n") != 0 {
			t.Errorf("got %v, want one error on tlog.dir", err)
		}
	})
}

// TestTS11_BundlePathLoad checks that the load refuses a bundle.path with a bad path part, file name, or directory (SEC-23).
// It also checks the value of store.path. The error names bundle.path.
// Each row runs with the key that it compares with (tlog.dir, acme.cache_dir or store.path) at its default or set.
func TestTS11_BundlePathLoad(t *testing.T) {
	const s = "/var/lib/phantom/"
	rows := []struct {
		name, path string
		with       []string
		want       string // want is "" for a path that loads.
	}{
		{"default", s + "bundle/current.cbnd", nil, ""},
		{"sibling directory", s + "bundle2/x.cbnd", nil, ""},
		{"nested directory", s + "bundle/a/b/current.cbnd", nil, ""},
		{"name that starts like tlog", s + "tlog2/x.cbnd", nil, ""},
		{"all permitted characters", s + "Ab_1.x-y/Z.cbnd", nil, ""},
		{"question mark", s + "bundle/c?.cbnd", nil, "each path part"},
		{"hash in a parent", s + "bun#dle/current.cbnd", nil, "each path part"},
		{"space", s + "bundle/my bundle.cbnd", nil, "each path part"},
		{"non-ASCII letter", s + "bundle/cürrent.cbnd", nil, "each path part"},
		{"dot dot", s + "bundle/../x.cbnd", nil, "must be clean"},
		{"outside the state directory", "/etc/current.cbnd", nil, "state directory"},
		{"state directory", "/var/lib/phantom", nil, "below the state directory"},
		{"other suffix", s + "bundle/current.bin", nil, "must end in .cbnd"},
		{"signature file", s + "bundle/current.cbnd.sig", nil, "must end in .cbnd"},
		{"suffix in other case", s + "bundle/current.CBND", nil, "must end in .cbnd"},
		{"no suffix", s + "bundle/current", nil, "must end in .cbnd"},
		{"file in the state directory", s + "current.cbnd", nil, "must not be the state directory"},
		{"tlog.dir default", s + "tlog/x.cbnd", nil, "in or above tlog.dir"},
		{"in tlog.dir", s + "tlog/a/x.cbnd", nil, "in or above tlog.dir"},
		{"tlog.dir set", s + "t2/x.cbnd", []string{"PHANTOM_TLOG_DIR=" + s + "t2"}, "in or above tlog.dir"},
		{"above tlog.dir", s + "a/x.cbnd", []string{"PHANTOM_TLOG_DIR=" + s + "a/t"}, "in or above tlog.dir"},
		{"acme.cache_dir default", s + "certs/x.cbnd", nil, "in or above acme.cache_dir"},
		{"in acme.cache_dir", s + "certs/a/x.cbnd", nil, "in or above acme.cache_dir"},
		{"acme.cache_dir set", s + "c2/x.cbnd", []string{"PHANTOM_ACME_CACHE_DIR=" + s + "c2"}, "in or above acme.cache_dir"},
		{"above acme.cache_dir", s + "c/x.cbnd", []string{"PHANTOM_ACME_CACHE_DIR=" + s + "c/d"}, "in or above acme.cache_dir"},
		{"keys", s + "keys/x.cbnd", nil, "keys directory"},
		{"in keys", s + "keys/a/x.cbnd", nil, "keys directory"},
		{"checkpoints", s + "checkpoints/x.cbnd", nil, "checkpoints directory"},
		{"in checkpoints", s + "checkpoints/a/x.cbnd", nil, "checkpoints directory"},
		{"store.path", s + "b2/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "b2/x.cbnd"}, "must not be store.path"},
		{"file name .cbnd alone", s + "bundle/.cbnd", nil, "character before .cbnd"},
		{"file name one character", s + "bundle/a.cbnd", nil, ""},
		{"keys in other case", s + "Keys/x.cbnd", nil, "keys directory"},
		{"in checkpoints in other case", s + "CHECKPOINTS/a/x.cbnd", nil, "checkpoints directory"},
		{"checkpoint.state", s + "checkpoint.state/x.cbnd", nil, "be in checkpoint.state"},
		{"in checkpoint.state", s + "checkpoint.state/a/x.cbnd", nil, "be in checkpoint.state"},
		{"checkpoint.state.tmp", s + "checkpoint.state.tmp/x.cbnd", nil, "be in checkpoint.state.tmp"},
		{"writer.stop", s + "writer.stop/x.cbnd", nil, "be in writer.stop"},
		{"writer.stop in other case", s + "WRITER.STOP/x.cbnd", nil, "be in writer.stop"},
		{"in checkpoint.state in other case", s + "Checkpoint.State/a/x.cbnd", nil, "be in checkpoint.state"},
		{"name that starts like writer.stop", s + "writer.stop2/x.cbnd", nil, ""},
		{"tlog.dir in other case", s + "TLOG/x.cbnd", nil, "in or above tlog.dir"},
		{"acme.cache_dir in other case", s + "Certs/x.cbnd", nil, "in or above acme.cache_dir"},
		{"store.path in other case", s + "B/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "b/x.cbnd"}, "must not be store.path"},
		{"directory is store.path", s + "db/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "db"}, "or a file of it"},
		{"directory is store.path in other case", s + "DB/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "db"}, "or a file of it"},
		{"in store.path", s + "db/a/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "db"}, "or a file of it"},
		{"directory is store.path-wal", s + "db-wal/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "db"}, "or a file of it"},
		{"in store.path-shm", s + "db-shm/a/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "db"}, "or a file of it"},
		{"directory is store.path-journal in other case", s + "DB-Journal/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "db"}, "or a file of it"},
		{"directory like store.path", s + "db2/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "db"}, ""},
		{"checkpoint.state.tmp in other case", s + "Checkpoint.State.TMP/x.cbnd", nil, "be in checkpoint.state.tmp"},
		{"directory is store.path-wal in other case", s + "DB-WAL/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "db"}, "or a file of it"},
		{"in store.path-shm in other case", s + "Db-Shm/a/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "db"}, "or a file of it"},
		{"in store.path in other case", s + "DB/a/x.cbnd", []string{"PHANTOM_STORE_PATH=" + s + "db"}, "or a file of it"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := loadProd(t, base, append([]string{"PHANTOM_BUNDLE_PATH=" + r.path}, r.with...)...)
			switch {
			case r.want == "" && err != nil, r.want != "" && err == nil:
				t.Fatalf("got %v, want %q", err, r.want)
			case err == nil:
			case !strings.Contains(err.Error(), "bundle.path at PHANTOM_BUNDLE_PATH: ") || !strings.Contains(err.Error(), r.want):
				t.Errorf("got %v, want an error on bundle.path with %q", err, r.want)
			}
		})
	}
}

// TestTS11_TLogDirKelvin checks a tlog.dir with a Kelvin sign (U+212A).
// The part rule refuses it. The error names tlog.dir only (SEC-11).
func TestTS11_TLogDirKelvin(t *testing.T) {
	_, err := loadProd(t, base, "PHANTOM_TLOG_DIR=/var/lib/phantom/\u212A", "PHANTOM_BUNDLE_PATH=/var/lib/phantom/k/x.cbnd")
	if err == nil || !strings.Contains(err.Error(), "tlog.dir at PHANTOM_TLOG_DIR: each path part") || strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("got %v, want one part-rule error on tlog.dir", err)
	}
}

// TestTS11_BundlePathFailedKey checks that the load gives the bundle.path error and no store.path error.
// A key that failed its own check is not in the cross-checks.
func TestTS11_BundlePathFailedKey(t *testing.T) {
	_, err := loadProd(t, base, "PHANTOM_BUNDLE_PATH=/var/lib/phantom/current.cbnd")
	if err == nil || !strings.Contains(err.Error(), "bundle.path") || strings.Contains(err.Error(), "store.path") {
		t.Errorf("got %v", err)
	}
}

// TestFoldASCII checks that foldASCII changes the letters A-Z only.
func TestFoldASCII(t *testing.T) {
	for _, r := range []struct{ in, want string }{
		{"KEYS", "keys"},
		{"Checkpoint.State", "checkpoint.state"},
		{"keys", "keys"},
		{"@[`{", "@[`{"},
		{"AZ", "az"},
		{"@AZ[", "@az["},
		{"\u212A", "\u212A"},
		{"\xc3\x89", "\xc3\x89"},
		{"", ""},
	} {
		if got := foldASCII(r.in); got != r.want {
			t.Errorf("foldASCII(%q) = %q, want %q", r.in, got, r.want)
		}
	}
}

// TestTU10_Defaults checks the 04 section 3 default of each key, on a minimal valid file.
func TestTU10_Defaults(t *testing.T) {
	c, err := loadProd(t, base)
	if err != nil {
		t.Fatal(err)
	}
	const state = "/var/lib/phantom/"
	rows := map[string]Value{
		"bundle.path":                 {Str: state + "bundle/current.cbnd"},
		"bundle.fetch_url":            {},
		"bundle.fetch_interval":       {Dur: 6 * time.Hour},
		"limits.max_conns":            {Int: 2000},
		"limits.body_bytes":           {Int: 65536},
		"limits.header_bytes":         {Int: 16384},
		"limits.per_ip_rps":           {Int: 50},
		"limits.per_ip_burst":         {Int: 200},
		"limits.queue_depth":          {Int: 4096},
		"store.path":                  {Str: state + "events.db"},
		"store.max_bytes":             {Int: 10737418240},
		"store.retention_days.ip":     {Int: 7},
		"store.retention_days.raw":    {Int: 30},
		"store.retention_days.events": {Int: 90},
		"tlog.dir":                    {Str: state + "tlog"},
		"tlog.checkpoint_interval":    {Dur: time.Hour},
		"alerts.min_band":             {Str: "agent-likely"},
		"privacy.store_body_prefix":   {Bool: true},
		"privacy.include_ip":          {},
	}
	for p, want := range rows {
		want.Source = "default"
		if got, ok := c.Get(p); !ok || got != want {
			t.Errorf("%s: got %+v, want %+v", p, got, want)
		}
	}
}

// TestTU10_Overrides checks that each key has a PHANTOM_ override that goes through the bounds.
// Each key of the table must have a row in scalarBounds.
func TestTU10_Overrides(t *testing.T) {
	rowOf := make(map[string]bound)
	for _, b := range scalarBounds {
		rowOf[b.key] = b
	}
	for _, k := range keys {
		b, ok := rowOf[k.path]
		if !ok {
			t.Errorf("%s has no row in scalarBounds", k.path)
			continue
		}
		if len(b.pass) == 0 {
			continue
		}
		v := b.pass[len(b.pass)-1]
		c, err := loadProd(t, base, append([]string{envName(k.path) + "=" + v}, b.with...)...)
		if err != nil {
			t.Errorf("%s: %v", envName(k.path), err)
			continue
		}
		if got, _ := c.Get(k.path); got.Source != envName(k.path) {
			t.Errorf("%s: the source is %q", k.path, got.Source)
		}
	}
	c, err := loadProd(t, base, "PHANTOM_LIMITS_BODY_BYTES=100", "PHANTOM_STORE_RETENTION_DAYS_IP=3")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Get("limits.body_bytes"); v.Int != 100 {
		t.Errorf("got %+v", v)
	}
	if v, _ := c.Get("store.retention_days.ip"); v.Int != 3 {
		t.Errorf("got %+v", v)
	}
	_, err = loadProd(t, base+"limits:\n  body_bytes: 100\n", "PHANTOM_LIMITS_BODY_BYTES=65537")
	if err == nil || !strings.Contains(err.Error(), "limits.body_bytes at PHANTOM_LIMITS_BODY_BYTES") {
		t.Errorf("got %v", err)
	}
}

// TestTU10_NewSectionsInvalid checks one invalid file value for each new section.
func TestTU10_NewSectionsInvalid(t *testing.T) {
	rows := []struct{ file, key string }{
		{base + "bundle:\n  fetch_url: http://b.example/x\n", "bundle.fetch_url"},
		{base + "limits:\n  body_bytes: 65537\n", "limits.body_bytes"},
		{base + "store:\n  retention_days:\n    ip: 8\n", "store.retention_days.ip"},
		{"acme:\n  email: sec@example.com\ntlog:\n  origin: \"phantom/<install_id>\"\n", "tlog.origin"},
		{base + "alerts:\n  min_band: human\n", "alerts.min_band"},
		{base + "privacy:\n  include_ip: 1\n", "privacy.include_ip"},
		{"acme:\n  email: sec@example.com\n", "tlog.origin"}, // The key is required.
	}
	for _, r := range rows {
		_, err := loadProd(t, r.file)
		if err == nil || !strings.Contains(err.Error(), r.key+" at ") {
			t.Errorf("%s: got %v", r.key, err)
		}
	}
}

// TestTU10_FetchURLAllowList checks that bundle.fetch_url adds its endpoint to the allow-list.
func TestTU10_FetchURLAllowList(t *testing.T) {
	c, err := loadProd(t, base)
	if err != nil || len(c.AllowList()) != 2 { // acme.ca and the publisher of base
		t.Fatalf("fetch off: %v, %+v", err, c)
	}
	c, err = loadProd(t, base, "PHANTOM_BUNDLE_FETCH_URL=https://Bundle.Example:8443/b")
	if err != nil {
		t.Fatal(err)
	}
	want := []Endpoint{{"https", "acme-v02.api.letsencrypt.org", "443"}, {"https", "bundle.example", "8443"}, ckptEndpoint}
	if got := c.AllowList(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// TestTS10_NewScalars checks strict scalars of the new keys through Load with the production table.
func TestTS10_NewScalars(t *testing.T) {
	rows := []struct{ name, file, key, want string }{
		{"YAML 1.1 bool on", "privacy:\n  include_ip: on\n", "privacy.include_ip", "the value is not a valid bool"},
		{"legacy octal", "limits:\n  max_conns: 0755\n", "limits.max_conns", "decimal literal only"},
		{"quoted int", "limits:\n  max_conns: \"100\"\n", "limits.max_conns", "the value is not a valid int"},
		{"float into int", "limits:\n  max_conns: 1.5\n", "limits.max_conns", "the value is not a valid int"},
		{"float into byte size", "limits:\n  body_bytes: 1.5\n", "limits.body_bytes", "the value is not a valid byte size"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := loadProd(t, base+r.file)
			if err == nil || !strings.Contains(err.Error(), r.key+" at ") || !strings.Contains(err.Error(), r.want) {
				t.Errorf("got %v", err)
			}
		})
	}
}

// Flow mappings for the list items. The variables that they name are in listEnv and in loadTest.
const (
	acmeTlog = "acme:\n  email: sec@example.com\n" + acmeNames + "tlog:\n  origin: test/origin\n"
	pubItem  = `{type: https-put, url: "https://ckpt.example/put", token_env: CKPT_TOKEN}`
	hookItem = `{type: webhook, url: "https://hook.example/a", hmac_secret_env: ALERT_HMAC}`
	sysItem  = `{type: syslog, addr: "udp://127.0.0.1:514"}`
	mailItem = `{type: smtp, host: "smtp://mail.example:587", from: a@b.example, to: [c@d.example]}`
)

// listEnv sets the variable of the webhook items to 32 bytes: the minimum of SEC-06.
var listEnv = []string{"ALERT_HMAC=" + strings.Repeat("h", 32)}

// pub returns a file whose tlog.publish list holds the items.
func pub(items ...string) string {
	return acmeTlog + "  publish:\n    - " + strings.Join(items, "\n    - ") + "\n"
}

// snk returns base and an alerts.sinks list that holds the items.
func snk(items ...string) string {
	return base + "alerts:\n  sinks:\n    - " + strings.Join(items, "\n    - ") + "\n"
}

// TestTS11_Lists checks the list rows of the 04 section 3 bounds table and the secret rules through Load:
// the minimum and the maximum pass, one past each edge fails, and each error names the key path (T-S-11).
func TestTS11_Lists(t *testing.T) {
	many := func(n int, s string) []string { return slices.Repeat([]string{s}, n) }
	to := func(n int) string { return "[" + strings.Join(many(n, "c@d.example"), ", ") + "]" }
	mail := func(f string) string {
		return `{type: smtp, host: "smtp://mail.example:587", from: a@b.example, ` + f + "}"
	}
	sys := func(addr string) string { return `{type: syslog, addr: "` + addr + `"}` }
	smtpHost := func(h string) string { return `{type: smtp, host: "` + h + `", from: a@b.example, to: [c@d.example]}` }
	tok := func(v string) string { return `{type: https-put, url: "https://a.example/", token_env: ` + v + "}" }
	hmac := func(v string) string { return `{type: webhook, url: "https://a.example/", hmac_secret_env: ` + v + "}" }
	rows := []struct {
		name, file string
		env        []string
		want       string // want is "" for an accepted file, or the key path that the error names.
	}{
		{"publish 1", pub(pubItem), nil, ""},
		{"publish 4", pub(many(4, pubItem)...), nil, ""},
		{"publish 5", pub(many(5, pubItem)...), nil, "tlog.publish"},
		{"publish empty", acmeTlog + "  publish: []\n", nil, "tlog.publish"},
		{"publish missing", acmeTlog, nil, "tlog.publish"},
		{"publish scalar", acmeTlog + "  publish: x\n", nil, "tlog.publish"},
		{"publish item scalar", pub("x"), nil, "tlog.publish[0]"},
		{"publish type", pub(`{type: s3, url: "https://a.example/", token_env: CKPT_TOKEN}`), nil, "tlog.publish[0].type"},
		{"publish type missing", pub(`{url: "https://a.example/", token_env: CKPT_TOKEN}`), nil, "tlog.publish[0].type"},
		{"publish url missing", pub(`{type: https-put, token_env: CKPT_TOKEN}`), nil, "tlog.publish[0].url"},
		{"publish url http", pub(`{type: https-put, url: "http://a.example/", token_env: CKPT_TOKEN}`), nil, "tlog.publish[0].url"},
		{"publish url user info", pub(`{type: https-put, url: "https://u:p@a.example/", token_env: CKPT_TOKEN}`), nil, "tlog.publish[0].url"},
		{"publish url link-local", pub(`{type: https-put, url: "https://169.254.169.254/", token_env: CKPT_TOKEN}`), nil, "tlog.publish[0].url"},
		{"publish url fragment", pub(`{type: https-put, url: "https://a.example/#f", token_env: CKPT_TOKEN}`), nil, "tlog.publish[0].url"},
		{"publish url not string", pub(`{type: https-put, url: 5, token_env: CKPT_TOKEN}`), nil, "tlog.publish[0].url"},
		{"publish token_env missing", pub(`{type: https-put, url: "https://a.example/"}`), nil, "tlog.publish[0].token_env"},
		{"publish unknown key", pub(pubItem, strings.TrimSuffix(pubItem, "}")+", extra: 1}"), nil, "tlog.publish[1].extra"},
		{"publish unknown mapping", pub(strings.TrimSuffix(pubItem, "}") + ", extra: {a: 1}}"), nil, "tlog.publish[0].extra"},
		{"sinks 0", base + "alerts:\n  sinks: []\n", nil, ""},
		{"sinks absent", base, nil, ""},
		{"sinks 8", snk(many(8, sysItem)...), nil, ""},
		{"sinks 9", snk(many(9, sysItem)...), nil, "alerts.sinks"},
		{"sinks scalar", base + "alerts:\n  sinks: x\n", nil, "alerts.sinks"},
		{"sink type", snk(`{type: pager, addr: "udp://h:1"}`), nil, "alerts.sinks[0].type"},
		{"sink type missing", snk(`{addr: "udp://h:1"}`), nil, "alerts.sinks[0].type"},
		{"sink type mapping", snk(`{type: {a: 1}, addr: "udp://h:1"}`), nil, "alerts.sinks[0].type"},
		{"sink unknown key", snk(hookItem, strings.TrimSuffix(sysItem, "}")+", extra: 1}"), listEnv, "alerts.sinks[1].extra"},
		{"sink key of another type", snk(strings.TrimSuffix(sysItem, "}") + `, url: "https://a.example/"}`), nil, "alerts.sinks[0].url"},
		{"webhook", snk(hookItem), listEnv, ""},
		{"webhook url http", snk(`{type: webhook, url: "http://a.example/", hmac_secret_env: ALERT_HMAC}`), listEnv, "alerts.sinks[0].url"},
		{"webhook url missing", snk(`{type: webhook, hmac_secret_env: ALERT_HMAC}`), listEnv, "alerts.sinks[0].url"},
		{"webhook url user info", snk(`{type: webhook, url: "https://u:p@a.example/", hmac_secret_env: ALERT_HMAC}`), listEnv, "alerts.sinks[0].url"},
		{"webhook url link-local", snk(`{type: webhook, url: "https://169.254.169.254/", hmac_secret_env: ALERT_HMAC}`), listEnv, "alerts.sinks[0].url"},
		{"webhook url unspecified", snk(`{type: webhook, url: "https://0.0.0.0/", hmac_secret_env: ALERT_HMAC}`), listEnv, "alerts.sinks[0].url"},
		{"webhook url fragment", snk(`{type: webhook, url: "https://a.example/#f", hmac_secret_env: ALERT_HMAC}`), listEnv, "alerts.sinks[0].url"},
		{"webhook hmac missing", snk(`{type: webhook, url: "https://a.example/"}`), nil, "alerts.sinks[0].hmac_secret_env"},
		{"webhook hmac 31 bytes", snk(hookItem), []string{"ALERT_HMAC=" + strings.Repeat("h", 31)}, "alerts.sinks[0].hmac_secret_env"},
		{"webhook hmac 32 bytes", snk(hookItem), []string{"ALERT_HMAC=" + strings.Repeat("h", 32)}, ""},
		{"syslog udp", snk(sysItem), nil, ""},
		{"syslog tcp", snk(sys("tcp://127.0.0.1:514")), nil, ""},
		{"syslog tls", snk(sys("tls://[2606:4700::1111]:6514")), nil, ""},
		{"syslog tls host name", snk(sys("tls://log.example:6514")), nil, ""},
		{"syslog tls loopback", snk(sys("tls://127.0.0.1:6514")), nil, "alerts.sinks[0].addr"},
		{"syslog udp 127.1.2.3", snk(sys("udp://127.1.2.3:514")), nil, ""},
		{"syslog tcp 127.1.2.3", snk(sys("tcp://127.1.2.3:514")), nil, ""},
		{"syslog udp ::1", snk(sys("udp://[::1]:514")), nil, ""},
		{"syslog tcp ::1", snk(sys("tcp://[::1]:514")), nil, ""},
		{"syslog udp host name", snk(sys("udp://log.example:514")), nil, "alerts.sinks[0].addr"},
		{"syslog tcp host name", snk(sys("tcp://log.example:514")), nil, "alerts.sinks[0].addr"},
		{"syslog udp localhost", snk(sys("udp://localhost:514")), nil, "alerts.sinks[0].addr"},
		{"syslog tcp localhost", snk(sys("tcp://localhost:514")), nil, "alerts.sinks[0].addr"},
		{"syslog udp private", snk(sys("udp://10.0.0.5:514")), nil, "alerts.sinks[0].addr"},
		{"syslog tcp private", snk(sys("tcp://10.0.0.5:514")), nil, "alerts.sinks[0].addr"},
		{"syslog udp v4-mapped loopback", snk(sys("udp://[::ffff:127.0.0.1]:514")), nil, "alerts.sinks[0].addr"},
		{"syslog tcp v4-mapped loopback", snk(sys("tcp://[::ffff:127.0.0.1]:514")), nil, "alerts.sinks[0].addr"},
		{"syslog udp global v6", snk(sys("udp://[2001:db8::1]:514")), nil, "alerts.sinks[0].addr"},
		{"syslog tcp global v6", snk(sys("tcp://[2001:db8::1]:514")), nil, "alerts.sinks[0].addr"},
		{"syslog udp bracketed IPv4", snk(sys("udp://[127.0.0.1]:514")), nil, "alerts.sinks[0].addr"},
		{"syslog tls bracketed name", snk(sys("tls://[example.com]:6514")), nil, "alerts.sinks[0].addr"},
		{"syslog udp upper-case scheme", snk(sys("UDP://127.0.0.1:514")), nil, "alerts.sinks[0].addr"},
		{"syslog scheme", snk(`{type: syslog, addr: "http://log.example:514"}`), nil, "alerts.sinks[0].addr"},
		{"syslog no scheme", snk(`{type: syslog, addr: "log.example:514"}`), nil, "alerts.sinks[0].addr"},
		{"syslog no port", snk(`{type: syslog, addr: "udp://log.example"}`), nil, "alerts.sinks[0].addr"},
		{"syslog port 0", snk(`{type: syslog, addr: "udp://log.example:0"}`), nil, "alerts.sinks[0].addr"},
		{"syslog port 65536", snk(`{type: syslog, addr: "udp://log.example:65536"}`), nil, "alerts.sinks[0].addr"},
		{"syslog path", snk(`{type: syslog, addr: "udp://log.example:514/x"}`), nil, "alerts.sinks[0].addr"},
		{"syslog user info", snk(`{type: syslog, addr: "udp://u:p@log.example:514"}`), nil, "alerts.sinks[0].addr"},
		{"syslog empty host", snk(`{type: syslog, addr: "udp://:514"}`), nil, "alerts.sinks[0].addr"},
		{"syslog unspecified", snk(`{type: syslog, addr: "udp://0.0.0.0:514"}`), nil, "alerts.sinks[0].addr"},
		{"syslog link-local", snk(`{type: syslog, addr: "udp://169.254.1.1:514"}`), nil, "alerts.sinks[0].addr"},
		{"syslog addr missing", snk(`{type: syslog}`), nil, "alerts.sinks[0].addr"},
		{"smtp", snk(mailItem), nil, ""},
		{"smtps", snk(smtpHost("smtps://mail.example:465")), nil, ""},
		{"smtp host no scheme", snk(smtpHost("mail.example:587")), nil, "alerts.sinks[0].host"},
		{"smtp host http", snk(smtpHost("http://mail.example:587")), nil, "alerts.sinks[0].host"},
		{"smtp host one slash", snk(smtpHost("smtp:/mail.example:587")), nil, "alerts.sinks[0].host"},
		{"smtp host upper-case scheme", snk(smtpHost("SMTP://mail.example:587")), nil, "alerts.sinks[0].host"},
		{"smtp host smtps upper-case", snk(smtpHost("SMTPS://mail.example:465")), nil, "alerts.sinks[0].host"},
		{"smtp host no port", snk(smtpHost("smtp://mail.example")), nil, "alerts.sinks[0].host"},
		{"smtp host link-local", snk(smtpHost("smtp://169.254.1.1:25")), nil, "alerts.sinks[0].host"},
		{"smtps host link-local", snk(smtpHost("smtps://169.254.1.1:465")), nil, "alerts.sinks[0].host"},
		{"smtp host CRLF", snk(smtpHost(`smtp://mail.example:25\r\nBcc: x`)), nil, "alerts.sinks[0].host"},
		{"smtp host missing", snk(`{type: smtp, from: a@b.example, to: [c@d.example]}`), nil, "alerts.sinks[0].host"},
		{"smtp host unspecified", snk(smtpHost("smtp://0.0.0.0:25")), nil, "alerts.sinks[0].host"},
		{"smtp from two addresses", snk(`{type: smtp, host: "smtp://m.example:25", from: "a@b.example, e@f.example", to: [c@d.example]}`), nil, "alerts.sinks[0].from"},
		{"smtp from CRLF", snk(`{type: smtp, host: "smtp://m.example:25", from: "a@b.example\r\nBcc: x@y.example", to: [c@d.example]}`), nil, "alerts.sinks[0].from"},
		{"smtp from missing", snk(`{type: smtp, host: "smtp://m.example:25", to: [c@d.example]}`), nil, "alerts.sinks[0].from"},
		{"smtp to 1", snk(mail("to: " + to(1))), nil, ""},
		{"smtp to 16", snk(mail("to: " + to(16))), nil, ""},
		{"smtp to 17", snk(mail("to: " + to(17))), nil, "alerts.sinks[0].to"},
		{"smtp to empty", snk(mail("to: []")), nil, "alerts.sinks[0].to"},
		{"smtp to missing", snk(mail("cc: x@y.example")), nil, "alerts.sinks[0].to"},
		{"smtp to scalar", snk(mail("to: c@d.example")), nil, "alerts.sinks[0].to"},
		{"smtp to CRLF", snk(mail(`to: [c@d.example, "e@f.example\nBcc: x@y.example"]`)), nil, "alerts.sinks[0].to[1]"},
		{"smtp to two addresses", snk(mail(`to: ["c@d.example, e@f.example"]`)), nil, "alerts.sinks[0].to[0]"},
		{"smtp to mapping", snk(mail(`to: [{a: 1}]`)), nil, "alerts.sinks[0].to[0]"},
		{"smtp to not string", snk(mail(`to: [5]`)), nil, "alerts.sinks[0].to[0]"},
		{"smtp unknown key", snk(mail("to: [c@d.example], cc: x@y.example")), nil, "alerts.sinks[0].cc"},
		// The rules of the *_env keys (SEC-13).
		{"env lower case", pub(tok("ckpt_token")), nil, "tlog.publish[0].token_env"},
		{"env digit first", pub(tok("1TOKEN")), []string{"1TOKEN=x"}, "tlog.publish[0].token_env"},
		{"env hyphen", pub(tok("CKPT-TOKEN")), []string{"CKPT-TOKEN=x"}, "tlog.publish[0].token_env"},
		{"env PHANTOM_ prefix", pub(tok("PHANTOM_TOKEN")), []string{"PHANTOM_TOKEN=x"}, "tlog.publish[0].token_env"},
		{"env underscore first", pub(tok("_TOKEN")), []string{"_TOKEN=x"}, ""},
		{"env unset", pub(tok("NO_SUCH_VAR")), nil, "tlog.publish[0].token_env"},
		{"env empty", pub(strings.Replace(pubItem, "CKPT_TOKEN", "EMPTY_TOKEN", 1)), []string{"EMPTY_TOKEN="}, "tlog.publish[0].token_env"},
		{"env twice", pub(pubItem), []string{tokenVar + "=" + strings.Repeat("u", 32)}, "tlog.publish[0].token_env"},
		{"env hmac unset", snk(hookItem), nil, "alerts.sinks[0].hmac_secret_env"},
		{"env hmac PHANTOM_ prefix", snk(hmac("PHANTOM_HMAC")), []string{"PHANTOM_HMAC=" + strings.Repeat("h", 32)}, "alerts.sinks[0].hmac_secret_env"},
		{"env hmac not string", snk(hmac("5")), nil, "alerts.sinks[0].hmac_secret_env"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			c, err := loadProd(t, r.file, r.env...)
			switch {
			case r.want == "" && err != nil:
				t.Errorf("got %v", err)
			case r.want != "" && (err == nil || !strings.Contains(err.Error(), "config: "+r.want+" at ")):
				t.Errorf("got %v, want an error that names %s", err, r.want)
			case r.want != "" && c != nil:
				t.Error("an invalid entry returned a config") // The load fails closed.
			}
		})
	}
}

// TestTS11_ListEnvTwice checks the detail text for a variable that has two
// entries in the environment.
func TestTS11_ListEnvTwice(t *testing.T) {
	_, err := loadProd(t, pub(pubItem), tokenVar+"="+strings.Repeat("u", 32))
	if err == nil || !strings.Contains(err.Error(), "config: tlog.publish[0].token_env at ") || !strings.Contains(err.Error(), envMany) {
		t.Errorf("got %v, want an error that names the key and holds the text %q", err, envMany)
	}
}

// envMany is the detail for a variable that has more than one entry in the
// environment.
const envMany = "the environment has more than one entry for the variable that the key names"

// TestTS10_EnvErrorsHideName checks that an error for a *_env key names the key path and never the
// variable name: an operator can paste a secret in place of a name (SEC-13, T-S-10).
func TestTS10_EnvErrorsHideName(t *testing.T) {
	const name = "JBSWY3DPEHPK3PXPZZSECRETQ7"
	tok := pub(`{type: https-put, url: "https://a.example/", token_env: ` + name + "}")
	hook := snk(`{type: webhook, url: "https://a.example/", hmac_secret_env: ` + name + "}")
	rows := []struct {
		label, file, key string
		env              []string
		text             string // text is "" or a part of the error text.
	}{
		{"token unset", tok, "tlog.publish[0].token_env", nil, ""},
		{"token empty", tok, "tlog.publish[0].token_env", []string{name + "="}, ""},
		{"hmac unset", hook, "alerts.sinks[0].hmac_secret_env", nil, ""},
		{"hmac short", hook, "alerts.sinks[0].hmac_secret_env", []string{name + "=short"}, ""},
		{"token twice", tok, "tlog.publish[0].token_env", []string{name + "=" + name, name + "=" + name}, envMany},
		{"name rule", strings.Replace(tok, name, name+"-x", 1), "tlog.publish[0].token_env", nil, ""},
		{"PHANTOM_ prefix", strings.Replace(tok, name, "PHANTOM_"+name, 1), "tlog.publish[0].token_env", nil, ""},
	}
	for _, r := range rows {
		t.Run(r.label, func(t *testing.T) {
			_, err := loadProd(t, r.file, r.env...)
			if err == nil || !strings.Contains(err.Error(), "config: "+r.key+" at ") {
				t.Fatalf("got %v, want an error that names %s", err, r.key)
			}
			if strings.Contains(err.Error(), name) {
				t.Errorf("the error holds the variable name: %v", err)
			}
			if !strings.Contains(err.Error(), r.text) {
				t.Errorf("got %v, want the text %q", err, r.text)
			}
		})
	}
}

// TestTU10_ListKeys checks that every list key of 04 section 3 loads and keeps its value with the source line,
// and that a list key has no PHANTOM_ override.
func TestTU10_ListKeys(t *testing.T) {
	file := acmeTlog + "  publish:\n    - " + pubItem + "\n    - " + strings.Replace(pubItem, "CKPT_TOKEN", "OTHER_TOKEN", 1) +
		"\nalerts:\n  sinks:\n    - " + hookItem + "\n    - " + sysItem + "\n    - " + mailItem + "\n"
	c, err := loadProd(t, file, append([]string{"OTHER_TOKEN=x"}, listEnv...)...)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"tlog.publish[0].type": "https-put", "tlog.publish[0].url": "https://ckpt.example/put", "tlog.publish[0].token_env": "CKPT_TOKEN",
		"tlog.publish[1].token_env": "OTHER_TOKEN",
		"alerts.sinks[0].type":      "webhook", "alerts.sinks[0].url": "https://hook.example/a", "alerts.sinks[0].hmac_secret_env": "ALERT_HMAC",
		"alerts.sinks[1].type": "syslog", "alerts.sinks[1].addr": "udp://127.0.0.1:514",
		"alerts.sinks[2].type": "smtp", "alerts.sinks[2].host": "smtp://mail.example:587", "alerts.sinks[2].from": "a@b.example", "alerts.sinks[2].to[0]": "c@d.example",
	}
	for p, s := range want {
		if v, ok := c.Get(p); !ok || v.Str != s || v.Source != cfg || v.Line == 0 {
			t.Errorf("%s: got %+v, want %q from the file", p, v, s)
		}
	}
	for _, name := range []string{"PHANTOM_TLOG_PUBLISH", "PHANTOM_TLOG_PUBLISH_0_URL", "PHANTOM_ALERTS_SINKS", "PHANTOM_ALERTS_SINKS_0_TYPE", "PHANTOM_ALERTS_SINKS_2_TO"} {
		_, err := loadProd(t, file, append([]string{name + "=x"}, append([]string{"OTHER_TOKEN=x"}, listEnv...)...)...)
		if err == nil || !strings.Contains(err.Error(), name+": unknown PHANTOM variable") {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// TestTS10_ListSecrets (SEC-13) sets every *_env variable to a marker and loads files with the production tables.
// Valid files and files with many list errors must not show the marker, or its length, in an error, in %#v of
// the error, or in the config. The loader shows a pasted name only if it matches the name rule.
func TestTS10_ListSecrets(t *testing.T) {
	const marker = "secret_marker_7f3a_abcde" // 24 bytes
	long := strings.Repeat(marker, 2)
	// loadTest sets CKPT_TOKEN, and a variable must not occur two times.
	// So the marker is in MARKER_TOKEN.
	env := []string{"MARKER_TOKEN=" + marker, "ALERT_HMAC=" + long, "SHORT_HMAC=" + marker}
	pubMarker := strings.Replace(pubItem, "CKPT_TOKEN", "MARKER_TOKEN", 1)
	good := pub(pubMarker) + "alerts:\n  sinks:\n    - " + hookItem + "\n"
	c, err := loadProd(t, good, env...)
	if err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprintf("%#v %v", c, c.AllowList()); strings.Contains(s, marker) {
		t.Errorf("the config shows the marker: %s", s)
	}
	bad := acmeTlog + "  publish:\n    - " + pubMarker + "\n    - " + `{type: https-put, url: "http://a.example/", token_env: ` + marker + "}\n" +
		"alerts:\n  sinks:\n    - " + `{type: webhook, url: "https://a.example/", hmac_secret_env: SHORT_HMAC}` + "\n" +
		"    - " + `{type: webhook, url: "https://a.example/", hmac_secret_env: ` + marker + "}\n" +
		"    - " + `{type: webhook, url: "https://u:` + marker + `@a.example/", hmac_secret_env: ALERT_HMAC, extra: 1}` + "\n"
	_, err = loadProd(t, bad, env...)
	if err == nil {
		t.Fatal("the invalid file loads")
	}
	for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
		s := fmt.Sprintf("%v %#v", e, e)
		if strings.Contains(strings.ToLower(s), marker) || strings.Contains(s, strconv.Itoa(len(marker))) {
			t.Errorf("the error shows the marker or its length: %s", s)
		}
	}
	for _, want := range []string{"tlog.publish[1].token_env", "alerts.sinks[0].hmac_secret_env", "alerts.sinks[1].hmac_secret_env", "alerts.sinks[2].url", "alerts.sinks[2].extra"} {
		if !strings.Contains(err.Error(), "config: "+want+" at ") {
			t.Errorf("the error lacks %s: %v", want, err)
		}
	}
	// The body forms of TestTS10_Secret, below each secret item key of the production lists.
	files := map[string]func(body string) string{
		"token_env": func(body string) string {
			return acmeTlog + "  publish:\n    - type: https-put\n      url: \"https://ckpt.example/put\"\n      token_env: " + body + "\n"
		},
		"hmac_secret_env": func(body string) string {
			return base + "alerts:\n  sinks:\n    - type: webhook\n      url: \"https://hook.example/a\"\n      hmac_secret_env: " + body + "\n"
		},
	}
	upper := strings.ToUpper(marker)
	for name, file := range files {
		for _, body := range []string{
			marker, "!" + marker, "!<" + marker + "> x", "[!" + marker + "]",
			"{" + upper + ": 1}", "\n        " + marker + ":\n          x: !t 1", "[" + marker + ": !t 1]",
			"{" + marker + ": 1, " + marker + ": 2}", "\n        - " + marker + ": !t 1", "[" + marker + "]",
		} {
			_, err := loadProd(t, file(body), env...)
			if err == nil {
				t.Errorf("%s %q: the invalid file loads", name, body)
				continue
			}
			for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
				if s := fmt.Sprintf("%v %#v", e, e); strings.Contains(strings.ToLower(s), marker) {
					t.Errorf("%s %q: the error shows the marker: %s", name, body, s)
				}
			}
		}
	}
	// The loader cuts these paths too. Each file puts the secret key in a different place.
	deep := "{" + marker + ": !t 1}"
	item := `type: https-put, url: "https://ckpt.example/put", `
	hook := `type: webhook, url: "https://hook.example/a", `
	for _, c := range []struct{ name, file, cut string }{
		{"list in list", acmeTlog + "  publish: [[{" + item + "token_env: " + deep + "}]]\n", "tlog.publish[0][0].token_env"},
		{"list as mapping", acmeTlog + "  publish: {token_env: " + deep + "}\n", "tlog.publish.token_env"},
		{"mapping with 0", acmeTlog + `  publish: {"0": {token_env: ` + deep + "}}\n", "tlog.publish.0.token_env"},
		{"token_env in sink", pub(pubItem) + "alerts:\n  sinks:\n    - {" + hook + "token_env: " + deep + "}\n", "alerts.sinks[0].token_env"},
		{"hmac in publish", acmeTlog + "  publish: [{" + item + "token_env: CKPT_TOKEN, hmac_secret_env: " + deep + "}]\n", "tlog.publish[0].hmac_secret_env"},
		{"tlog as list", "acme:\n  email: sec@example.com\ntlog: [{origin: test/origin, publish: [{" + item + "token_env: " + deep + "}]}]\n", "tlog[0].publish[0].token_env"},
		{"alerts as list", pub(pubItem) + "alerts: [{sinks: [{" + hook + "hmac_secret_env: " + deep + "}]}]\n", "alerts[0].sinks[0].hmac_secret_env"},
		{"token_env at a wrong indent", acmeTlog + "  token_env: " + deep + "\n", "tlog.token_env"},
		{"top-level token_env", pub(pubItem) + "token_env: " + deep + "\n", "token_env"},
		{"alerts.hmac_secret_env", pub(pubItem) + "alerts:\n  hmac_secret_env: " + deep + "\n", "alerts.hmac_secret_env"},
	} {
		_, err := loadProd(t, c.file, env...)
		if err == nil {
			t.Errorf("%s: the invalid file loads", c.name)
			continue
		}
		errs := err.(interface{ Unwrap() []error }).Unwrap()
		// A reader error has no Key. readError changes a path below a secret
		// key to the path of that key. The Detail starts with that path.
		if !slices.ContainsFunc(errs, func(e error) bool {
			return strings.HasPrefix(e.(*Error).Detail, c.cut+": ")
		}) {
			t.Errorf("%s: no error names the path %s: %v", c.name, c.cut, err)
		}
		for _, e := range errs {
			if s := fmt.Sprintf("%v %#v", e, e); strings.Contains(strings.ToLower(s), marker) {
				t.Errorf("%s: the error shows the marker: %s", c.name, s)
			}
		}
	}
}

// TestTS11_URLKeys checks that each URL in configtest.BadURLs fails for each
// URL key. The error names the key. The error text holds neither "example" nor
// "169.254" (T-S-11).
func TestTS11_URLKeys(t *testing.T) {
	for _, bad := range configtest.BadURLs {
		u := bad.URL
		for _, r := range []struct{ key, file string }{
			{"acme.ca", "acme:\n  email: sec@example.com\n  ca: \"" + u + "\"\n" + acmeNames + tlogLine},
			{"bundle.fetch_url", base + "bundle:\n  fetch_url: \"" + u + "\"\n"},
			{"tlog.publish[0].url", pub(`{type: https-put, url: "` + u + `", token_env: CKPT_TOKEN}`)},
			{"alerts.sinks[0].url", snk(`{type: webhook, url: "` + u + `", hmac_secret_env: ALERT_HMAC}`)},
		} {
			_, err := loadProd(t, r.file, listEnv...)
			if err == nil || !strings.Contains(err.Error(), "config: "+r.key+" at ") {
				t.Errorf("%s %s: got %v", r.key, u, err)
			} else if s := err.Error(); strings.Contains(s, "example") || strings.Contains(s, "169.254") {
				t.Errorf("%s %s: the error shows the URL: %v", r.key, u, err)
			}
		}
	}
}

// egressKeyFiles returns one file for each key that holds an endpoint.
// The key has host. The first field is the key. A syslog address uses tls.
func egressKeyFiles(host string) [][2]string {
	sys := func(addr string) string { return `{type: syslog, addr: "` + addr + `"}` }
	smtpHost := func(h string) string { return `{type: smtp, host: "` + h + `", from: a@b.example, to: [c@d.example]}` }
	return [][2]string{
		{"acme.ca", "acme:\n  email: sec@example.com\n  ca: \"https://" + host + "/d\"\n" + acmeNames + tlogLine},
		{"bundle.fetch_url", base + "bundle:\n  fetch_url: \"https://" + host + "/b\"\n"},
		{"tlog.publish[0].url", pub(`{type: https-put, url: "https://` + host + `/p", token_env: CKPT_TOKEN}`)},
		{"alerts.sinks[0].url", snk(`{type: webhook, url: "https://` + host + `/h", hmac_secret_env: ALERT_HMAC}`)},
		{"alerts.sinks[0].addr", snk(sys("tls://" + host + ":6514"))},
		{"alerts.sinks[0].host", snk(smtpHost("smtp://" + host + ":25"))},
		{"alerts.sinks[0].host", snk(smtpHost("smtps://" + host + ":465"))},
	}
}

// TestTS11_EgressLiterals checks that each literal in
// configtest.EgressLiterals fails for each endpoint key, and that each literal
// in configtest.GlobalLiterals passes. The error names the key and gives the
// fixed rule (T-S-11).
func TestTS11_EgressLiterals(t *testing.T) {
	for _, lit := range configtest.EgressLiterals {
		for _, r := range egressKeyFiles(lit) {
			_, err := loadProd(t, r[1], listEnv...)
			if err == nil || !strings.Contains(err.Error(), "config: "+r[0]+" at ") || !strings.Contains(err.Error(), "egress rule") {
				t.Errorf("%s %s: got %v", r[0], lit, err)
			}
		}
	}
	for _, lit := range configtest.GlobalLiterals {
		for _, r := range egressKeyFiles(lit) {
			if _, err := loadProd(t, r[1], listEnv...); err != nil {
				t.Errorf("%s %s: got %v", r[0], lit, err)
			}
		}
	}
	for _, addr := range []string{"udp://127.0.0.1:514", "tcp://127.0.0.1:514", "udp://[::1]:514", "tcp://[::1]:514"} {
		if _, err := loadProd(t, snk(`{type: syslog, addr: "`+addr+`"}`), listEnv...); err != nil {
			t.Errorf("%s: got %v", addr, err)
		}
	}
}

// withList adds a private list to a flow mapping item.
func withList(item, list string) string {
	return strings.TrimSuffix(item, "}") + ", private: [" + list + "]}"
}

// litKind is one endpoint kind. file returns a config whose endpoint host is
// host. The list is on the item of the endpoint if own is true, else on
// another item. scheme and port are those of the AllowList endpoint.
type litKind struct {
	key, scheme, port string
	file              func(host, list string, own bool) string
}

// litKinds returns the six endpoint kinds, with smtps as a seventh row.
func litKinds() []litKind {
	sinks := func(lit func(h string) string, other string) func(string, string, bool) string {
		return func(h, l string, own bool) string {
			a, b := lit(h), other
			if own {
				a = withList(a, l)
			} else {
				b = withList(b, l)
			}
			return snk(a, b)
		}
	}
	smtp := func(scheme, port string) func(string, string, bool) string {
		return sinks(func(h string) string {
			return `{type: smtp, host: "` + scheme + `://` + h + `:` + port + `", from: a@b.example, to: [c@d.example]}`
		}, hookItem)
	}
	return []litKind{
		{"acme.ca", "https", "443", func(h, l string, own bool) string {
			ca, bundle := "", ""
			if own {
				ca = "  ca_private: [" + l + "]\n"
			} else {
				bundle = "bundle:\n  fetch_url: \"https://b.example/x\"\n  fetch_private: [" + l + "]\n"
			}
			return "acme:\n  email: sec@example.com\n  ca: \"https://" + h + "/d\"\n" + ca + acmeNames + tlogLine + bundle
		}},
		{"bundle.fetch_url", "https", "443", func(h, l string, own bool) string {
			if own {
				return base + "bundle:\n  fetch_url: \"https://" + h + "/b\"\n  fetch_private: [" + l + "]\n"
			}
			return base + "bundle:\n  fetch_url: \"https://" + h + "/b\"\n" + "alerts:\n  sinks:\n    - " + withList(hookItem, l) + "\n"
		}},
		{"tlog.publish[1].url", "https", "443", func(h, l string, own bool) string {
			lit := `{type: https-put, url: "https://` + h + `/p", token_env: CKPT_TOKEN}`
			if own {
				return pub(pubItem, withList(lit, l))
			}
			return pub(withList(pubItem, l), lit)
		}},
		{"alerts.sinks[0].url", "https", "443", sinks(func(h string) string {
			return `{type: webhook, url: "https://` + h + `/h", hmac_secret_env: ALERT_HMAC}`
		}, mailItem)},
		{"alerts.sinks[0].addr", "tls", "6514", sinks(func(h string) string {
			return `{type: syslog, addr: "tls://` + h + `:6514"}`
		}, hookItem)},
		{"alerts.sinks[0].host", "smtp", "25", smtp("smtp", "25")},
		{"alerts.sinks[0].host", "smtps", "465", smtp("smtps", "465")},
	}
}

// TestTS26_LiteralHostList checks an IP-literal endpoint host that the egress
// rule refuses. It passes only if the list of its own item holds it. The
// never-list must not hold it. The error names the key one time and shows no
// part of the host (T-S-26, T-S-11).
func TestTS26_LiteralHostList(t *testing.T) {
	rows := []struct {
		name, host, list string
		passes           bool
	}{
		{"v4 in list", "10.1.2.3", "10.0.0.0/8", true},
		{"v6 in list", "[fd00::1]", "fd00::/8", true},
		{"mapped in list", "[::ffff:10.1.2.3]", "10.0.0.0/8", true},
		{"in a private class, not in list", "10.1.2.3", "192.168.0.0/16", false},
		{"cloud metadata v4, class list", "100.100.100.200", "100.64.0.0/10", false},
		{"cloud metadata v6, class list", "[fd00:ec2::254]", "fd00::/8", false},
		{"cloud metadata v4, entry for it", "100.100.100.200", "100.100.100.200", false},
		{"benchmark range", "198.18.0.1", "10.0.0.0/8", false},
		{"link-local", "169.254.169.254", "10.0.0.0/8", false},
		{"loopback", "127.0.0.1", "10.0.0.0/8", false},
	}
	for _, k := range litKinds() {
		for _, r := range rows {
			t.Run(k.key+"/"+k.scheme+"/"+r.name, func(t *testing.T) {
				_, err := loadProd(t, k.file(r.host, r.list, true), listEnv...)
				if r.passes {
					if err != nil {
						t.Errorf("own list: got %v", err)
					}
					// The same list on another item does not help.
					_, err = loadProd(t, k.file(r.host, r.list, false), listEnv...)
				}
				wantKey(t, err, k.key, r.host)
			})
		}
	}
}

// wantKey checks that err is one error for key, with no part of host.
func wantKey(t *testing.T, err error, key, host string) {
	t.Helper()
	if err == nil || strings.Count(err.Error(), "config: "+key+" at ") != 1 {
		t.Errorf("want one error for %s, got %v", key, err)
		return
	}
	if strings.Contains(err.Error(), strings.Trim(host, "[]")) {
		t.Errorf("the error shows the host: %v", err)
	}
}

// TestTS26_LiteralHostListAllowList checks that a literal that passes by its
// list is in AllowList, in canonical form (C4, T-S-26).
func TestTS26_LiteralHostListAllowList(t *testing.T) {
	for _, k := range litKinds() {
		for _, r := range []struct{ host, list, want string }{
			{"10.1.2.3", "10.0.0.0/8", "10.1.2.3"},
			{"[fd00::1]", "fd00::/8", "fd00::1"},
			{"[::ffff:10.1.2.3]", "10.0.0.0/8", "10.1.2.3"},
		} {
			t.Run(k.key+"/"+k.scheme+"/"+r.want, func(t *testing.T) {
				c, err := loadProd(t, k.file(r.host, r.list, true), listEnv...)
				if err != nil {
					t.Fatal(err)
				}
				if want := (Endpoint{k.scheme, r.want, k.port}); !slices.Contains(c.AllowList(), want) {
					t.Errorf("AllowList %+v lacks %+v", c.AllowList(), want)
				}
			})
		}
	}
}

// TestTS11_SystemNetRefusesLoopback checks that the Dialer of SystemNet
// refuses a dial to a loopback address (T-S-21).
func TestTS11_SystemNetRefusesLoopback(t *testing.T) {
	_, err := SystemNet().Dialer.DialContext(context.Background(), "tcp", "127.0.0.1:9")
	if !errors.Is(err, egress.ErrRefused) {
		t.Errorf("got %v, want egress.ErrRefused", err)
	}
}

// TestTS11_SinkEndpoints checks that each sink type of the alerts.sinks schema
// gives its endpoint in AllowList. A type with no fixture or no endpoint
// fails (C4, T-S-11).
func TestTS11_SinkEndpoints(t *testing.T) {
	fixtures := map[string]struct {
		item string
		want Endpoint
	}{
		"webhook": {hookItem, Endpoint{"https", "hook.example", "443"}},
		"syslog":  {sysItem, Endpoint{"udp", "127.0.0.1", "514"}},
		"smtp":    {mailItem, Endpoint{"smtp", "mail.example", "587"}},
	}
	for typ := range sinkSchemas {
		t.Run(typ, func(t *testing.T) {
			f, ok := fixtures[typ]
			if !ok {
				t.Fatalf("the sink type %s has no fixture", typ)
			}
			c, err := loadProd(t, snk(f.item), listEnv...)
			if err != nil {
				t.Fatal(err)
			}
			want := []Endpoint{{"https", "acme-v02.api.letsencrypt.org", "443"}, ckptEndpoint, f.want}
			if got := c.AllowList(); !reflect.DeepEqual(got, want) {
				t.Errorf("got %+v, want %+v", got, want)
			}
		})
	}
}

// TestTS11_SinkUnknownType checks that an unknown sink type adds nothing.
// It checks that the endpoints of the sinks after it stay (C4, T-S-11).
func TestTS11_SinkUnknownType(t *testing.T) {
	c := &Config{values: map[string]Value{
		"alerts.sinks[0].type": {Str: "pager"},
		"alerts.sinks[1].type": {Str: "syslog"},
		"alerts.sinks[1].addr": {Str: "udp://127.0.0.1:514"},
	}}
	if got, want := c.AllowList(), []Endpoint{{"udp", "127.0.0.1", "514"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// TestTS08_AllowList checks that AllowList holds the endpoints of acme.ca, bundle.fetch_url, tlog.publish[].url,
// and the sinks, and that an endpoint that many keys share is in the list one time (C4, T-S-08, T-S-11).
func TestTS08_AllowList(t *testing.T) {
	file := "acme:\n  email: sec@example.com\n  ca: https://ca.example:14000/dir\n" + acmeNames + "bundle:\n  fetch_url: https://CA.EXAMPLE:14000/b\n" +
		"tlog:\n  origin: test/origin\n  publish:\n    - " + pubItem + "\n    - " + `{type: https-put, url: "https://CA.example:14000/ckpt", token_env: CKPT_TOKEN}` + "\n" +
		"alerts:\n  sinks:\n" +
		"    - " + `{type: webhook, url: "https://ckpt.example:443/hook", hmac_secret_env: ALERT_HMAC}` + "\n" +
		"    - " + sysItem + "\n" +
		"    - " + `{type: syslog, addr: "tcp://[::1]:514"}` + "\n" +
		"    - " + `{type: syslog, addr: "tls://[2606:4700::AAAA]:6514"}` + "\n" +
		"    - " + mailItem + "\n" +
		"    - " + `{type: smtp, host: "smtp://MAIL.example:587", from: a@b.example, to: [c@d.example]}` + "\n" +
		"    - " + `{type: smtp, host: "smtps://mail.example:465", from: a@b.example, to: [c@d.example]}` + "\n" +
		"    - " + hookItem + "\n"
	c, err := loadProd(t, file, listEnv...)
	if err != nil {
		t.Fatal(err)
	}
	want := []Endpoint{
		{"https", "ca.example", "14000"}, {"https", "ckpt.example", "443"},
		{"udp", "127.0.0.1", "514"}, {"tcp", "::1", "514"}, {"tls", "2606:4700::aaaa", "6514"},
		// A loopback sink is in the list (04 section 3).
		{"smtp", "mail.example", "587"}, {"smtps", "mail.example", "465"}, {"https", "hook.example", "443"},
	}
	if got := c.AllowList(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

// namesFile returns base with the acme.names list set to the entries.
func namesFile(names ...string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = strconv.Quote(n)
	}
	return strings.Replace(base, acmeNames, "  names: ["+strings.Join(q, ", ")+"]\n", 1)
}

// TestTS11_ACMENames checks the acme.names rule: the count, each entry, the duplicates, and the missing
// override (SEC-21, T-S-11, T-U-10). Each bad value gives an error that names acme.names. The override
// row checks that a PHANTOM_ variable for a list key is an unknown-variable error (T-U-10).
func TestTS11_ACMENames(t *testing.T) {
	l63 := strings.Repeat("a", 63)
	name253 := strings.Join([]string{l63, l63, l63, strings.Repeat("a", 61)}, ".")
	var many []string
	for i := range 17 {
		many = append(many, fmt.Sprintf("h%d.host.zz", i))
	}
	const key = "acme.names"
	rows := []struct {
		name, file, env, want string // want is "" for a file that loads.
	}{
		{"1 name", namesFile("decoy.host.zz"), "", ""},
		{"16 names", namesFile(many[:16]...), "", ""},
		{"label of 63 bytes", namesFile(l63 + ".zz"), "", ""},
		{"name of 253 bytes", namesFile(name253), "", ""},
		{"digits and hyphen", namesFile("a-1.b2-c.zz"), "", ""},
		{"0 names", namesFile(), "", key},
		{"17 names", namesFile(many...), "", key},
		{"upper-case letter", namesFile("Decoy.host.zz"), "", key},
		{"wildcard", namesFile("*.host.zz"), "", key},
		{"IPv4 literal", namesFile("192.0.2.1"), "", key},
		{"IPv6 literal", namesFile("2001:db8::1"), "", key},
		{"trailing dot", namesFile("decoy.host.zz."), "", key},
		{"empty label", namesFile("decoy..host.zz"), "", key},
		{"one label", namesFile("decoy"), "", key},
		{"label of 64 bytes", namesFile(l63 + "a.zz"), "", key},
		{"name of 254 bytes", namesFile(name253 + "a"), "", key},
		{"leading hyphen", namesFile("-decoy.host.zz"), "", key},
		{"trailing hyphen", namesFile("decoy-.host.zz"), "", key},
		{"underscore", namesFile("de_coy.host.zz"), "", key},
		{"non-ASCII", namesFile("dé.host.zz"), "", key},
		// The names local and internal have one label.
		// The rule for two labels refuses them.
		{"local", namesFile("local"), "", key},
		{"internal", namesFile("internal"), "", key},
		{"duplicate", namesFile("a.host.zz", "b.host.zz", "a.host.zz"), "", key},
		{"not a scalar", strings.Replace(base, "[decoy.host.zz]", "[[a]]", 1), "", "acme.names[0]"},
		{"not a string", strings.Replace(base, "[decoy.host.zz]", "[12]", 1), "", "acme.names[0]"},
		{"not a list", strings.Replace(base, "[decoy.host.zz]", "decoy.host.zz", 1), "", key},
		{"missing", strings.Replace(base, acmeNames, "", 1), "", key},
		{"override", base, "PHANTOM_ACME_NAMES=decoy.host.zz", "PHANTOM_ACME_NAMES: unknown PHANTOM variable"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var env []string
			if r.env != "" {
				env = append(env, r.env)
			}
			c, err := loadProd(t, r.file, env...)
			switch {
			case r.want == "" && err != nil:
				t.Errorf("got %v", err)
			case r.want != "" && (err == nil || !strings.Contains(err.Error(), r.want)):
				t.Errorf("got %v, want an error with %q", err, r.want)
			case r.want != "" && c != nil:
				t.Error("a config came back with the error")
			}
		})
	}
}

// TestTS11_ACMENamesTripleDuplicate checks a name that is in the list 3 times.
// It gives one duplicate error line, not one for each extra copy
// (SEC-21, T-S-11).
func TestTS11_ACMENamesTripleDuplicate(t *testing.T) {
	_, err := loadProd(t, namesFile("a.host.zz", "a.host.zz", "a.host.zz"))
	if err == nil {
		t.Fatal("got no error")
	}
	if n := strings.Count(err.Error(), "the list must not hold an entry two times"); n != 1 {
		t.Errorf("got %d duplicate errors, want 1: %v", n, err)
	}
}

// certItem returns one tls.certs entry for name, with valid paths.
func certItem(name string) string {
	return "{name: " + strconv.Quote(name) + ", cert_file: /etc/phantom/a.pem, key_file: /etc/phantom/a.key}"
}

// certsFile returns a config with the tls.certs entries. The head is the
// text of the acme section ("" for none). The tlog section is the one of
// base.
func certsFile(head string, entries ...string) string {
	return head + "tls:\n  certs: [" + strings.Join(entries, ", ") + "]\n" + tlogLine
}

// loadWants loads file. If want is "", the file must load. Else the load
// must fail with an error that holds want, and no config comes back.
func loadWants(t *testing.T, file, want string, env ...string) *Config {
	t.Helper()
	c, err := loadProd(t, file, env...)
	switch {
	case want == "" && err != nil:
		t.Errorf("got %v", err)
	case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
		t.Errorf("got %v, want an error with %q", err, want)
	case want != "" && c != nil:
		t.Error("a config came back with the error")
	}
	return c
}

// TestTS11_SpecialUseNames checks the name rule in acme.names and
// tls.certs (SEC-21, SEC-31, T-S-11). Both lists refuse each name of the
// special-use list and each name below one. They also refuse a name with
// a number as last label. The list is a copy of the spec, so a change of
// one entry in the code fails here.
func TestTS11_SpecialUseNames(t *testing.T) {
	zones := []string{
		"alt", "example", "example.com", "example.net", "example.org", "invalid", "local", "localhost", "onion", "test",
		"home.arpa", "6tisch.arpa", "eap.arpa", "eap-noob.arpa", "ipv4only.arpa", "resolver.arpa", "service.arpa",
		"10.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa", "170.0.0.192.in-addr.arpa", "171.0.0.192.in-addr.arpa",
		"8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa", "b.e.f.ip6.arpa",
	}
	for i := 16; i <= 31; i++ {
		zones = append(zones, strconv.Itoa(i)+".172.in-addr.arpa")
	}
	refused := []string{"127.1", "0x7f.1", "a.123", "a.0x7f", "a.0x0", "a.0x10", "a.0x", "x.1.10.in-addr.arpa", "1.10.in-addr.arpa"}
	for _, z := range zones {
		refused = append(refused, "x."+z, "x.y."+z)
		if strings.Contains(z, ".") {
			refused = append(refused, z)
		}
	}
	passed := []string{"15.172.in-addr.arpa", "32.172.in-addr.arpa", "a.123a", "x.host.zz", "examplee.com", "xexample.com", "x.test.zz", "arpa.zz"}
	for _, list := range []struct{ name, key string }{{"acme.names", "acme.names[0]"}, {"tls.certs", "tls.certs[0].name"}} {
		file := func(name string) string {
			if list.name == "acme.names" {
				return namesFile(name)
			}
			return certsFile("", certItem(name))
		}
		t.Run(list.name, func(t *testing.T) {
			for _, n := range refused {
				t.Run("refused "+n, func(t *testing.T) { loadWants(t, file(n), list.key+" at") })
			}
			for _, n := range passed {
				t.Run("passes "+n, func(t *testing.T) { loadWants(t, file(n), "") })
			}
		})
	}
}

// TestTS11_InternalNames checks the rule for an internal name. It is
// always allowed in tls.certs, and in acme.names only when acme.ca is an
// https URL (SEC-31, T-S-11, T-S-27). When PHANTOM_ACME_CA is set, its
// value decides which CA is in use, not the file.
func TestTS11_InternalNames(t *testing.T) {
	https := "acme:\n  ca: \"https://ca.host.zz/dir\"\n"
	httpsEmail := https + "  email: sec@example.com\n"
	names := func(head string) string { return head + "  names: [x.internal]\n" + tlogLine }
	rows := []struct {
		name, file, want string
		env              []string
	}{
		{"tls.certs, default CA", certsFile("", certItem("x.internal")), "", nil},
		{"tls.certs, letsencrypt-staging", certsFile("acme:\n  ca: letsencrypt-staging\n", certItem("x.internal")), "", nil},
		{"tls.certs, https CA", certsFile(https, certItem("x.internal")), "", nil},
		{"tls.certs, below internal", certsFile("", certItem("a.b.internal")), "", nil},
		{"acme.names, https CA", names(httpsEmail), "", nil},
		{"acme.names, default CA", names("acme:\n  email: sec@example.com\n"), "acme.names[0] at", nil},
		{"acme.names, letsencrypt", names("acme:\n  email: sec@example.com\n  ca: letsencrypt\n"), "acme.names[0] at", nil},
		{"acme.names, letsencrypt-staging", names("acme:\n  email: sec@example.com\n  ca: letsencrypt-staging\n"), "acme.names[0] at", nil},
		{"acme.names, other name with letsencrypt", namesFile("x.host.zz"), "", nil},
		{"acme.names, second entry, default CA", namesFile("a.host.zz", "x.internal"), "acme.names[1] at", nil},
		{"acme.names, https file CA, letsencrypt in the environment", names(httpsEmail), "acme.names[0] at", []string{"PHANTOM_ACME_CA=letsencrypt"}},
		{"acme.names, default file CA, https in the environment", names("acme:\n  email: sec@example.com\n"), "", []string{"PHANTOM_ACME_CA=https://ca.host.zz/dir"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) { loadWants(t, r.file, r.want, r.env...) })
	}
}

// TestTS11_DecoyNameCount checks the count and the compare of names
// (SEC-31, T-S-11, T-S-27). There are 1 to 16 names over both lists. A
// name is in one list only, and tls.certs has no repeat.
func TestTS11_DecoyNameCount(t *testing.T) {
	head := "acme:\n  email: sec@example.com\n"
	list := func(prefix string, from, to int) []string {
		var l []string
		for i := from; i < to; i++ {
			l = append(l, fmt.Sprintf("%s%d.host.zz", prefix, i))
		}
		return l
	}
	both := func(nNames, nCerts int) string {
		var items []string
		for _, n := range list("c", 0, nCerts) {
			items = append(items, certItem(n))
		}
		q := make([]string, 0, nNames)
		for _, n := range list("n", 0, nNames) {
			q = append(q, strconv.Quote(n))
		}
		file := head
		if nNames > 0 {
			file += "  names: [" + strings.Join(q, ", ") + "]\n"
		}
		return certsFile(file, items...)
	}
	rows := []struct{ name, file, want string }{
		{"0 names", certsFile(""), "acme.names at"},
		{"1 certificate", both(0, 1), ""},
		{"16 certificates", both(0, 16), ""},
		{"16 over both lists", both(8, 8), ""},
		{"16 names and 0 certificates", both(16, 0), ""},
		{"17 over both lists", both(9, 8), "acme.names at"},
		{"17 over both lists, 16 names", both(16, 1), "acme.names at"},
		{"17 certificates", both(0, 17), "tls.certs at"},
		{"a name in both lists", certsFile(head+"  names: [a.host.zz]\n", certItem("a.host.zz")), "tls.certs[0].name at"},
		{"the second certificate is in names", certsFile(head+"  names: [a.host.zz]\n", certItem("b.host.zz"), certItem("a.host.zz")), "tls.certs[1].name at"},
		{"the certificate is the second name", certsFile(head+"  names: [a.host.zz, b.host.zz]\n", certItem("b.host.zz")), "tls.certs[0].name at"},
		{"a name two times in tls.certs", certsFile("", certItem("a.host.zz"), certItem("b.host.zz"), certItem("a.host.zz")), "tls.certs[2].name at"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) { loadWants(t, r.file, r.want) })
	}
	// A list with a shape error gets its own error and no total error.
	const total = "need 1 to 16 names in total"
	shape := []struct{ name, file, key string }{
		{"17 names", both(17, 0), "acme.names at"},
		{"17 certificates", both(0, 17), "tls.certs at"},
		{"names not a list", strings.Replace(base, "[decoy.host.zz]", "x", 1), "acme.names at"},
		{"certificates not a list", "tls:\n  certs: x\n" + tlogLine, "tls.certs at"},
		{"names a mapping", strings.Replace(base, "[decoy.host.zz]", "{a: b}", 1), "acme.names at"},
		{"certificates a mapping", "tls:\n  certs: {a: b}\n" + tlogLine, "tls.certs at"},
	}
	for _, r := range shape {
		t.Run("no total error, "+r.name, func(t *testing.T) {
			_, err := loadProd(t, r.file)
			if err == nil || !strings.Contains(err.Error(), r.key) {
				t.Fatalf("got %v, want an error with %q", err, r.key)
			}
			if strings.Contains(err.Error(), total) {
				t.Errorf("got a total error: %v", err)
			}
		})
	}
	c := loadWants(t, both(0, 1), "")
	if v, ok := c.Get("tls.certs[0].cert_file"); !ok || v.Str != "/etc/phantom/a.pem" {
		t.Errorf("got %+v, %v", v, ok)
	}
}

// TestTS11_DecoyErrors checks the full text of a compare error, with its
// file line (T-S-11). It also checks that a name that fails its own check
// gets no repeat error.
func TestTS11_DecoyErrors(t *testing.T) {
	t.Run("full text with the line", func(t *testing.T) {
		file := certsFile("acme:\n  email: sec@example.com\n  names: [a.host.zz]\n", certItem("a.host.zz"))
		_, err := loadProd(t, file)
		want := "config: tls.certs[0].name at " + cfg + ":5: the name must not be in acme.names too"
		if err == nil || err.Error() != want {
			t.Errorf("got %v, want %q", err, want)
		}
	})
	t.Run("a failed name two times", func(t *testing.T) {
		_, err := loadProd(t, certsFile("", certItem("Bad.host.zz"), certItem("Bad.host.zz")))
		if err == nil {
			t.Fatal("got no error")
		}
		for _, k := range []string{"tls.certs[0].name at", "tls.certs[1].name at"} {
			if !strings.Contains(err.Error(), k) {
				t.Errorf("got %v, want an error with %q", err, k)
			}
		}
		if strings.Contains(err.Error(), "two times") {
			t.Errorf("got a repeat error: %v", err)
		}
	})
}

// TestTS11_ACMEEmail checks that acme.email is required only with
// acme.names (T-S-11, T-S-27).
func TestTS11_ACMEEmail(t *testing.T) {
	rows := []struct{ name, file, want string }{
		{"tls.certs only, no email", certsFile("", certItem("a.host.zz")), ""},
		{"names, no email", strings.Replace(base, "  email: sec@example.com\n", "", 1), "acme.email at"},
		{"names, bad email, no required error", strings.Replace(base, "sec@example.com", "a b", 1), "acme.email at"},
		{"certificates and names, no email", certsFile("acme:\n  names: [n.host.zz]\n", certItem("a.host.zz")), "acme.email at"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := loadProd(t, r.file)
			switch {
			case r.want == "" && err != nil:
				t.Errorf("got %v", err)
			case r.want != "" && (err == nil || !strings.Contains(err.Error(), r.want)):
				t.Errorf("got %v, want an error with %q", err, r.want)
			}
			if err != nil && r.name == "names, bad email, no required error" && strings.Contains(err.Error(), "the key is required") {
				t.Errorf("a bad acme.email also gives a required error: %v", err)
			}
		})
	}
	t.Run("email from the environment", func(t *testing.T) {
		loadWants(t, strings.Replace(base, "  email: sec@example.com\n", "", 1), "", "PHANTOM_ACME_EMAIL=sec@example.com")
	})
}

// TestTS11_TLSCertsShape checks the shape of tls.certs. It is a list of
// mappings with name, cert_file and key_file. There is no type key and
// no override, and the paths are absolute and clean. Each error names
// its key (SEC-31, T-S-11, T-S-27).
func TestTS11_TLSCertsShape(t *testing.T) {
	ok := certItem("a.host.zz")
	with := func(v string) string { return base + "tls:\n  certs: " + v + "\n" }
	rows := []struct{ name, file, env, want string }{
		{"valid", with("[" + ok + "]"), "", ""},
		{"empty list with names", with("[]"), "", ""},
		{"not a list", with("x"), "", "tls.certs at"},
		{"section is not a mapping", base + "tls: [x]\n", "", "tls at"},
		{"entry is not a mapping", with("[x]"), "", "tls.certs[0] at"},
		{"entry is a list", with("[[a]]"), "", "tls.certs[0] at"},
		{"no name", with("[{cert_file: /a.pem, key_file: /a.key}]"), "", "tls.certs[0].name at"},
		{"no cert_file", with(`[{name: a.host.zz, key_file: /a.key}]`), "", "tls.certs[0].cert_file at"},
		{"no key_file", with(`[{name: a.host.zz, cert_file: /a.pem}]`), "", "tls.certs[0].key_file at"},
		{"unknown key", with(`[{name: a.host.zz, cert_file: /a.pem, key_file: /a.key, extra: 1}]`), "", "tls.certs[0].extra at"},
		{"type key", with(`[{type: static, name: a.host.zz, cert_file: /a.pem, key_file: /a.key}]`), "", "tls.certs[0].type at"},
		{"relative cert_file", with(`[{name: a.host.zz, cert_file: a.pem, key_file: /a.key}]`), "", "tls.certs[0].cert_file at"},
		{"relative key_file", with(`[{name: a.host.zz, cert_file: /a.pem, key_file: a.key}]`), "", "tls.certs[0].key_file at"},
		{"unclean cert_file", with(`[{name: a.host.zz, cert_file: /x/../a.pem, key_file: /a.key}]`), "", "tls.certs[0].cert_file at"},
		{"name is a list", with(`[{name: [a], cert_file: /a.pem, key_file: /a.key}]`), "", "tls.certs[0].name at"},
		{"second entry bad", with("[" + ok + ", " + certItem("Bad.host.zz") + "]"), "", "tls.certs[1].name at"},
		{"override", base, "PHANTOM_TLS_CERTS=x", "PHANTOM_TLS_CERTS: unknown PHANTOM variable"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var env []string
			if r.env != "" {
				env = append(env, r.env)
			}
			loadWants(t, r.file, r.want, env...)
		})
	}
}

// TestTS11_ACMECacheDir checks the acme.cache_dir rule on the path text (SEC-21, T-S-11). Each bad
// value gives an error that names acme.cache_dir.
func TestTS11_ACMECacheDir(t *testing.T) {
	const s = "/var/lib/phantom/"
	rows := []struct {
		name, dir string
		with      []string
		want      string // want is "" for a value that loads.
	}{
		{"default", "", nil, ""},
		{"sibling", s + "certs2", nil, ""},
		{"all permitted characters", s + "Ab_1.x-y/Z", nil, ""},
		{"name that starts like tlog", s + "tlog2", nil, ""},
		{"state directory", "/var/lib/phantom", nil, "below the state directory"},
		{"space", s + "my certs", nil, "each path part"},
		{"question mark", s + "certs?x", nil, "each path part"},
		{"non-ASCII letter", s + "cér", nil, "each path part"},
		{"dot dot", s + "a/../certs", nil, "clean"},
		{"outside the state directory", "/var/lib/other", nil, "state directory"},
		{"tlog.dir", s + "tlog", nil, "in or above tlog.dir"},
		{"in tlog.dir", s + "tlog/c", nil, "in or above tlog.dir"},
		{"above tlog.dir", s + "a", []string{"PHANTOM_TLOG_DIR=" + s + "a/t"}, "in or above tlog.dir"},
		{"bundle directory", s + "bundle", nil, "directory of bundle.path"},
		{"in the bundle directory", s + "bundle/c", nil, "directory of bundle.path"},
		{"above the bundle directory", s + "b", []string{"PHANTOM_BUNDLE_PATH=" + s + "b/x/current.cbnd"}, "directory of bundle.path"},
		{"keys", s + "keys", nil, "keys directory"},
		{"in keys", s + "keys/c", nil, "keys directory"},
		{"checkpoints", s + "checkpoints", nil, "checkpoints directory"},
		{"in checkpoints", s + "checkpoints/c", nil, "checkpoints directory"},
		{"checkpoint.state", s + "checkpoint.state", nil, "must not be or be in checkpoint.state"},
		{"checkpoint.state.tmp", s + "checkpoint.state.tmp", nil, "must not be or be in checkpoint.state.tmp"},
		{"in checkpoint.state.tmp", s + "checkpoint.state.tmp/c", nil, "must not be or be in checkpoint.state.tmp"},
		{"writer.stop in other case", s + "WRITER.STOP", nil, "must not be or be in writer.stop"},
		{"name that starts like writer.stop", s + "writer.stop2", nil, ""},
		{"tlog.dir in other case", s + "TLOG", nil, "in or above tlog.dir"},
		{"in tlog.dir in other case", s + "Tlog/c", nil, "in or above tlog.dir"},
		{"above tlog.dir in other case", s + "A", []string{"PHANTOM_TLOG_DIR=" + s + "a/t"}, "in or above tlog.dir"},
		{"bundle directory in other case", s + "BUNDLE", nil, "directory of bundle.path"},
		{"in the bundle directory in other case", s + "Bundle/c", nil, "directory of bundle.path"},
		{"above the bundle directory in other case", s + "B", []string{"PHANTOM_BUNDLE_PATH=" + s + "b/x/current.cbnd"}, "directory of bundle.path"},
		{"keys in other case", s + "Keys", nil, "keys directory"},
		{"in keys in other case", s + "KEYS/c", nil, "keys directory"},
		{"checkpoints in other case", s + "CHECKPOINTS", nil, "checkpoints directory"},
		{"in checkpoints in other case", s + "Checkpoints/c", nil, "checkpoints directory"},
		{"in tlog.dir set in other case", s + "logs/c", []string{"PHANTOM_TLOG_DIR=" + s + "LOGS"}, "in or above tlog.dir"},
		{"above tlog.dir set in other case", s + "a", []string{"PHANTOM_TLOG_DIR=" + s + "A/t"}, "in or above tlog.dir"},
		{"above the bundle directory set in other case", s + "b", []string{"PHANTOM_BUNDLE_PATH=" + s + "B/x/current.cbnd"}, "directory of bundle.path"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			env := r.with
			if r.dir != "" {
				env = append([]string{"PHANTOM_ACME_CACHE_DIR=" + r.dir}, env...)
			}
			_, err := loadProd(t, base, env...)
			switch {
			case r.want == "" && err != nil:
				t.Errorf("got %v", err)
			case r.want != "" && (err == nil || !strings.Contains(err.Error(), "acme.cache_dir at ") || !strings.Contains(err.Error(), r.want)):
				t.Errorf("got %v, want an error on acme.cache_dir with %q", err, r.want)
			}
		})
	}
}

const (
	hmacVar    = "HMAC_KEY"
	publishURL = `url: "https://ckpt.example/put", token_env: ` + tokenVar
)

// privateFile returns a config that puts list (a YAML flow list) in the
// private list at key. The file meets the cross rules. For an alert sink,
// kind is the sink type.
func privateFile(key, kind, list string) string {
	switch key {
	case "acme.ca_private":
		return "acme:\n  email: sec@example.com\n  ca: \"https://ca.example/dir\"\n  ca_private: " + list + "\n" + acmeNames + tlogLine
	case "bundle.fetch_private":
		return base + "bundle:\n  fetch_url: \"https://bundle.example/x\"\n  fetch_private: " + list + "\n"
	case "tlog.publish[0].private":
		return "acme:\n  email: sec@example.com\n" + acmeNames +
			"tlog: {origin: test/origin, publish: [{type: https-put, " + publishURL + ", private: " + list + "}]}\n"
	}
	sinks := map[string]string{
		"webhook": `{type: webhook, url: "https://hook.example/x", hmac_secret_env: ` + hmacVar + ", private: " + list + "}",
		"syslog":  `{type: syslog, addr: "tls://logs.example:6514", private: ` + list + "}",
		"smtp":    `{type: smtp, host: "smtp://mail.example:587", from: a@example.com, to: [b@example.com], private: ` + list + "}",
	}
	return base + "alerts:\n  sinks:\n    - " + sinks[kind] + "\n"
}

// TestTS26_PrivateLoad checks the load rows of the four private list keys
// and of each item type (SEC-30, T-S-26). A refused entry names its own
// key. A ninth entry or a duplicate names the list. A duplicate is the same
// prefix in two spellings. The error must not hold the leak text of the
// row. A row with no leak text has an entry that is too short for a fair
// check. A non-string entry also gets a detail that does not say URL.
func TestTS26_PrivateLoad(t *testing.T) {
	hmac := hmacVar + "=" + strings.Repeat("h", 32)
	targets := []struct{ name, key, kind string }{
		{"acme.ca_private", "acme.ca_private", ""},
		{"bundle.fetch_private", "bundle.fetch_private", ""},
		{"tlog.publish", "tlog.publish[0].private", ""},
		{"webhook", "alerts.sinks[0].private", "webhook"},
		{"syslog", "alerts.sinks[0].private", "syslog"},
		{"smtp", "alerts.sinks[0].private", "smtp"},
	}
	nine := `["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9"]`
	type privRow struct {
		name, list string
		bad        string // bad is "", "list" or "entry".
		leak       string // leak is a text that the error must not hold.
		nonString  bool
	}
	rows := []privRow{
		{"one address", `["10.1.2.3"]`, "", "", false},
		{"empty", `[]`, "", "", false},
		{"eight", strings.Replace(nine, `, "10.0.0.9"`, "", 1), "", "", false},
		{"each class", `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "fd00::1"]`, "", "", false},
		{"nine", nine, "list", "10.0.0.9", false},
		{"duplicate", `["10.0.0.1", "10.0.0.2", "10.0.0.1"]`, "list", "10.0.0.2", false},
		{"duplicate with /32", `["10.0.0.1", "10.0.0.1/32"]`, "list", "10.0.0.1/32", false},
		{"duplicate with /128", `["fd00::1", "fd00:0::1"]`, "list", "fd00:0::1", false},
		{"duplicate in other case", `["fd00::a", "FD00::A"]`, "list", "FD00::A", false},
		{"host name", `["internal.corp.example"]`, "entry", "internal.corp.example", false},
		{"port", `["10.0.0.1:443"]`, "entry", "10.0.0.1:443", false},
		{"not a scalar", `[[a]]`, "entry", "", false},
		// The text 10 is too short for a fair leak check.
		{"integer 10", `[10]`, "entry", "", true},
		{"integer", `[7654321]`, "entry", "7654321", true},
		{"float", `[10.5]`, "entry", "10.5", true},
		{"bool", `[true]`, "entry", "true", true},
		{"null", `[null]`, "entry", "null", true},
	}
	for _, e := range []string{"0.0.0.0/0", "::/0", "198.18.0.0/15", "192.0.2.1", "64:ff9b::/96", "2002::/16",
		"fec0::/10", "::ffff:10.0.0.0/104", "fe80::1%eth0", "10.0.0.1/8", "127.0.0.1", "100.0.0.0/8"} {
		leak := e
		if len(e) < 8 { // ::/0 is too short for a fair check.
			leak = ""
		}
		rows = append(rows, privRow{"entry " + e, `["` + e + `"]`, "entry", leak, false})
	}
	for _, tg := range targets {
		for _, r := range rows {
			t.Run(tg.name+"/"+r.name, func(t *testing.T) {
				_, err := loadProd(t, privateFile(tg.key, tg.kind, r.list), hmac)
				want := map[string]string{"": "", "list": tg.key, "entry": tg.key + "[0]"}[r.bad]
				switch {
				case r.bad == "" && err != nil:
					t.Errorf("got %v", err)
				case r.bad != "" && !hasKeyError(err, want):
					t.Errorf("got %v, want an error on %s", err, want)
				case r.leak != "" && strings.Contains(err.Error(), r.leak):
					t.Errorf("the error holds the entry: %v", err)
				case r.nonString && (strings.Contains(err.Error(), "URL") || !strings.Contains(err.Error(), "IP address or prefix")):
					t.Errorf("the detail does not name an address or a prefix: %v", err)
				}
			})
		}
	}
	t.Run("absent in an item", func(t *testing.T) {
		if _, err := loadProd(t, base); err != nil {
			t.Error(err)
		}
	})
	t.Run("not a list", func(t *testing.T) {
		_, err := loadProd(t, privateFile("tlog.publish[0].private", "", `"10.0.0.1"`))
		if !hasKeyError(err, "tlog.publish[0].private") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("acme.names refuses a text duplicate", func(t *testing.T) {
		if _, err := loadProd(t, namesFile("a.host.zz", "a.host.zz")); !hasKeyError(err, "acme.names") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("smtp to allows a duplicate", func(t *testing.T) {
		f := strings.Replace(privateFile("alerts.sinks[0].private", "smtp", "[]"), "to: [b@example.com]", "to: [b@example.com, b@example.com]", 1)
		if _, err := loadProd(t, f); err != nil {
			t.Error(err)
		}
	})
	t.Run("smtp to stays 1 to 16 entries", func(t *testing.T) {
		f := strings.Replace(privateFile("alerts.sinks[0].private", "smtp", "[]"), "to: [b@example.com]", "to: []", 1)
		if _, err := loadProd(t, f); !hasKeyError(err, "alerts.sinks[0].to") {
			t.Errorf("got %v", err)
		}
	})
}

// TestTS11_PrivateCross checks the rule of each private list. The key
// bundle.fetch_private needs a bundle.fetch_url that is not empty. The key
// acme.ca_private needs an acme.ca that is an https URL. A syslog private
// key needs a tls:// address. A present key breaks its rule also when it is
// empty. An absent key is valid. The error names the list key, also when an
// entry is refused (SEC-30, T-S-11).
func TestTS11_PrivateCross(t *testing.T) {
	acme := func(ca, list string) string {
		if ca != "" {
			ca = "  ca: " + ca + "\n"
		}
		return "acme:\n  email: sec@example.com\n" + ca + "  ca_private: " + list + "\n" + acmeNames + tlogLine
	}
	bundle := func(url, list string) string { return base + "bundle:\n" + url + "  fetch_private: " + list + "\n" }
	// sinks returns two syslog sinks. An empty list text leaves the key out.
	sinks := func(addr0, list0, addr1, list1 string) string {
		item := func(a, list string) string {
			if list != "" {
				list = ", private: " + list
			}
			return `    - {type: syslog, addr: "` + a + `"` + list + "}\n"
		}
		return base + "alerts:\n  sinks:\n" + item(addr0, list0) + item(addr1, list1)
	}
	const (
		l      = `["10.0.0.1"]`
		fetch  = "  fetch_url: \"https://bundle.example/x\"\n"
		tlsA   = "tls://logs.example:6514"
		tlsB   = "tls://logs2.example:6514"
		udpA   = "udp://127.0.0.1:514"
		tcpA   = "tcp://127.0.0.1:514"
		httpsA = `"https://ca.example/dir"`
	)
	rows := []struct {
		name, file string
		want       []string // want holds each key that the load must refuse.
	}{
		{"fetch_url empty", bundle(`  fetch_url: ""`+"\n", l), []string{"bundle.fetch_private"}},
		{"fetch_url absent", bundle("", l), []string{"bundle.fetch_private"}},
		{"fetch_url set", bundle(fetch, l), nil},
		{"empty list, fetch_url empty", bundle("", "[]"), []string{"bundle.fetch_private"}},
		{"empty list, fetch_url set", bundle(fetch, "[]"), nil},
		{"ca default", acme("", l), []string{"acme.ca_private"}},
		{"ca letsencrypt", acme("letsencrypt", l), []string{"acme.ca_private"}},
		{"ca letsencrypt-staging", acme("letsencrypt-staging", l), []string{"acme.ca_private"}},
		{"ca https URL", acme(httpsA, l), nil},
		{"empty list, letsencrypt", acme("letsencrypt", "[]"), []string{"acme.ca_private"}},
		{"empty list, https URL", acme(httpsA, "[]"), nil},
		{"udp sink", sinks(tlsA, l, udpA, l), []string{"alerts.sinks[1].private"}},
		{"tcp sink", sinks(tcpA, l, tlsA, l), []string{"alerts.sinks[0].private"}},
		{"tls sinks", sinks(tlsA, l, tlsB, l), nil},
		{"empty list, udp sink", sinks(udpA, "[]", tlsA, l), []string{"alerts.sinks[0].private"}},
		{"empty list, tls sink", sinks(tlsA, "[]", tlsB, "[]"), nil},
		{"no list, udp sink", sinks(udpA, "", tcpA, ""), nil},
		// The entry error does not hide the error of the list.
		{"udp sink, bad entry 0", sinks(udpA, `["x", "10.0.0.1"]`, tlsA, l), []string{"alerts.sinks[0].private[0]", "alerts.sinks[0].private"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := loadProd(t, r.file)
			if len(r.want) == 0 {
				if err != nil {
					t.Errorf("got %v", err)
				}
				return
			}
			for _, k := range r.want {
				if !hasKeyError(err, k) {
					t.Errorf("got %v, want an error on %s", err, k)
				}
			}
			if err != nil && strings.Count(err.Error(), "\n") != len(r.want)-1 {
				t.Errorf("got %d errors, want %d: %v", strings.Count(err.Error(), "\n")+1, len(r.want), err)
			}
		})
	}
}

// TestTS11_PrivateNoEnv checks that no private list has a PHANTOM_
// override. The name for each list is an unknown variable (SEC-30,
// T-S-11).
func TestTS11_PrivateNoEnv(t *testing.T) {
	for _, name := range []string{"PHANTOM_ACME_CA_PRIVATE", "PHANTOM_BUNDLE_FETCH_PRIVATE",
		"PHANTOM_TLOG_PUBLISH_0_PRIVATE", "PHANTOM_ALERTS_SINKS_0_PRIVATE"} {
		t.Run(name, func(t *testing.T) {
			_, err := loadProd(t, base, name+"=10.0.0.0/8")
			if err == nil || !strings.Contains(err.Error(), name+": unknown PHANTOM variable") {
				t.Errorf("got %v", err)
			}
		})
	}
}

// TestTS26_PrivateListAccessor checks that PrivateList gives the entries of
// one item only, and that the caller gets a copy (SEC-30, T-S-26).
func TestTS26_PrivateListAccessor(t *testing.T) {
	file := "acme:\n  email: sec@example.com\n  ca: \"https://ca.example/dir\"\n  ca_private: [\"10.0.0.0/8\", \"192.168.1.5\"]\n" + acmeNames +
		"tlog: {origin: test/origin, publish: [\n" +
		"  {type: https-put, " + publishURL + ", private: [\"172.16.0.0/12\"]},\n" +
		"  {type: https-put, " + publishURL + ", private: [\"10.9.0.0/16\", \"fc00::1\"]},\n" +
		"  {type: https-put, " + publishURL + "}]}\n"
	c, err := loadProd(t, file)
	if err != nil {
		t.Fatal(err)
	}
	pfx := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, e := range s {
			out = append(out, netip.MustParsePrefix(e))
		}
		return out
	}
	for _, r := range []struct {
		path string
		want []netip.Prefix
	}{
		{"acme.ca_private", pfx("10.0.0.0/8", "192.168.1.5/32")},
		{"tlog.publish[0]", pfx("172.16.0.0/12")},
		{"tlog.publish[1]", pfx("10.9.0.0/16", "fc00::1/128")},
		{"tlog.publish[2]", nil},
		{"tlog.publish[3]", nil},
		{"bundle.fetch_private", nil},
		{"tlog.publish[0].private", pfx("172.16.0.0/12")},
		// These paths are not a private list.
		{"alerts.sinks[0].to", nil},
		{"tlog.publish", nil},
		{"acme.ca_private[0]", nil},
		{"", nil},
		{"alerts.sinks[01]", nil},
		{"acme.names", nil},
		{"tlog.publish[0].url", nil},
		{"tlog.publish[0].private[0]", nil},
	} {
		if got := c.PrivateList(r.path); !slices.Equal(got, r.want) {
			t.Errorf("PrivateList(%q) = %v, want %v", r.path, got, r.want)
		}
	}
	// A config that holds a parsable value below each path that is not a
	// private list. PrivateList must still give nil for the path.
	seed := &Config{values: map[string]Value{}}
	for _, k := range []string{"alerts.sinks[0].to[0]", "tlog.publish[0]", "acme.ca_private[0][0]",
		"[0]", "alerts.sinks[01].private[0]", "acme.names[0]", "alerts.sinks[0].private[0]"} {
		seed.values[k] = Value{Str: "10.0.0.1"}
	}
	for _, p := range []string{"alerts.sinks[0].to", "tlog.publish", "acme.ca_private[0]", "", "alerts.sinks[01]", "acme.names"} {
		if got := seed.PrivateList(p); got != nil {
			t.Errorf("PrivateList(%q) = %v, want nil", p, got)
		}
	}
	if got := seed.PrivateList("alerts.sinks[0]"); len(got) != 1 {
		t.Errorf("PrivateList of a sink = %v, want 1 entry", got)
	}
	got := c.PrivateList("tlog.publish[1]")
	got[0] = netip.Prefix{}
	if again := c.PrivateList("tlog.publish[1]"); !slices.Equal(again, pfx("10.9.0.0/16", "fc00::1/128")) {
		t.Errorf("a change of the result changed the config: %v", again)
	}
}
