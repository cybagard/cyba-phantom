package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
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
	}, func(s string) string { return checkListen(nil, s) })
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
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) { wantLoad(t, r.file, r.want) })
	}
}

func wantLoad(t *testing.T, file, want string) {
	t.Helper()
	_, err := Load(writeConfig(t, base+file), nil)
	if (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
		t.Errorf("got %v, want %q", err, want)
	}
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
func TestTU10_OpsListenOverlap(t *testing.T) {
	useTestKeys(t)
	rows := []struct{ name, file, want string }{
		{"default", "", ""},
		{"equal to http", "listen:\n  http: \"127.0.0.1:9443\"\n", "ops.listen"},
		{"equal to https", "listen:\n  https: \"127.0.0.1:9443\"\n", "ops.listen"},
		{"inside empty host", "listen:\n  https: \":9443\"\n", "ops.listen"},
		{"inside unspecified host", "listen:\n  https: \"0.0.0.0:9443\"\n", "ops.listen"},
		{"empty host, other port", "listen:\n  https: \":8443\"\n", ""},
		{"same port, other IP", "listen:\n  https: \"192.0.2.1:9443\"\n", ""},
		{"ops on port 443", "ops:\n  listen: \"127.0.0.1:443\"\n", "ops.listen"},
		{"ops on port 80", "ops:\n  listen: \"[::1]:80\"\n", "ops.listen"},
		{"mapped unspecified", "listen:\n  https: \"[::ffff:0.0.0.0]:9443\"\n", "ops.listen"},
		{"mapped unspecified, other port", "listen:\n  https: \"[::ffff:0.0.0.0]:8443\"\n", ""},
		{"host name, same port", "listen:\n  http: \"localhost:9443\"\n", "ops.listen"},
		{"host name https, same port", "listen:\n  https: \"example.com:9443\"\n", "ops.listen"},
		{"numeric host, same port", "listen:\n  http: \"0:9443\"\n", "listen.http"},
		{"zoned unspecified http", "listen:\n  http: \"[::%lo0]:9443\"\n", "ops.listen"},
		{"zoned unspecified https", "listen:\n  https: \"[::%lo0]:9443\"\n", "ops.listen"},
		{"zoned unspecified, other port", "listen:\n  https: \"[::%lo0]:8443\"\n", ""},
		{"host name, other port", "listen:\n  http: \"localhost:8443\"\n", ""},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) { wantLoad(t, r.file, r.want) })
	}
}

// TestTU10_CrossCheckFailedKey checks that a key whose value failed is not in the cross check.
func TestTU10_CrossCheckFailedKey(t *testing.T) {
	useTestKeys(t)
	for _, file := range []string{
		"listen:\n  http: \":443\"\n  https: bad\n",
		"listen:\n  http: \":443\"\n  https: \":99999\"\n",
	} {
		_, err := Load(writeConfig(t, base+file), nil)
		if err == nil || !strings.Contains(err.Error(), "listen.https") {
			t.Fatalf("got %v", err)
		}
		if strings.Contains(err.Error(), "default") || strings.Contains(err.Error(), "must differ") {
			t.Errorf("a stale default is in the cross check: %v", err)
		}
	}
	_, err := Load(writeConfig(t, base), []string{"CANARY_LISTEN_HTTP=:9443", "CANARY_OPS_LISTEN=0.0.0.0:9443"})
	if err == nil || strings.Count(err.Error(), "\n") != 0 || !strings.Contains(err.Error(), "ops.listen at CANARY_OPS_LISTEN") {
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
		_, err := Load(writeConfig(t, base+file), nil)
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
		{"two", "a@example.com, b@example.com", "one address"},
		{"display name", "Sec <sec@example.com>", "one address"},
		{"angle only", "<sec@example.com>", "one address"},
		{"no domain", "sec", "one address"},
		{"space padding", " sec@example.com", "one address"},
		{"LF", "sec@example.com\n", "CR or LF"},
		{"CR", "sec@example.com\r", "CR or LF"},
		{"CRLF header", "a@example.com\r\nBcc: b@example.com", "CR or LF"},
		{"LF in middle", "a@example.com\nb@example.com", "CR or LF"},
	}, func(s string) string { return checkEmail(nil, s) })
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
		{"ipv4", "https://192.0.2.1/dir", []string{"https"}, ""},
		{"ipv6", "https://[2001:db8::1]/dir", []string{"https"}, ""},
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
		{"link-local v4", "https://169.254.169.254/", []string{"https"}, "link-local"},
		{"link-local v6", "https://[fe80::1]/", []string{"https"}, "link-local"},
		{"inside fe80::/10", "https://[fe81::]/", []string{"https"}, "link-local"},
		{"top of fe80::/10", "https://[febf::1]/", []string{"https"}, "link-local"},
		{"outside fe80::/10", "https://[fec0::1]/", []string{"https"}, ""},
		{"v4 mapped link-local", "https://[::ffff:169.254.169.254]/", []string{"https"}, "link-local"},
		{"zone", "https://[fe80::1%25eth0]/", []string{"https"}, "zone"},
		{"zone on global", "https://[2001:db8::1%25eth0]/", []string{"https"}, "zone"},
		{"unspecified v4", "https://0.0.0.0/", []string{"https"}, "unspecified"},
		{"unspecified v6", "https://[::]/", []string{"https"}, "unspecified"},
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
		{"numeric host with dot at end", "https://2852039166./", []string{"https"}, "number"},
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
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, got := parseURL(r.in, r.schemes...)
			if (r.want == "") != (got == "") || !strings.Contains(got, r.want) {
				t.Errorf("parseURL(%q) = %q, want %q", r.in, got, r.want)
			}
		})
	}
}

// TestTU10_CA checks the acme.ca values and the allow-list.
func TestTU10_CA(t *testing.T) {
	runRows(t, []row{
		{"letsencrypt", "letsencrypt", ""},
		{"staging", "letsencrypt-staging", ""},
		{"https", "https://ca.example/dir", ""},
		{"https port", "https://127.0.0.1:14000/dir", ""},
		{"tcp", "tcp://ca.example:443", "scheme"},
		{"http", "http://ca.example/dir", "scheme"},
		{"other name", "zerossl", "scheme"},
		{"case", "Letsencrypt", "scheme"},
		{"empty", "", "scheme"},
		{"link-local", "https://[fe81::]/dir", "link-local"},
		{"user", "https://u:p@ca.example/dir", "user information"},
		{"port leading zero", "https://ca.example:0443/dir", "decimal"},
		{"number host", "https://2852039166/dir", "number"},
		{"full-width host", "https://１６９．２５４．１６９．２５４/dir", "ASCII"},
	}, func(s string) string { return checkCA(nil, s) })
}

// TestTU10_AllowList checks that AllowList returns the acme.ca endpoint only.
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
		{"ipv6", "acme:\n  ca: \"https://[2001:db8::1]:8443/\"\n", []Endpoint{{"https", "2001:db8::1", "8443"}}},
		{"upper case host", "acme:\n  ca: https://CA.Example:14000/dir\n", []Endpoint{{"https", "ca.example", "14000"}}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			body := "acme:\n  email: sec@example.com\n"
			if r.file != "" {
				body += strings.TrimPrefix(r.file, "acme:\n")
			}
			c, err := Load(writeConfig(t, body+tlogOrigin), nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.AllowList(); !reflect.DeepEqual(got, r.want) {
				t.Errorf("got %+v, want %+v", got, r.want)
			}
		})
	}
}

// TestTU10_PathForm checks the path helper.
func TestTU10_PathForm(t *testing.T) {
	runRows(t, []row{
		{"absolute", "/var/lib/agent-canary/certs", ""},
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

// TestTU10_HtpasswdValueOnly checks that the error shows the path in the Value field only,
// cut to 64 bytes, and that the detail is fixed text.
func TestTU10_HtpasswdValueOnly(t *testing.T) {
	useTestKeys(t)
	p := filepath.Join(t.TempDir(), strings.Repeat("n", 90))
	_, err := Load(writeConfig(t, base+"ops:\n  basic_auth_htpasswd: "+p+"\n"), nil)
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
	_, err := Load(writeConfig(t, base+"ops:\n  basic_auth_htpasswd: "+p+"\n"), nil)
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
			_, err := Load(writeConfig(t, "acme:\n  email: sec@example.com\n  ca: \""+ca+"\"\n"+tlogOrigin), nil)
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
		_, err := Load(writeConfig(t, base), []string{"CANARY_ACME_CA=https://u:" + secret + "@h/"})
		if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "CANARY_ACME_CA") {
			t.Errorf("got %v", err)
		}
	})
	t.Run("email keeps the at sign", func(t *testing.T) {
		_, err := Load(writeConfig(t, "acme:\n  email: \"ops@corp.com, b@corp.com\"\n"+tlogOrigin), nil)
		if err == nil || !strings.Contains(err.Error(), `value "ops@corp.com, b@corp.com"`) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("valid email passes", func(t *testing.T) {
		if _, err := Load(writeConfig(t, "acme:\n  email: ops@corp.com\n"+tlogOrigin), nil); err != nil {
			t.Error(err)
		}
	})
}

// loadProd loads file with the production key table. The default htpasswd path does not exist
// on a test host, so the call sets it through the environment.
func loadProd(t *testing.T, file string, env ...string) (*Config, error) {
	t.Helper()
	const htpasswdEnv = "CANARY_OPS_BASIC_AUTH_HTPASSWD"
	// The loader rejects a variable that occurs two times, so the default is set only if the caller does not set it.
	if !slices.ContainsFunc(env, func(kv string) bool { return strings.HasPrefix(kv, htpasswdEnv+"=") }) {
		env = append([]string{htpasswdEnv + "=" + filepath.Join(testDir, "htpasswd")}, env...)
	}
	return Load(writeConfig(t, file), env)
}

// bound is one row of the 04 section 3 bounds table: values that pass, values that fail,
// and the other variables that the row needs. The test sets a value by its CANARY_ variable.
type bound struct {
	key        string
	pass, fail []string
	with       []string
}

var (
	longOrigin = strings.Repeat("a", 128)
	fetchURL   = "CANARY_BUNDLE_FETCH_URL=https://bundle.example/current"
	// groupWritable is a file in a temp dir with mode 0660. The other bad values of the htpasswd row
	// are a relative path, an unclean path, and a missing file. All of them go through the CANARY_ variable.
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
	{key: "listen.http", pass: []string{":1", ":65535"}, fail: []string{":0", ":65536", "x"}},
	{key: "listen.https", pass: []string{":1", ":65535"}, fail: []string{":0", ":65536", ":80"}},
	{key: "ops.listen", pass: []string{"127.0.0.1:1", "[::1]:65535", "10.0.0.1:9443"}, fail: []string{"127.0.0.1:0", "127.0.0.1:65536", "0.0.0.0:9443", "8.8.8.8:9443", "localhost:9443"}},
	{key: "ops.basic_auth_htpasswd", pass: []string{filepath.Join(testDir, "htpasswd")}, fail: []string{"htpasswd", testDir + "/./htpasswd", filepath.Join(testDir, "missing"), groupWritable}},
	{key: "acme.email", pass: []string{"a@b.example"}, fail: []string{"a@b.example\nBcc: c@d.example", "a@b.example, c@d.example", ""}},
	{key: "acme.ca", pass: []string{"letsencrypt", "letsencrypt-staging", "https://ca.example/dir"}, fail: []string{"http://ca.example/dir", "https://u:p@ca.example/", "https://169.254.169.254/"}},
	{key: "acme.cache_dir", pass: []string{"/var/lib/agent-canary/certs"}, fail: []string{"/var/lib/other", "var/lib/agent-canary", "/var/lib/agent-canary/../x"}},
	{key: "bundle.path", pass: []string{"/var/lib/agent-canary/bundle/current.cbnd"}, fail: []string{"/etc/current.cbnd", "bundle.cbnd", "/var/lib/agent-canary/b/../../x"}},
	{key: "bundle.fetch_url", pass: []string{"", "https://bundle.example:8443/b"}, fail: []string{"http://bundle.example/b", "https://u:p@bundle.example/b", "https://bundle.example/b#f", "https://169.254.169.254/b", "https://0.0.0.0/b", "ftp://bundle.example/b"}},
	{key: "bundle.fetch_interval", pass: []string{"15m", "168h"}, fail: []string{"14m59s", "168h1s", "0s", "-1h"}, with: []string{fetchURL}},
	{key: "bundle.fetch_interval", pass: []string{"1s"}, fail: []string{"0s", "-1h"}}, // The fetch is off: only the check for a value > 0 applies.
	{key: "limits.max_conns", pass: []string{"1", "2000"}, fail: []string{"0", "2001", "-1"}},
	{key: "limits.body_bytes", pass: []string{"1", "65536"}, fail: []string{"0", "65537"}},
	{key: "limits.header_bytes", pass: []string{"1", "16384"}, fail: []string{"0", "16385"}},
	{key: "limits.per_ip_rps", pass: []string{"1", "1000"}, fail: []string{"0", "1001"}, with: []string{"CANARY_LIMITS_PER_IP_BURST=5000"}},
	{key: "limits.per_ip_rps", pass: []string{"200"}}, // The default burst is 200. A larger rate fails on the burst key (TestTS11_CrossChecks).
	{key: "limits.per_ip_burst", pass: []string{"100", "5000"}, fail: []string{"99", "5001", "0"}, with: []string{"CANARY_LIMITS_PER_IP_RPS=100"}},
	{key: "limits.per_ip_burst", pass: []string{"1"}, fail: []string{"0"}, with: []string{"CANARY_LIMITS_PER_IP_RPS=1"}},
	{key: "limits.queue_depth", pass: []string{"1", "8192"}, fail: []string{"0", "8193"}},
	{key: "store.path", pass: []string{"/var/lib/agent-canary/events.db"}, fail: []string{"/tmp/events.db", "events.db"}},
	{key: "store.max_bytes", pass: []string{"268435456", "9223372036854775807"}, fail: []string{"268435455", "0", "9223372036854775808"}},
	{key: "store.retention_days.ip", pass: []string{"1", "7"}, fail: []string{"0", "8"}},
	{key: "store.retention_days.raw", pass: []string{"1", "30"}, fail: []string{"0", "31"}},
	{key: "store.retention_days.events", pass: []string{"30", "90"}, fail: []string{"29", "91", "0"}},
	{key: "store.retention_days.events", pass: []string{"5"}, fail: []string{"4"}, with: []string{"CANARY_STORE_RETENTION_DAYS_RAW=5"}},
	{key: "tlog.dir", pass: []string{"/var/lib/agent-canary/tlog"}, fail: []string{"/var/tlog", "tlog"}},
	{key: "tlog.origin", pass: []string{"a", longOrigin, "agent-canary/abc_1.2-x"}, fail: []string{"", longOrigin + "a", "agent-canary/<install_id>", "a b", "a\nb", "é"}},
	{key: "tlog.checkpoint_interval", pass: []string{"1m", "24h"}, fail: []string{"59s", "24h0m1s", "0s", "-1m"}},
	{key: "alerts.min_band", pass: []string{"agent-likely", "agent-confirmed"}, fail: []string{"human", "crawler", "", "Agent-Likely"}},
	{key: "privacy.store_body_prefix", pass: []string{"true", "false"}, fail: []string{"on", "yes", "1", "True"}},
	{key: "privacy.include_ip", pass: []string{"true", "false"}, fail: []string{"on", "yes", "1", "True"}},
}

// TestTS11_ScalarBounds runs the bounds table through Load, one value per CANARY_ variable.
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
		{"burst below rps", "limits:\n  per_ip_rps: 300\n", "limits.per_ip_burst at default: the value must not be less than limits.per_ip_rps"},
		{"burst equals rps", "limits:\n  per_ip_rps: 200\n", ""},
		{"events below raw", "store:\n  retention_days:\n    raw: 91\n", "store.retention_days.raw"}, // The raw bound fails first.
		{"events below raw 2", "store:\n  retention_days:\n    raw: 30\n    events: 29\n", "store.retention_days.events at " + cfg[len(cfg)-64:] + ":8: the value must not be less than"},
		{"interval, fetch off", "bundle:\n  fetch_interval: 1s\n", ""},
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

// TestTU10_Defaults checks the 04 section 3 default of each key, on a minimal valid file.
func TestTU10_Defaults(t *testing.T) {
	c, err := loadProd(t, base)
	if err != nil {
		t.Fatal(err)
	}
	const state = "/var/lib/agent-canary/"
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

// TestTU10_Overrides checks that each key has a CANARY_ override that goes through the bounds.
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
		if !ok || len(b.pass) == 0 {
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
	c, err := loadProd(t, base, "CANARY_LIMITS_BODY_BYTES=100", "CANARY_STORE_RETENTION_DAYS_IP=3")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Get("limits.body_bytes"); v.Int != 100 {
		t.Errorf("got %+v", v)
	}
	if v, _ := c.Get("store.retention_days.ip"); v.Int != 3 {
		t.Errorf("got %+v", v)
	}
	_, err = loadProd(t, base+"limits:\n  body_bytes: 100\n", "CANARY_LIMITS_BODY_BYTES=65537")
	if err == nil || !strings.Contains(err.Error(), "limits.body_bytes at CANARY_LIMITS_BODY_BYTES") {
		t.Errorf("got %v", err)
	}
}

// TestTU10_NewSectionsInvalid checks one invalid file value for each new section.
func TestTU10_NewSectionsInvalid(t *testing.T) {
	rows := []struct{ file, key string }{
		{base + "bundle:\n  fetch_url: http://b.example/x\n", "bundle.fetch_url"},
		{base + "limits:\n  body_bytes: 65537\n", "limits.body_bytes"},
		{base + "store:\n  retention_days:\n    ip: 8\n", "store.retention_days.ip"},
		{"acme:\n  email: sec@example.com\ntlog:\n  origin: \"agent-canary/<install_id>\"\n", "tlog.origin"},
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
	if err != nil || len(c.AllowList()) != 1 {
		t.Fatalf("fetch off: %v, %+v", err, c)
	}
	c, err = loadProd(t, base, "CANARY_BUNDLE_FETCH_URL=https://Bundle.Example:8443/b")
	if err != nil {
		t.Fatal(err)
	}
	want := []Endpoint{{"https", "acme-v02.api.letsencrypt.org", "443"}, {"https", "bundle.example", "8443"}}
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
