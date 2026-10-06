package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
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
			c, err := Load(writeConfig(t, body), nil)
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
			_, err := Load(writeConfig(t, "acme:\n  email: sec@example.com\n  ca: \""+ca+"\"\n"), nil)
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
		_, err := Load(writeConfig(t, "acme:\n  email: \"ops@corp.com, b@corp.com\"\n"), nil)
		if err == nil || !strings.Contains(err.Error(), `value "ops@corp.com, b@corp.com"`) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("valid email passes", func(t *testing.T) {
		if _, err := Load(writeConfig(t, "acme:\n  email: ops@corp.com\n"), nil); err != nil {
			t.Error(err)
		}
	})
}
