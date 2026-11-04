package bait

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// member is the token member of a body.
const member = `"token":"` + tokText + `"`

// pad gives s with spaces at the end, up to n bytes.
func pad(s string, n int) string { return s + strings.Repeat(" ", n-len(s)) }

// The body forms of the hostile input.
var (
	formSmall   = `{` + member + `}`
	formDup     = `{` + member + `,` + member + `}`
	formDeep    = strings.Repeat(`{"a":`, 2000) + `1` + strings.Repeat(`}`, 2000)
	formOpen    = strings.Repeat(`[`, 4096)
	formObjOpen = `{"a":` + strings.Repeat(`[`, 4090)
	formMembers = func() string {
		var b strings.Builder
		b.WriteByte('{')
		for i := 0; i < 400; i++ {
			b.WriteString(`"m` + strconv.Itoa(100+i) + `":1,`)
		}
		b.WriteString(member + `}`)
		return b.String()
	}()
)

// bodyCases are the inputs of the scan. want is the candidate or "".
var bodyCases = []struct{ name, body, want string }{
	{"small", formSmall, tokText},
	{"dup", formDup, ""},
	{"deep-2000", formDeep, ""},
	{"open-4096", formOpen, ""},
	{"obj-open-4090", formObjOpen, ""},
	{"members-400", formMembers, tokText},
	{"white space", " \t\r\n{ \n\"token\" \t: \r" + `"` + tokText + "\" }\n ", tokText},
	{"all scalars", `{"n":-1.5e+3,"t":true,"f":false,"z":null,"s":"x\"y\\é\/",` + member + `,"i":0}`, tokText},
	{"quote in string", `{"a":"q\"}","b":"\\",` + member + `}`, tokText},
	{"empty", ``, ""},
	{"white space only", ` `, ""},
	{"empty object", `{}`, ""},
	{"empty object spaces", `{ }`, ""},
	{"array", `[` + member + `]`, ""},
	{"string", `"` + tokText + `"`, ""},
	{"number", `1`, ""},
	{"dup first number", `{"token":1,` + member + `}`, ""},
	{"dup other order", `{` + member + `,"token":1}`, ""},
	{"number value", `{"token":1}`, ""},
	{"null value", `{"token":null}`, ""},
	{"true value", `{"token":true}`, ""},
	{"object value", `{"token":{}}`, ""},
	{"nested before", `{"a":{"b":1},` + member + `}`, ""},
	{"nested empty object", `{"a":{},` + member + `}`, ""},
	{"nested array", `{"a":[],` + member + `}`, ""},
	{"nested in token", `{"token":{"token":"` + tokText + `"}}`, ""},
	{"trailing comma", `{` + member + `,}`, ""},
	{"leading comma", `{,` + member + `}`, ""},
	{"double comma", `{` + member + `,,"a":1}`, ""},
	{"no colon", `{"token" "` + tokText + `"}`, ""},
	{"no comma", `{"a":1 ` + member + `}`, ""},
	{"unclosed", `{` + member, ""},
	{"trailing byte", formSmall + `x`, ""},
	{"trailing object", formSmall + `{}`, ""},
	{"trailing comma byte", formSmall + `,`, ""},
	{"leading byte", `x` + formSmall, ""},
	{"bom", "\xef\xbb\xbf" + formSmall, ""},
	{"name with backslash", `{"a\\b":1,` + member + `}`, ""},
	{"name with escape", "{\"tok\\u0065n\":\"" + tokText + "\"}", ""},
	{"name with quote escape", `{"a\"":1,` + member + `}`, ""},
	{"control in string", "{\"a\":\"x\x01\"," + member + `}`, ""},
	{"newline in string", "{\"a\":\"x\n\"," + member + `}`, ""},
	{"control in name", "{\"a\x01\":1," + member + `}`, ""},
	{"invalid utf-8", "{\"a\":\"\xff\"," + member + `}`, ""},
	{"invalid utf-8 name", "{\"\xc3\":1," + member + `}`, ""},
	{"bad escape", `{"a":"\x",` + member + `}`, ""},
	{"short unicode escape", `{"a":"\u12",` + member + `}`, ""},
	{"bad unicode escape", `{"a":"\u12g4",` + member + `}`, ""},
	{"escape at end", `{"a":"\`, ""},
	{"unterminated string", `{"a":"x`, ""},
	{"leading zero", `{"a":01,` + member + `}`, ""},
	{"number dot", `{"a":1.,` + member + `}`, ""},
	{"number start dot", `{"a":.5,` + member + `}`, ""},
	{"number plus", `{"a":+1,` + member + `}`, ""},
	{"number exp", `{"a":1e,` + member + `}`, ""},
	{"number minus", `{"a":-,` + member + `}`, ""},
	{"number letters", `{"a":1x,` + member + `}`, ""},
	{"short literal", `{"a":tru,` + member + `}`, ""},
	{"upper literal", `{"a":True,` + member + `}`, ""},
	{"long literal", `{"a":nullx,` + member + `}`, ""},
	{"escape in value", `{"token":"abcdefghijklmnopqrstuvw\n"}`, ""},
	{"upper", `{"token":"` + strings.ToUpper(tokText) + `"}`, ""},
	{"25 bytes", `{"token":"` + tokText[:25] + `"}`, ""},
	{"27 bytes", `{"token":"` + tokText + `a"}`, ""},
	{"escaped byte", `{"token":"%61` + tokText[3:] + `"}`, ""},
	{"name case", `{"Token":"` + tokText + `"}`, ""},
	{"longer name", `{"tokenx":"` + tokText + `"}`, ""},
}

// TestTS32BodyScan checks the scan of the flat object.
func TestTS32BodyScan(t *testing.T) {
	for _, c := range bodyCases {
		v, ok := bodyMember([]byte(c.body), "token")
		if (ok && string(v) != c.want) || ok != (c.want != "") {
			t.Errorf("%s: got %q %v, want %q", c.name, v, ok, c.want)
		}
	}
}

// FuzzBodyMember checks that the scan never panics. A candidate that it gives
// is in valid UTF-8 input. The seed corpus is the table of the scan.
func FuzzBodyMember(f *testing.F) {
	for _, c := range bodyCases {
		f.Add([]byte(c.body))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, ok := bodyMember(b, "token")
		if ok && (!isCandidate(v) || !utf8.Valid(b) || !strings.Contains(string(b), string(v))) {
			t.Fatalf("body %q gave %q", b, v)
		}
	})
}

// rewind is a body reader that counts. It gives data, then fail or io.EOF.
type rewind struct {
	data     []byte
	off, got int
	fail     error
}

func (r *rewind) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		if r.fail != nil {
			return 0, r.fail
		}
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	r.got += n
	return n, nil
}

func (r *rewind) Close() error { return nil }

func (r *rewind) reset() { r.off, r.got = 0, 0 }

// postWith makes a request with a counting body. cl is the Content-Length.
func postWith(method, body string, cl int64, fail error) (*http.Request, *rewind) {
	rb := &rewind{data: []byte(body), fail: fail}
	r := httptest.NewRequest(method, "/", nil)
	r.Body, r.ContentLength = rb, cl
	return r, rb
}

// TestTS32BodyCandidate checks the read rules of the body candidate.
func TestTS32BodyCandidate(t *testing.T) {
	edge := func(n int) string { return pad(formSmall, n) }
	cases := []struct {
		name, method, body string
		cl                 int64
		fail               error
		want               string
		got                int // bytes read
	}{
		{"post", "POST", formSmall, int64(len(formSmall)), nil, tokText, len(formSmall)},
		{"chunked", "POST", formSmall, -1, nil, tokText, len(formSmall)},
		{"cl 4096", "POST", edge(4096), 4096, nil, tokText, 4096},
		{"chunked 4096", "POST", edge(4096), -1, nil, tokText, 4096},
		{"cl 4097", "POST", edge(4097), 4097, nil, "", 0},
		{"cl 5000", "POST", edge(5000), 5000, nil, "", 0},
		{"chunked 4097", "POST", edge(4097), -1, nil, "", 4097},
		{"cl lies 4096", "POST", edge(4097), 4096, nil, "", 4097},
		{"chunked 300 KiB", "POST", edge(300 << 10), -1, nil, "", 4097},
		{"read error", "POST", formSmall, -1, errors.New("boom"), "", len(formSmall)},
		{"unexpected eof", "POST", formSmall, -1, io.ErrUnexpectedEOF, "", len(formSmall)},
		{"get", "GET", formSmall, -1, nil, "", 0},
		{"head", "HEAD", formSmall, -1, nil, "", 0},
		{"put", "PUT", formSmall, -1, nil, "", 0},
		{"empty", "POST", "", 0, nil, "", 0},
	}
	for _, c := range cases {
		r, rb := postWith(c.method, c.body, c.cl, c.fail)
		got, ok := BodyCandidate(r, "token")
		if (ok && string(got[:]) != c.want) || ok != (c.want != "") {
			t.Errorf("%s: got %q %v, want %q", c.name, got[:], ok, c.want)
		}
		if rb.got != c.got {
			t.Errorf("%s: read %d bytes, want %d", c.name, rb.got, c.got)
		}
	}
	r, _ := postWith("POST", formSmall, -1, nil)
	r.Body = nil
	if _, ok := BodyCandidate(r, "token"); ok {
		t.Error("nil body gave a candidate")
	}
}

// TestTS32BodyNoAllocs checks the body forms, and each path that takes a pool
// buffer. A buffer that does not go back to the pool makes the next call
// allocate a new one.
func TestTS32BodyNoAllocs(t *testing.T) {
	big := pad(formSmall, 4097)
	forms := map[string]struct {
		body string
		cl   int64
		fail error
		ok   bool
	}{
		"small":         {formSmall, -1, nil, true},
		"dup":           {formDup, -1, nil, false},
		"deep-2000":     {formDeep, -1, nil, false},
		"open-4096":     {formOpen, -1, nil, false},
		"obj-open-4090": {formObjOpen, -1, nil, false},
		"members-400":   {formMembers, int64(len(formMembers)), nil, true},
		"4097 bytes":    {big, -1, nil, false},
		"read error":    {formSmall, -1, errors.New("boom"), false},
		"cl over":       {big, 4097, nil, false},
	}
	for name, f := range forms {
		r, rb := postWith("POST", f.body, f.cl, f.fail)
		if _, ok := BodyCandidate(r, "token"); ok != f.ok {
			t.Errorf("%s: ok = %v", name, ok)
		}
		n := testing.AllocsPerRun(2000, func() {
			rb.reset()
			BodyCandidate(r, "token")
		})
		if n != 0 {
			t.Errorf("%s: %v allocations", name, n)
		}
	}
}

// TestTS32BodyServer checks the read limit with a real server. The handler
// counts the bytes that the call reads from the body of the connection.
func TestTS32BodyServer(t *testing.T) {
	type result struct {
		got  int
		cl   int64
		cand string
	}
	res := make(chan result, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rb := &tallyBody{ReadCloser: r.Body}
		r.Body = rb
		c, ok := BodyCandidate(r, "token")
		cand := ""
		if ok {
			cand = string(c[:])
		}
		res <- result{rb.got, r.ContentLength, cand}
	}))
	defer srv.Close()
	for _, c := range []struct {
		name    string
		body    string
		chunked bool
		want    result
	}{
		{"chunked 300 KiB", pad(formSmall, 300<<10), true, result{4097, -1, ""}},
		{"chunked small", formSmall, true, result{len(formSmall), -1, tokText}},
		{"length 300 KiB", pad(formSmall, 300<<10), false, result{0, 300 << 10, ""}},
		{"length small", formSmall, false, result{len(formSmall), int64(len(formSmall)), tokText}},
	} {
		var body io.Reader = strings.NewReader(c.body)
		if c.chunked {
			body = io.MultiReader(body)
		}
		resp, err := http.Post(srv.URL, "application/json", body)
		if err == nil {
			resp.Body.Close()
		}
		if got := <-res; got != c.want {
			t.Errorf("%s: got %+v, want %+v (client error %v)", c.name, got, c.want, err)
		}
	}
}

// tallyBody counts the bytes that a handler reads from a body.
type tallyBody struct {
	io.ReadCloser
	got int
}

func (c *tallyBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.got += n
	return n, err
}

// BenchmarkBodyCandidate reads and scans a body of 4 KiB.
func BenchmarkBodyCandidate(b *testing.B) {
	head, tail := `{"pad":"`, `",`+member+`}`
	body := head + strings.Repeat("x", 4096-len(head)-len(tail)) + tail
	r, rb := postWith("POST", body, int64(len(body)), nil)
	if _, ok := BodyCandidate(r, "token"); !ok || len(body) != 4096 {
		b.Fatalf("body of %d bytes, no candidate", len(body))
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		rb.reset()
		BodyCandidate(r, "token")
	}
}
