package bundle

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	ts25Env      = "PHANTOM_TS25_CASE"
	ts25Marker   = "PHANTOM_TS25_CHILD" // only the parent sets it
	ts25HWMMax   = 140_000_000
	ts25KeptMax  = 56 << 20
	ts25ParseMax = 5 * time.Second
	ts25Held     = 16 << 20 // file bytes and bytes of the bundle that runs
	ts25GC       = 50
	ts25Limit    = 256 << 20
	ts25MixSmall = 1023 // templates of one action before the last template
	ts25Depth    = 9999
	ts25MaxParen = 2*ts25Depth + 5
)

// The caps of SEC-29 as numbers. The code constants must equal them.
const (
	ts25TmplBytes   = 65536
	ts25TmplActs    = 2048
	ts25BundleBytes = 524288
	ts25BundleActs  = 16384
	// The numbers of T-S-25 and the archive caps, not the code constants.
	ts25EntryBytes   = 4 << 20
	ts25DecodedBytes = 8 << 20
)

// ts25Splits are the numbers of templates, with the size and the "{{" count of
// each template. All of them fill the bundle caps, or the template caps.
var ts25Splits = []struct{ n, size, acts int }{
	{1, ts25TmplBytes, ts25TmplActs}, {8, ts25TmplBytes, ts25TmplActs},
	{16, 32768, 1024}, {1024, 512, 16},
}

// The text of a shape has a fixed part, such as the braces and the name of a
// function. The numbers that the generators subtract from size count its bytes.
// ub and ua are the bytes and the "{{" of one unit of the shape.
type ts25Shape struct {
	name   string
	open   bool // no {{end}}: the parse gives an error
	ub, ua int
	gen    func(size, acts int) string
}

// ts25Fill joins units of open(i) until the next unit goes over size bytes or
// acts "{{". It writes all opens, then all shuts.
func ts25Fill(size, acts int, open func(int) string, shut string) string {
	var o, s strings.Builder
	used, n := 0, 0
	for i := 0; ; i++ {
		a := open(i)
		k := strings.Count(a+shut, "{{")
		if n+k > acts || used+len(a)+len(shut) > size {
			return o.String() + s.String()
		}
		o.WriteString(a)
		s.WriteString(shut)
		used += len(a) + len(shut)
		n += k
	}
}

func ts25Const(s string) func(int) string { return func(int) string { return s } }

func ts25Flat(unit string) func(int, int) string {
	return func(size, acts int) string { return ts25Fill(size, acts, ts25Const(unit), "") }
}

// ts25Parens is one action with parentheses and exactly n bytes, n >= 5. An
// even n has one space inside. The depth is (n-5)/2.
func ts25Parens(n int) string {
	d := (n - 5) / 2
	return "{{" + strings.Repeat("(", d) + "1" + strings.Repeat(" ", (n-5)%2) + strings.Repeat(")", d) + "}}"
}

// ts25ParensFill is actions of depth 9 999, then one action for the rest. If
// the rest is 1 to 4 bytes, the last two actions share it and are shallower.
func ts25ParensFill(size int) string {
	var b strings.Builder
	for size > 0 {
		n := min(size, ts25MaxParen)
		if r := size - n; r > 0 && r < 5 {
			n -= 5
		}
		b.WriteString(ts25Parens(n))
		size -= n
	}
	return b.String()
}

func ts25Pad(s string, n int) string { return s + strings.Repeat("a", n-len(s)) }

func ts25Shapes() []ts25Shape {
	var out []ts25Shape
	nest := func(name string, open func(int) string) {
		ub := len(open(9999))
		out = append(out,
			ts25Shape{name, false, ub + 7, 2, func(size, acts int) string { return ts25Fill(size, acts, open, "{{end}}") }},
			ts25Shape{name + "-open", true, ub, 1, func(size, acts int) string { return ts25Fill(size, acts, open, "") }})
	}
	for _, c := range []string{"if", "range", "with"} {
		nest(c, ts25Const("{{"+c+" 1}}"))
	}
	nest("block", func(i int) string { return fmt.Sprintf(`{{block "b%d" .}}`, i) })
	flat := func(name, unit string) {
		out = append(out, ts25Shape{name, false, len(unit), strings.Count(unit, "{{"), ts25Flat(unit)})
	}
	flat("num", "{{1}}")
	flat("dot", "{{.}}")
	flat("field", "{{.A.B}}")
	flat("adot", "a{{.}}")
	flat("text", "a")
	def := func(i int) string { return fmt.Sprintf(`{{define "d%d"}}x{{end}}`, i) }
	return append(out,
		ts25Shape{"parens", false, 1, 0, func(size, _ int) string { return ts25ParensFill(size) }},
		ts25Shape{"define", false, len(def(9999)), 2, func(size, acts int) string { return ts25Fill(size, acts, def, "") }},
		ts25Shape{"args", false, 2, 0, func(size, _ int) string {
			return "{{print" + strings.Repeat(" 1", (size-9)/2) + "}}"
		}},
		ts25Shape{"pipe", false, 6, 0, func(size, _ int) string {
			return "{{1" + strings.Repeat("|print", (size-5)/6) + "}}"
		}},
		// Many declarations, then many uses of the last one. A use scans the
		// declared names from the first.
		ts25Shape{"vars", false, 3, 0, func(size, _ int) string {
			m := (size - 17) / 2 / 8
			return "{{print" + strings.Repeat(" ($a:=1)", m) + " ($b:=1)" +
				strings.Repeat(" $b", (size-17-8*m)/3) + "}}"
		}},
		ts25Shape{"vars2", false, 3, 0, func(size, acts int) string {
			m := min(acts-2, size/2/9)
			return strings.Repeat("{{$a:=1}}", m) + "{{$b:=1}}" +
				"{{print" + strings.Repeat(" $b", (size-18-9*m)/3) + "}}"
		}},
		ts25Shape{"nestparens", true, 1, 1, func(size, acts int) string {
			opens := strings.Repeat("{{if 1}}", acts-1)
			return opens + ts25Parens(min(ts25MaxParen, size-len(opens)))
		}},
		ts25Shape{"elseif", false, 13, 1, func(size, acts int) string {
			return "{{if 1}}" + strings.Repeat("{{else if 1}}", min(acts-2, (size-15)/13)) + "{{end}}"
		}})
}

// ts25Case kinds: "balanced" parses. "open" has no {{end}}, so the parse gives
// an error after at least one constructor call. A cap refuses an "over" case
// before the first constructor call.
type ts25Case struct {
	name  string
	n     int // templates that the constructor must make
	kind  string
	fills func([]string) string // the empty string when the texts fill the caps
	texts func() []string
}

// ts25Deep is false for a text with parentheses but not to depth 9999.
func ts25Deep(s string) bool {
	return !strings.Contains(s, "((") || strings.Contains(s, strings.Repeat("(", ts25Depth))
}

// ts25Fills checks that each text is within one unit of its binding cap.
// A text with room for parentheses must also reach depth 9999.
func ts25Fills(size, acts, ub, ua int) func([]string) string {
	return func(texts []string) string {
		for _, s := range texts {
			if n := strings.Count(s, "{{"); size-len(s) >= ub && acts-n >= ua || size >= 2*ts25Depth+5 && !ts25Deep(s) {
				return fmt.Sprintf("a text has %d bytes and %d \"{{\" (caps %d and %d) or too little depth",
					len(s), n, size, acts)
			}
		}
		return ""
	}
}

// ts25MixFills checks the bundle bytes, and the bytes and "{{" of the last
// template of a mix.
func ts25MixFills(acts int) func([]string) string {
	return func(texts []string) string {
		total, last := 0, texts[len(texts)-1]
		for _, s := range texts {
			total += len(s)
		}
		if n := strings.Count(last, "{{"); total != ts25BundleBytes || len(last) != ts25TmplBytes || n != acts || !ts25Deep(last) {
			return fmt.Sprintf("the bundle has %d bytes, the last template %d bytes and %d \"{{\", or too little depth",
				total, len(last), n)
		}
		return ""
	}
}

// ts25Mix is 1 023 templates of one action, then the last template. The first
// templates bring the bundle to its byte cap. The last template has acts "{{".
func ts25Mix(name, kind string, acts int, last string) ts25Case {
	return ts25Case{name, ts25MixSmall + 1, kind, ts25MixFills(acts), func() []string {
		rest := ts25BundleBytes - len(last)
		out := make([]string, 0, ts25MixSmall+1)
		for i := range ts25MixSmall {
			out = append(out, ts25Parens(rest/ts25MixSmall+min(1, max(0, rest%ts25MixSmall-i))))
		}
		return append(out, last)
	}}
}

func ts25Cases() []ts25Case {
	var out []ts25Case
	for _, sh := range ts25Shapes() {
		for _, sp := range ts25Splits {
			kind := "balanced"
			if sh.open {
				kind = "open"
			}
			out = append(out, ts25Case{fmt.Sprintf("%s_%d", sh.name, sp.n), sp.n, kind,
				ts25Fills(sp.size, sp.acts, sh.ub, sh.ua),
				func() []string { return slices.Repeat([]string{sh.gen(sp.size, sp.acts)}, sp.n) }})
		}
	}
	deep := ts25Parens(ts25MaxParen)
	for _, m := range []struct{ name, open string }{{"mix_if", "{{if 1}}"}, {"mix_range", "{{range 1}}"}, {"mix_with", "{{with 1}}"}} {
		out = append(out, ts25Mix(m.name, "open", ts25TmplActs,
			ts25Pad(strings.Repeat(m.open, ts25TmplActs-1)+deep, ts25TmplBytes)))
	}
	chain := "{{if 1}}" + strings.Repeat("{{else if 1}}", ts25TmplActs-3) + deep
	out = append(out, ts25Mix("mix_elseif", "balanced", ts25TmplActs, ts25Pad(chain, ts25TmplBytes-7)+"{{end}}"),
		ts25Mix("mix_parens", "balanced", 4, ts25ParensFill(ts25TmplBytes)))
	act := strings.Repeat("{{1}}", ts25TmplActs)
	for _, o := range []struct {
		name  string
		texts func() []string
	}{
		{"over_template_bytes", func() []string { return []string{strings.Repeat("a", ts25TmplBytes+1)} }},
		{"over_template_actions", func() []string { return []string{act + "{{1}}"} }},
		{"over_bundle_bytes", func() []string {
			return append(slices.Repeat([]string{strings.Repeat("a", ts25TmplBytes)}, ts25BundleBytes/ts25TmplBytes), "a")
		}},
		{"over_bundle_actions", func() []string {
			return append(slices.Repeat([]string{act}, ts25BundleActs/ts25TmplActs), "{{1}}")
		}},
		{"nested_if_4MiB", func() []string { return []string{strings.Repeat("{{if 1}}", ts25EntryBytes/8)} }},
	} {
		out = append(out, ts25Case{name: o.name, kind: "over", texts: o.texts})
	}
	return out
}

type ts25Result struct {
	calls, set, gc, limit int
	perr                  bool
	hwm, kept             int64
	stack, nano, held     int64
}

// TestTS25CapConstants checks the caps in the code against SEC-29 and the
// archive caps. It also checks the depth of 9 999. A change then fails T-S-25.
func TestTS25CapConstants(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"maxTemplateBytes", maxTemplateBytes, ts25TmplBytes},
		{"maxTemplateActions", maxTemplateActions, ts25TmplActs},
		{"maxBundleBytes", maxBundleBytes, ts25BundleBytes},
		{"maxBundleActions", maxBundleActions, ts25BundleActs},
		{"MaxEntryBytes", MaxEntryBytes, ts25EntryBytes},
		{"MaxDecodedBytes", MaxDecodedBytes, ts25DecodedBytes},
		{"ts25Depth", ts25Depth, 9999},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d; T-S-25 needs %d", c.name, c.got, c.want)
		}
	}
}

// TestTS25TemplateParseMemory is T-S-25 for the caps of SEC-29. It starts one
// child process for each case.
func TestTS25TemplateParseMemory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the child reads /proc/self/status")
	}
	for _, c := range ts25Cases() {
		t.Run(c.name, func(t *testing.T) {
			if c.fills != nil {
				if msg := c.fills(c.texts()); msg != "" {
					t.Fatal(msg)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestTS25Child$", "-test.timeout=60s")
			// A later value replaces an earlier one with the same name.
			cmd.Env = append(os.Environ(), ts25Env+"="+c.name, ts25Marker+"=1",
				"GOMEMLIMIT="+strconv.Itoa(ts25Limit), "GOGC="+strconv.Itoa(ts25GC))
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("child: %v\n%.1024s", err, stderr.String())
			}
			var r ts25Result
			found := false
			for _, line := range strings.Split(stdout.String(), "\n") {
				if strings.HasPrefix(line, "TS25 ") {
					found = true
					if _, err := fmt.Sscanf(line, "TS25 calls=%d perr=%t hwm=%d kept=%d stack=%d ns=%d set=%d gc=%d limit=%d held=%d",
						&r.calls, &r.perr, &r.hwm, &r.kept, &r.stack, &r.nano, &r.set, &r.gc, &r.limit, &r.held); err != nil {
						t.Fatalf("result line %q: %v", line, err)
					}
				}
			}
			if !found {
				t.Fatalf("no result line in the child output\n%.1024s", stdout.String())
			}
			took := time.Duration(r.nano)
			t.Logf("case %s: VmHWM %.1f MB, kept %.1f MiB, StackSys %.1f MiB, parse %.2f s",
				c.name, float64(r.hwm)/1e6, float64(r.kept)/(1<<20), float64(r.stack)/(1<<20), took.Seconds())
			if r.held != 24<<20 {
				t.Errorf("child holds %d bytes of bundle data; T-S-25 needs %d", r.held, 24<<20)
			}
			if r.gc != ts25GC || r.limit != ts25Limit {
				t.Errorf("child GC percent %d and memory limit %d; want %d and %d", r.gc, r.limit, ts25GC, ts25Limit)
			}
			// A case that a cap refuses by mistake is a test bug, not a pass.
			bad := r.perr != (c.kind != "balanced")
			switch c.kind {
			case "over":
				bad = bad || r.calls != 0
			case "open":
				bad = bad || r.calls < 1
			default:
				bad = bad || r.calls != c.n || r.set != c.n
			}
			if bad {
				t.Errorf("%d constructor calls, %d kept templates, template_parse %v; want a %s case of %d templates",
					r.calls, r.set, r.perr, c.kind, c.n)
			}
			if ts25Race {
				return
			}
			if r.hwm > ts25HWMMax {
				t.Errorf("VmHWM %d bytes; want at most %d", r.hwm, ts25HWMMax)
			}
			if r.kept > ts25KeptMax {
				t.Errorf("kept heap %d bytes; want at most %d", r.kept, ts25KeptMax)
			}
			if took > ts25ParseMax {
				t.Errorf("parse took %v; want at most %v", took, ts25ParseMax)
			}
		})
	}
}

// TestTS25Child is the child process of one case. It skips if
// PHANTOM_TS25_CASE or the marker is not set. Only the parent sets them.
func TestTS25Child(t *testing.T) {
	name := os.Getenv(ts25Env)
	if name == "" || os.Getenv(ts25Marker) == "" {
		t.Skip("child process of TestTS25TemplateParseMemory")
	}
	cases := ts25Cases()
	i := slices.IndexFunc(cases, func(c ts25Case) bool { return c.name == name })
	if i < 0 {
		t.Fatalf("no case %q", name)
	}
	gc := debug.SetGCPercent(-1)
	debug.SetGCPercent(gc)
	limit := debug.SetMemoryLimit(-1)
	a, hold := ts25Archive(cases[i].texts())
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	calls := 0
	start := time.Now()
	set, err := parseWith(a, func(n string) *template.Template { calls++; return newTemplate(n) })
	took := time.Since(start)
	runtime.ReadMemStats(&after) // read the stack before a GC shrinks it
	stack := after.StackSys
	runtime.GC()
	runtime.ReadMemStats(&after)
	held := len(hold)
	for _, b := range a.files {
		held += len(b)
	}
	fmt.Printf("TS25 calls=%d perr=%t hwm=%d kept=%d stack=%d ns=%d set=%d gc=%d limit=%d held=%d\n",
		calls, err == ErrTemplateParse, ts25VmHWM(t), int64(after.HeapInuse)-int64(before.HeapInuse),
		stack, took.Nanoseconds(), len(set), gc, limit, held)
	runtime.KeepAlive(set)
	runtime.KeepAlive(a)
	runtime.KeepAlive(hold)
}

// ts25Archive makes an archive with one file for each text. A fill file brings
// it to ts25DecodedBytes (8 MiB). The second result is the rest of the 24 MiB.
func ts25Archive(texts []string) (*Archive, []byte) {
	a := &Archive{files: map[string][]byte{}}
	total := 0
	for i, s := range texts {
		n := fmt.Sprintf("vhosts/h.example/%04d.tmpl", i)
		a.files[n] = []byte(s)
		a.names = append(a.names, n)
		total += len(s)
	}
	a.files["assets/fill.bin"] = bytes.Repeat([]byte("x"), ts25DecodedBytes-total)
	a.names = append(a.names, "assets/fill.bin")
	slices.Sort(a.names)
	return a, bytes.Repeat([]byte("y"), ts25Held)
}

// ts25VmHWM reads the peak resident set size, in bytes, from /proc.
func ts25VmHWM(t *testing.T) int64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "VmHWM:" {
			kb, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return kb << 10
		}
	}
	t.Fatal("no VmHWM line in /proc/self/status")
	return 0
}
