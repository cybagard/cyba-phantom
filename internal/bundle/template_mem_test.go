package bundle

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// T-S-25: the peak memory and the time of the template parse at the caps. Each
// case runs in its own child process, so that VmHWM is for that case only.
// With -race, every case still runs and the parent checks the parse result and
// the exit status. It checks the VmHWM, kept heap and time lines only without
// -race, because the detector adds memory and time.

const (
	ts25Env      = "PHANTOM_TS25_CASE"
	ts25HWMMax   = 140_000_000
	ts25KeptMax  = 56 << 20
	ts25ParseMax = 5 * time.Second
	ts25Held     = 16 << 20 // the file bytes and the running bundle
)

// ts25Splits are the numbers of templates, with the size and the "{{" count of
// each template. All of them fill the bundle caps, or the template caps.
var ts25Splits = []struct{ n, size, acts int }{
	{1, 64 << 10, 4096}, {8, 64 << 10, 2048}, {16, 32 << 10, 1024}, {1024, 512, 16},
}

type ts25Shape struct {
	name string
	open bool // no {{end}}: the parse gives an error
	gen  func(size, acts int) string
}

// ts25Fill joins units of open(i) until the next unit goes over size bytes or
// acts "{{". Each unit is followed, at the end, by one shut.
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

func ts25Parens(d int) string {
	return "{{" + strings.Repeat("(", d) + "1" + strings.Repeat(")", d) + "}}"
}

func ts25Shapes() []ts25Shape {
	var out []ts25Shape
	nest := func(name string, open func(int) string) {
		out = append(out,
			ts25Shape{name, false, func(size, acts int) string { return ts25Fill(size, acts, open, "{{end}}") }},
			ts25Shape{name + "-open", true, func(size, acts int) string { return ts25Fill(size, acts, open, "") }})
	}
	for _, c := range []string{"if", "range", "with"} {
		nest(c, ts25Const("{{"+c+" 1}}"))
	}
	nest("block", func(i int) string { return fmt.Sprintf(`{{block "b%d" .}}`, i) })
	return append(out,
		ts25Shape{"parens", false, func(size, acts int) string {
			return ts25Fill(size, acts, ts25Const(ts25Parens(min(9999, (size-5)/2))), "")
		}},
		ts25Shape{"num", false, ts25Flat("{{1}}")},
		ts25Shape{"dot", false, ts25Flat("{{.}}")},
		ts25Shape{"field", false, ts25Flat("{{.A.B}}")},
		ts25Shape{"adot", false, ts25Flat("a{{.}}")},
		ts25Shape{"text", false, ts25Flat("a")},
		ts25Shape{"define", false, func(size, acts int) string {
			return ts25Fill(size, acts, func(i int) string { return fmt.Sprintf(`{{define "d%d"}}x{{end}}`, i) }, "")
		}},
		ts25Shape{"args", false, func(size, _ int) string {
			return "{{print" + strings.Repeat(" 1", (size-9)/2) + "}}"
		}},
		ts25Shape{"pipe", false, func(size, _ int) string {
			return "{{1" + strings.Repeat("|print", (size-5)/6) + "}}"
		}},
		// Many declarations, then many uses of the last one. A use scans the
		// declared names from the first.
		ts25Shape{"vars", false, func(size, _ int) string {
			m := (size - 17) / 2 / 8
			return "{{print" + strings.Repeat(" ($a:=1)", m) + " ($b:=1)" +
				strings.Repeat(" $b", (size-17-8*m)/3) + "}}"
		}},
		ts25Shape{"vars2", false, func(size, acts int) string {
			m := min(acts-2, size/2/9)
			return strings.Repeat("{{$a:=1}}", m) + "{{$b:=1}}" +
				"{{print" + strings.Repeat(" $b", (size-18-9*m)/3) + "}}"
		}},
		ts25Shape{"nestparens", true, func(size, acts int) string {
			opens := strings.Repeat("{{if 1}}", acts-1)
			return opens + ts25Parens(min(9999, (size-len(opens)-5)/2))
		}})
}

type ts25Case struct {
	name  string
	shape string
	split int
	n     int  // templates that the constructor must make
	open  bool // the parse gives an error after at least one constructor call
	over  bool // a cap refuses the bundle before the first constructor call
	texts func() []string
}

func ts25Cases() []ts25Case {
	var out []ts25Case
	for _, sh := range ts25Shapes() {
		for _, sp := range ts25Splits {
			out = append(out, ts25Case{
				name: fmt.Sprintf("%s_%d", sh.name, sp.n), shape: sh.name, split: sp.n, n: sp.n, open: sh.open,
				texts: func() []string { return slices.Repeat([]string{sh.gen(sp.size, sp.acts)}, sp.n) },
			})
		}
	}
	act := strings.Repeat("{{1}}", maxTemplateActions)
	for _, o := range []struct {
		name  string
		texts func() []string
	}{
		{"over_template_bytes", func() []string { return []string{strings.Repeat("a", maxTemplateBytes+1)} }},
		{"over_template_actions", func() []string { return []string{act + "{{1}}"} }},
		{"over_bundle_bytes", func() []string {
			return append(slices.Repeat([]string{strings.Repeat("a", maxTemplateBytes)}, 8), "a")
		}},
		{"over_bundle_actions", func() []string { return append(slices.Repeat([]string{act}, 4), "{{1}}") }},
		{"nested_if_4MiB", func() []string { return []string{strings.Repeat("{{if 1}}", MaxEntryBytes/8)} }},
	} {
		out = append(out, ts25Case{name: o.name, shape: o.name, over: true, texts: o.texts})
	}
	return out
}

type ts25Result struct {
	calls       int
	perr        bool
	hwm, kept   int64
	stack, nano int64
}

// TestTS25TemplateParseMemory starts one child process for each case.
func TestTS25TemplateParseMemory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the child reads /proc/self/status")
	}
	for _, c := range ts25Cases() {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestTS25Child$")
			// A later value replaces an earlier one with the same name.
			cmd.Env = append(os.Environ(), ts25Env+"="+c.name, "GOMEMLIMIT=256MiB", "GOGC=50")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("child: %v\n%.1024s", err, stderr.String())
			}
			var r ts25Result
			for _, line := range strings.Split(stdout.String(), "\n") {
				if strings.HasPrefix(line, "TS25 ") {
					if _, err := fmt.Sscanf(line, "TS25 calls=%d perr=%t hwm=%d kept=%d stack=%d ns=%d",
						&r.calls, &r.perr, &r.hwm, &r.kept, &r.stack, &r.nano); err != nil {
						t.Fatalf("result line %q: %v", line, err)
					}
				}
			}
			took := time.Duration(r.nano)
			t.Logf("shape %s, split %d: VmHWM %.1f MB, kept %.1f MiB, StackSys %.1f MiB, parse %.2f s",
				c.shape, c.split, float64(r.hwm)/1e6, float64(r.kept)/(1<<20), float64(r.stack)/(1<<20), took.Seconds())
			// A case that a cap refuses by mistake is a test bug, not a pass.
			switch {
			case c.over && !(r.perr && r.calls == 0):
				t.Errorf("%d constructor calls, template_parse %v; want 0 and true", r.calls, r.perr)
			case c.open && !(r.perr && r.calls >= 1):
				t.Errorf("%d constructor calls, template_parse %v; want 1 or more and true", r.calls, r.perr)
			case !c.over && !c.open && !(!r.perr && r.calls == c.n):
				t.Errorf("%d constructor calls, template_parse %v; want %d and false", r.calls, r.perr, c.n)
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

// TestTS25Child is the child process of one case. It skips without its
// variable.
func TestTS25Child(t *testing.T) {
	name := os.Getenv(ts25Env)
	if name == "" {
		t.Skip("child process of TestTS25TemplateParseMemory")
	}
	i := slices.IndexFunc(ts25Cases(), func(c ts25Case) bool { return c.name == name })
	if i < 0 {
		t.Fatalf("no case %q", name)
	}
	a, hold := ts25Archive(ts25Cases()[i].texts())
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
	fmt.Printf("TS25 calls=%d perr=%t hwm=%d kept=%d stack=%d ns=%d\n", calls, err == ErrTemplateParse,
		ts25VmHWM(t), int64(after.HeapInuse)-int64(before.HeapInuse), stack, took.Nanoseconds())
	runtime.KeepAlive(set)
	runtime.KeepAlive(a)
	runtime.KeepAlive(hold)
}

// ts25Archive makes an archive with one file for each text. A fill file brings
// it to MaxDecodedBytes. The second result is the rest of the 24 MiB.
func ts25Archive(texts []string) (*Archive, []byte) {
	a := &Archive{files: map[string][]byte{}}
	total := 0
	for i, s := range texts {
		n := fmt.Sprintf("vhosts/h.example/%04d.tmpl", i)
		a.files[n] = []byte(s)
		a.names = append(a.names, n)
		total += len(s)
	}
	a.files["assets/fill.bin"] = bytes.Repeat([]byte("x"), MaxDecodedBytes-total)
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
