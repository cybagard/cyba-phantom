package bait

import (
	"bytes"
	"errors"
	"strings"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// planBudget is the most bytes that the plans of one site keep (SEC-32). A plan
// counts as the bytes that it allocates, so the budget bounds the heap. See
// plan.size.
const planBudget = 4 << 20

// planHeader is the heap size of the plan struct. The struct has 72 bytes. The
// allocator gives it the size class of 80 bytes. A test checks this.
const planHeader = 80

// maxActs is the most trap actions of a template. The loader refuses more.
const maxActs = 64

// maxTokText is the most bytes of a token text that a plan page writes. The
// text of a token has 26 bytes.
const maxTokText = 32

// alphabet is the token alphabet (internal/token). Each marker holds all of it.
const alphabet = "abcdefghijklmnopqrstuvwxyz234567"

// The first and last character of a marker in the two marker runs. Run 0 uses
// hex digits and run 1 uses letters that are not hex digits. The escape of a
// CSS string depends on this class of the first character of a token.
var markerEdges = [2][2]byte{{'a', '7'}, {'q', 'z'}}

// plan is the output of one template with a marker in place of each token. A
// request writes the fixed bytes and the token text at each cut, with no
// Execute. Cut i is at offs[i] in fixed. acts[i] is the position of its action
// in the action list of the template.
type plan struct {
	fixed []byte
	offs  []uint32
	acts  []uint8
}

// size is the count of the plan against the budget. It is the heap that the
// plan keeps. It has four parts. The first is the capacity of fixed, at 1
// byte each. The second is the capacity of offs, at 4 bytes each. The third
// is the capacity of acts, at 1 byte each. The last is planHeader. cut makes
// each array with append. So its capacity is
// the size class that the allocator gave it. An array of 1 to 15 bytes can
// use a block of 16 bytes. So each array counts at least 16 bytes.
func (p *plan) size() int {
	return heapBytes(cap(p.fixed)) + heapBytes(4*cap(p.offs)) + heapBytes(cap(p.acts)) + planHeader
}

// heapBytes is the heap that n bytes of one slice can use.
func heapBytes(n int) int {
	if n == 0 {
		return 0
	}
	return max(n, 16)
}

// markerOf gives the marker of action act in marker run run. It has an edge
// character, the alphabet, two characters that give act, and a last edge
// character.
func markerOf(act, run int) string {
	return string(markerEdges[run][0]) + alphabet + string(alphabet[act>>5&31]) + string(alphabet[act&31]) + string(markerEdges[run][1])
}

// errPlanOver is the error of a marker run that passes its cap.
var errPlanOver = errors.New("bait: plan over the budget")

// runWriter keeps the output of a marker run. It refuses a write that would
// take the output over max.
type runWriter struct {
	buf  bytes.Buffer
	max  int
	peak int
}

func (w *runWriter) Write(p []byte) (int, error) {
	if len(p) > w.max-w.buf.Len() {
		return 0, errPlanOver
	}
	w.buf.Write(p)
	w.peak = max(w.peak, w.buf.Len())
	return len(p), nil
}

// planner builds the plans of one site. left is the budget that is left.
type planner struct {
	b     *bundle.Bundle
	traps []bundle.Trap
	left  int
	plans map[string]*plan // a nil plan means the template has none
	w     runWriter
	runs  int // marker runs, for a test
}

func newPlanner(b *bundle.Bundle, traps []bundle.Trap, budget int) *planner {
	return &planner{b: b, traps: traps, left: budget, plans: map[string]*plan{}}
}

// of gives the plan of the template name, or nil. It builds the plan at the
// first call for a name. acts are the key-set indexes of its trap actions.
func (p *planner) of(name string, acts []int) *plan {
	if p == nil || name == "" {
		return nil
	}
	if pl, ok := p.plans[name]; ok {
		return pl
	}
	var pl *plan
	if p.left > 0 && len(acts) <= maxActs {
		pl = p.build(name, acts)
	}
	p.plans[name] = pl
	return pl
}

// build makes the plan with two marker runs. It gives nil in these cases.
// A run fails, a marker does not come back exactly, or the two runs differ.
// A marker in the template text or in a trap text also gives nil, with no
// separate check. A marker of one run has the wrong edge characters in the
// other run. An extra marker in the output breaks the count in cut.
// It also gives nil for a plan over the budget that is left. A run writes 36
// bytes for a cut that counts 5 or more. So a plan near the end of the
// budget can fail at the cap of its run.
func (p *planner) build(name string, acts []int) *plan {
	var runs [2]*plan
	for run := range runs {
		page := bundle.Page{Trap: make(map[string]string, len(acts))}
		var want []uint8
		for i, ix := range acts {
			m := markerOf(i, run)
			t := p.traps[ix]
			page.Trap[t.ID] = t.Render(m)
			for range strings.Count(page.Trap[t.ID], m) {
				want = append(want, uint8(i))
			}
		}
		p.w.buf.Reset()
		p.w.max = p.left
		p.runs++
		if p.b.Execute(&p.w, name, page) != nil {
			return nil
		}
		if runs[run] = cut(p.w.buf.Bytes(), run, want); runs[run] == nil {
			return nil
		}
	}
	a, c := runs[0], runs[1]
	// cut checks the actions of each run against the same list. So the two
	// action lists are equal here, and so are the two cut counts.
	if !bytes.Equal(a.fixed, c.fixed) {
		return nil
	}
	for i := range a.offs {
		if a.offs[i] != c.offs[i] {
			return nil
		}
	}
	if a.size() > p.left {
		return nil
	}
	p.left -= a.size()
	return a
}

// cut splits the output of a marker run at its markers. It gives nil if the
// markers are not those of want, in this order, or if one is not exact.
func cut(out []byte, run int, want []uint8) *plan {
	pl := &plan{fixed: make([]byte, 0, len(out))}
	for {
		k := bytes.Index(out, []byte(alphabet))
		if k < 0 {
			break
		}
		end := k + len(alphabet) + 3
		if k < 1 || end > len(out) || out[k-1] != markerEdges[run][0] || out[end-1] != markerEdges[run][1] {
			return nil
		}
		hi, lo := strings.IndexByte(alphabet, out[end-3]), strings.IndexByte(alphabet, out[end-2])
		if hi < 0 || lo < 0 || hi<<5|lo >= maxActs {
			return nil
		}
		pl.fixed = append(pl.fixed, out[:k-1]...)
		pl.offs = append(pl.offs, uint32(len(pl.fixed)))
		pl.acts = append(pl.acts, uint8(hi<<5|lo))
		out = out[end:]
	}
	if !bytes.Equal(pl.acts, want) {
		return nil
	}
	// append rounds the capacity up to the size class, so cap shows the heap.
	fixed := append(pl.fixed, out...)
	return &plan{
		fixed: append([]byte(nil), fixed...),
		offs:  append([]uint32(nil), pl.offs...),
		acts:  append([]uint8(nil), pl.acts...),
	}
}

// write writes the page of p to w. toks gives the token text of each action.
func (p *plan) write(w *capWriter, toks *[maxActs]string) error {
	prev := 0
	for i, off := range p.offs {
		if _, err := w.Write(p.fixed[prev:off]); err != nil {
			return err
		}
		if err := w.writeString(toks[p.acts[i]]); err != nil {
			return err
		}
		prev = int(off)
	}
	_, err := w.Write(p.fixed[prev:])
	return err
}
