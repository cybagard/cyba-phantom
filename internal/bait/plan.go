package bait

import (
	"bytes"
	"errors"
	"strings"

	"github.com/cybagard/cyba-phantom/internal/bundle"
)

// planBudget is the most bytes that the plans of one site keep (SEC-32). A plan
// counts as the allocated size of its arrays and its struct. See plan.size.
// The heap that the plans keep is near this count.
const planBudget = 4 << 20

// planSlack is a part of the budget that the plans do not use. The heap of
// plans is near the count, and a full budget measured 4 KB above it. The build
// counts plans against planBudget less planSlack. So the heap stays under
// planBudget.
const planSlack = 16 << 10

// planWork is the most output bytes of all marker runs of one site build. A run
// that fails counts too. When the work is used, no more marker run starts.
// The factor is 4. At 2 times, the fill shape got 207 plans (3 990 400 bytes)
// and the most-cuts shape got 11. At 4 times, they got 455 (4 177 920 bytes)
// and 22. The escape-growth shape got 9 plans at both.
const planWork = 4 * planBudget

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

// The first two and the last two characters of a marker in the two marker runs.
// Run 0 uses hex digits and run 1 uses letters that are not hex digits. The
// class must hold for two characters at each end. An escaper can look at the
// neighbour bytes of a token. The URL normalizer keeps a "%" only before two
// hex digits (url.go:118). The CSS escape looks one byte ahead. No other
// escaper of go1.27.3 looks further into a value where a plan can exist.
var (
	markerStarts = [2]string{"a7", "qz"}
	markerEnds   = [2]string{"7a", "zq"}
)

// plan is the output of one template with a marker in place of each token. A
// request writes the fixed bytes and the token text at each cut, with no
// Execute. Cut i is at offs[i] in fixed. acts[i] is the position of its action
// in the action list of the template.
type plan struct {
	fixed []byte
	offs  []uint32
	acts  []uint8
}

// size is the count of the plan against the budget. It is the allocated size
// of the plan. It has four parts. The first is the capacity of fixed, at 1
// byte each. The second is the capacity of offs, at 4 bytes each. The third
// is the capacity of acts, at 1 byte each. The last is planHeader. cut makes
// each array with append. So its capacity is the size class that the
// allocator gave it. An array of 1 to 15 bytes can use a block of 16 bytes.
// So each array counts at least 16 bytes. The measured heap is near the count.
func (p *plan) size() int {
	return heapBytes(cap(p.fixed)) + heapBytes(4*cap(p.offs)) + heapBytes(cap(p.acts)) + planHeader
}

// heapBytes is the heap that n bytes of one array can use.
func heapBytes(n int) int {
	if n == 0 {
		return 0
	}
	return max(n, 16)
}

// markerWords are in each marker, after the first two characters. The filters
// of html/template refuse them. htmlNameFilter refuses an attribute name with
// src. cssValueFilter refuses a value with expression or mozbinding. So a
// marker never comes back in these two contexts. A template with an action
// there gets no plan, for each token. Such a filter looks at the whole value,
// so a marker run cannot show it.
const markerWords = "srcexpressionmozbinding"

// markerHead gives the first two characters and the words of a marker.
func markerHead(run int) string { return markerStarts[run] + markerWords }

// markerOf gives the marker of action act in marker run run. It has the head,
// the alphabet, two characters that give act, and a last edge character.
func markerOf(act, run int) string {
	return markerHead(run) + alphabet + string(alphabet[act>>5&31]) + string(alphabet[act&31]) + markerEnds[run]
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

// planner builds the plans of one site. left is the budget that is left. work
// is the run output that is left (planWork).
type planner struct {
	b     *bundle.Bundle
	traps []bundle.Trap
	left  int
	work  int
	plans map[string]*plan // a nil plan means the template has none
	w     runWriter
	// runs and runBytes count the marker runs and their output, for a test.
	runs, runBytes int
}

func newPlanner(b *bundle.Bundle, traps []bundle.Trap, budget int) *planner {
	return &planner{b: b, traps: traps, left: budget, work: planWork, plans: map[string]*plan{}}
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
	if p.left > 0 && p.work > 0 && len(acts) <= maxActs {
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
// Some filters of html/template look at the whole value. They refuse the
// marker, so it does not come back (see markerWords).
// It also gives nil for a plan over the budget that is left. A run writes 59
// bytes for a cut that counts 5 or more. So a plan near the end of the
// budget can fail at the cap of its run. The cap of a run is the smaller of
// the budget left and the work left. A run that fails counts as work.
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
		p.w.max = min(p.left, p.work)
		workCaps := p.work <= p.left
		p.runs++
		err := p.b.Execute(&p.w, name, page)
		p.runBytes += p.w.buf.Len()
		p.work -= p.w.buf.Len()
		if errors.Is(err, errPlanOver) && workCaps {
			// The work cap stopped the run, so no run can start.
			p.work = 0
		}
		if err != nil {
			return nil
		}
		if runs[run] = cut(p.w.buf.Bytes(), run, want); runs[run] == nil {
			return nil
		}
	}
	a, c := runs[0], runs[1]
	// cut checks each run against a list of actions with equal values. So the
	// two action lists are equal here, and so are the two cut counts. The
	// offsets compare is defensive: no escaper moves a byte across a token.
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
		end, lead := k+len(alphabet)+2+len(markerEnds[run]), len(markerStarts[run])+len(markerWords)
		if k < lead || end > len(out) || string(out[k-lead:k]) != markerHead(run) || string(out[end-len(markerEnds[run]):end]) != markerEnds[run] {
			return nil
		}
		hi, lo := strings.IndexByte(alphabet, out[k+len(alphabet)]), strings.IndexByte(alphabet, out[k+len(alphabet)+1])
		if hi < 0 || lo < 0 || hi<<5|lo >= maxActs {
			return nil
		}
		pl.fixed = append(pl.fixed, out[:k-lead]...)
		pl.offs = append(pl.offs, uint32(len(pl.fixed)))
		pl.acts = append(pl.acts, uint8(hi<<5|lo))
		out = out[end:]
	}
	if !bytes.Equal(pl.acts, want) {
		return nil
	}
	fixed := append(pl.fixed, out...)
	// append rounds each capacity up to the size class, so cap shows the heap.
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
