package token

// Positions is the number of texts in one Check call. A callback route has
// up to 4 positions (ADR-039 decision 6).
const Positions = 4

// Check parses and verifies the texts of the positions of one request. It
// loads the ring one time and reads the clock one time for all positions
// (ADR-039 decision 6). An empty text is an absent position.
//
// Each position does one decrypt for each key set of the ring. An absent text
// and a text that Parse refuses get these decrypts too. Such a position
// verifies the zero block. The time of a position can show if it holds a
// match, a parsed text or an absent text. A refused or absent position always
// gives the zero Result, and it does not count in Futures. Check does not
// allocate in steady state.
func (r *Ring) Check(texts [Positions]string) [Positions]Result {
	now := r.now()
	sets := r.active(r.cur.Load(), now)
	var out [Positions]Result
	buf := scratch.Get().(*[2 * Size]byte)
	for i, s := range texts {
		tok, ok := Parse(s)
		out[i] = r.verifyAt(buf, sets, now, tok, ok)
	}
	clear(buf[:])
	scratch.Put(buf)
	return out
}
