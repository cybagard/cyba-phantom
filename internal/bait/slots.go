package bait

import (
	"net/http"
	"strings"
)

// maxSlotValue is the most bytes of a header slot value (ADR-035).
const maxSlotValue = 1024

// slotHeader is a header slot of one response, with its value checked. name is
// in canonical form. val is the one value.
type slotHeader struct {
	name string
	val  []string
}

// validSlotValue reports whether v can be a header value. It has at most
// maxSlotValue bytes. Each byte is in 0x20 to 0x7E, so tab is not valid.
func validSlotValue(v string) bool {
	if len(v) > maxSlotValue {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7E {
			return false
		}
	}
	return true
}

// putSlots adds each slot to hd. It skips a slot whose name is in hd already,
// with case ignored. So a slot never replaces or repeats a header that the
// engine set before. The slots written first count for the next ones. The
// check covers only the names in hd. The load rule permits only X- names,
// so a slot cannot name Content-Length or Allow.
func putSlots(hd http.Header, slots []slotHeader) {
	for _, s := range slots {
		taken := false
		for k := range hd {
			if strings.EqualFold(k, s.name) {
				taken = true
				break
			}
		}
		if !taken {
			hd[s.name] = s.val
		}
	}
}

// addSlots writes the slot headers of m to hd. It adds the number of slots
// that m leaves out to slotDrops. Call it after the fixed headers.
func (h *Handler) addSlots(hd http.Header, m *minted) {
	putSlots(hd, m.slots)
	if m.left > 0 {
		h.slotDrops.Add(int64(m.left))
	}
}
