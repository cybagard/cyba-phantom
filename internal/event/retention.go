package event

import "errors"

// RetentionCounts is the detail of a retention event: what one retention run
// did. Each member is an integer. A count is the number of rows that the
// statements of the run changed. It is never a cost.
//
//   - IP: session rows whose address the 7-day step set to NULL.
//   - Fields: event rows whose fields the field clear changed.
//   - Rolled: request rows that the roll-up step deleted.
//   - Deleted: refused, beacon, mint, ip_counter, event, token and session
//     rows that the delete statements removed. rollup_seen and meta rows are
//     not in it.
//   - Evicted and Vacuumed: rows that the database cap removed, and the pages
//     that it freed. They are 0 while no cap step exists.
//   - CutoffIP and CutoffRaw: the cutoff of the address step and the raw
//     cutoff of the run, in unix ms.
type RetentionCounts struct {
	IP, Fields, Rolled, Deleted, Evicted, Vacuumed int64
	CutoffIP, CutoffRaw                            int64
}

// retentionMembers are the only members that the detail of a retention event
// can have.
var retentionMembers = map[string]bool{
	"ip": true, "fields": true, "rolled": true, "deleted": true,
	"evicted": true, "vacuumed": true, "cutoff_ip": true, "cutoff_raw": true,
}

// detail returns the detail of a retention event, with all eight members.
func (c RetentionCounts) detail() Detail {
	return Detail{
		"ip": Int(c.IP), "fields": Int(c.Fields), "rolled": Int(c.Rolled),
		"deleted": Int(c.Deleted), "evicted": Int(c.Evicted),
		"vacuumed": Int(c.Vacuumed), "cutoff_ip": Int(c.CutoffIP),
		"cutoff_raw": Int(c.CutoffRaw),
	}
}

// NewRetentionEvent makes the retention event of one run. The event has no
// session. It returns an error when a count is outside +-(2^53-1).
func NewRetentionEvent(now Clock, c RetentionCounts) (*Event, error) {
	return NewEvent(now, Input{Kind: KindRetention, Detail: c.detail()})
}

var errRetentionDetail = errors.New("event: the detail of a retention event has only the eight integer members")

// checkRetentionDetail refuses a member that is not one of the eight, and a
// text value. The canonical encoder in NewEvent refuses an integer outside
// +-(2^53-1).
func checkRetentionDetail(d Detail) error {
	for k, v := range d {
		if !retentionMembers[k] || v.tag != 'i' {
			return errRetentionDetail
		}
	}
	return nil
}
