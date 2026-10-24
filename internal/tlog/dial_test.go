package tlog

import (
	"errors"
	"testing"
	"time"

	"github.com/cybagard/cyba-phantom/internal/egress"
)

// releaseDialer gives the publisher the dialer of the release build, with no
// permitted test address.
func releaseDialer(c *publishConfig) { c.dialer = egress.Dialer(dialTimeout) }

// refusedPublish publishes one note and checks that the guard refuses it. The
// error has the class address refused. The target sees no connection. The error
// and the log have no address of the target.
func refusedPublish(t *testing.T, e *pubEnv, p *Publisher, a *fakeTarget) {
	t.Helper()
	e.add(t, 1)
	err := e.spool.Publish(0, p)
	if !errors.Is(err, errPublishAddress) {
		t.Fatalf("err = %v, want a refused address", err)
	}
	if n := a.connCount(); n != 0 {
		t.Fatalf("the target accepted %d connections, want none", n)
	}
	if attempts, _, _ := a.got(); len(attempts) != 0 {
		t.Fatal("the target got a request")
	}
	e.assertClean(t, "error", err.Error())
	e.assertClean(t, "log", e.logs.String())
}

// T-S-21, T-S-13: the dialer of the release build refuses a loopback test
// target. The target sees no connection.
func TestTS21_PublisherRefusesLoopbackTarget(t *testing.T) {
	a := newTarget(t)
	e := newPub(t, time.Minute, []*fakeTarget{a}, releaseDialer)
	refusedPublish(t, e, e.pub, a)
}

// T-S-13: the publisher has no address rule of its own. NewPublisher takes no
// option. It dials through the egress guard and refuses 127.0.0.1.
func TestTS13_NewPublisherRefusesLoopback(t *testing.T) {
	a := newTarget(t)
	e := newPub(t, time.Minute, []*fakeTarget{a})
	lg, buf := testLogger()
	p, err := NewPublisher(e.spool, []PublishTarget{{a.url(), tokenVar}}, time.Minute, lg)
	must(t, err)
	e.logs = buf
	refusedPublish(t, e, p, a)
}
