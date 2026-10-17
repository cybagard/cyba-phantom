package listener

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	// tp09Conns is the number of client connections for each form, and the
	// default of limits.max_conns.
	tp09Conns = 2000
	// tp09HeaderBytes is the default of limits.header_bytes.
	tp09HeaderBytes = 16384
	// tp09Client is the test function that the child process runs.
	tp09Client = "TestTP09Client"

	// The mix has three kinds of connection. 300 pool holders read about 30 000
	// bytes each, so that they charge about 26 KB each to the pool: together
	// they take most of the 8 MiB, and none of them is refused. 1 000 are
	// record-header connections, the largest part of the memory for each
	// connection. The 700 others are kept-open connections that read about
	// 3 200 bytes in the first period, below the 4 KiB that the pool does not
	// charge.
	mixHolders    = 300
	mixHeaders    = 1000
	holderBytes   = 30000
	nearLimitHead = 1500 // size of the request head of a near-limit connection
	// certBytes is the part of the Certificate-type message that the forms over
	// a limit send. It is more than the budget of the first period.
	certBytes = 50000
)

// errCut ends a handshake after the write that cutConn cuts.
var errCut = errors.New("handshake cut")

// cutConn changes the Writes of a client. cut returns the bytes to send for
// the Write p. When stop is true the Write fails after it, so the handshake
// ends at once and the socket stays open.
type cutConn struct {
	net.Conn
	cut func(p []byte) (send []byte, stop bool)
}

func (c *cutConn) Write(p []byte) (int, error) {
	send, stop := c.cut(p)
	if _, err := c.Conn.Write(send); err != nil {
		return 0, err
	}
	if stop {
		return 0, errCut
	}
	return len(p), nil
}

// mixKind gives the kind of connection number i of the mix.
func mixKind(i int) string {
	switch {
	case i < mixHolders:
		return "holder"
	case i < mixHolders+mixHeaders:
		return "record_header"
	}
	return "near_limit"
}

// tp09Dial runs the client side of one connection of a form on raw. A form
// over a limit ignores the errors of the handshake: the server closes it.
func tp09Dial(t *testing.T, form string, raw net.Conn) error {
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: testName, NextProtos: []string{"http/1.1"}} // the child has no certificate pool
	_ = raw.SetReadDeadline(time.Now().Add(20 * time.Second))
	switch form {
	case "normal", "near_limit":
		tc := tls.Client(raw, cfg)
		if err := tc.Handshake(); err != nil {
			return err
		}
		head := 0
		if form == "near_limit" {
			head = nearLimitHead
		}
		if got := status(tc, head); got != 200 {
			return fmt.Errorf("status %d", got)
		}
		return raw.SetDeadline(time.Time{})
	case "hello_open":
		cfg.NextProtos = manyProtos(245)
		_ = tls.Client(raw, cfg).Handshake()
	case "hello_pending":
		// The client sends the whole ClientHello but its last byte.
		cfg.NextProtos = manyProtos(245)
		need, got := 0, 0
		_ = tls.Client(&cutConn{Conn: raw, cut: func(p []byte) ([]byte, bool) {
			if need == 0 {
				need = 4 + (int(p[6])<<16 | int(p[7])<<8 | int(p[8]))
			}
			if got += len(p) - 5; got < need {
				return p, false
			}
			return p[:len(p)-1], true
		}}, cfg).Handshake()
	case "hello_4k":
		// The first record claims 18 432 bytes, the largest length. The client
		// sends 4 096 bytes of it.
		cfg.NextProtos = manyProtos(245)
		_ = tls.Client(&cutConn{Conn: raw, cut: func(p []byte) ([]byte, bool) {
			q := bytes.Clone(p[:4096])
			q[3], q[4] = 0x48, 0x00
			return q, true
		}}, cfg).Handshake()
	case "cert_tls12":
		cfg.MaxVersion = tls.VersionTLS12
		_ = tls.Client(&nthWrite{Conn: raw, at: 2, payload: plainRecords(certMessage()[:certBytes])}, cfg).Handshake()
	case "cert_tls13", "holder", "record_header":
		var keyLog bytes.Buffer
		cfg.MinVersion, cfg.KeyLogWriter = tls.VersionTLS13, &keyLog
		cc := &countConn{Conn: raw}
		tc := tls.Client(cc, cfg)
		if err := tc.Handshake(); err != nil {
			return err
		}
		if form == "record_header" { // the largest length of a TLS 1.3 record, and no more bytes
			_, err := raw.Write([]byte{23, 3, 3, 0x41, 0x00})
			return err
		}
		w := newRecordWriter(t, keyLog.String(), tc.ConnectionState().CipherSuite)
		msg := certMessage()[:certBytes]
		if form == "holder" { // two records of 22 bytes more than their message
			msg = certMessage()[:holderBytes-cc.n-44]
		}
		_, _ = raw.Write(w.handshake(msg)) // the server can close before the write ends
	default:
		return fmt.Errorf("unknown form %q", form)
	}
	return nil
}

// TestTP09Client is the child process of TestTP09. It opens the connections of
// one form from 63 loopback sources, at most 32 from each, prints a READY line
// and holds the connections until its stdin closes.
func TestTP09Client(t *testing.T) {
	addr := os.Getenv("PHANTOM_TP09_ADDR")
	if addr == "" {
		t.Skip("child process of TestTP09")
	}
	form := os.Getenv("PHANTOM_TP09_FORM")
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		held []net.Conn // a socket that nothing refers to is closed by its finalizer
		bad  atomic.Int64
		sem  = make(chan struct{}, 32)
	)
	for i := range tp09Conns {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			raw, err := loopbackDialer(byte(2+i/maxConnsPerSource)).Dial("tcp", addr)
			if err != nil {
				bad.Add(1)
				return
			}
			mu.Lock()
			held = append(held, raw)
			mu.Unlock()
			kind := form
			if form == "mix" {
				kind = mixKind(i)
			}
			if err := tp09Dial(t, kind, raw); err != nil {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	fmt.Printf("READY bad=%d\n", bad.Load())
	_, _ = io.Copy(io.Discard, os.Stdin)
	runtime.KeepAlive(held)
}

// startClients runs the child process of one form and returns when its clients
// are done. The returned function stops the child and waits for it.
func startClients(t *testing.T, addr, form string) func() {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+tp09Client+"$")
	cmd.Env = append(os.Environ(), "PHANTOM_TP09_ADDR="+addr, "PHANTOM_TP09_FORM="+form)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { _ = stdin.Close(); _ = cmd.Wait() }) }
	t.Cleanup(func() { _ = cmd.Process.Kill(); stop() })
	for sc := bufio.NewScanner(stdout); sc.Scan(); {
		if strings.HasPrefix(sc.Text(), "READY") {
			t.Logf("clients of form %s: %s", form, sc.Text())
			return stop
		}
	}
	t.Fatalf("clients of form %s: no READY line", form)
	return nil
}

// memNow returns the heap and stack in use after two collections.
func memNow() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse + m.StackInuse
}

// rssBytes reads the resident set size of this process (Linux).
func rssBytes(t *testing.T) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "VmRSS:" {
			kb, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return kb << 10
		}
	}
	t.Fatal("no VmRSS line in /proc/self/status")
	return 0
}

// settle waits until the open count and the pool stay the same for 1.5 s, and
// returns them.
func (s *Server) settle(t *testing.T) (open int, pool int64) {
	t.Helper()
	last, lastPool := -1, int64(-1)
	deadline := time.Now().Add(60 * time.Second)
	for same := 0; same < 15; {
		if time.Now().After(deadline) {
			t.Fatalf("the open count does not settle: %d", len(s.sem))
		}
		time.Sleep(100 * time.Millisecond)
		open, pool = len(s.sem), s.rd.pool.Load()
		if open == last && pool == lastPool {
			same++
		} else {
			same = 0
		}
		last, lastPool = open, pool
	}
	return open, pool
}

// T-P-09: 2 000 decoy connections for each client form. It runs only with
// PHANTOM_TP09=1, so it is not part of make all. The server runs in this
// process with the production limits. The clients run in a child process (this
// test binary again), so that their memory is not in the server heap. The
// timeouts are long: the production deadlines bound time, not memory, and the
// connections must stay open while the test reads the memory.
func TestTP09(t *testing.T) {
	if os.Getenv("PHANTOM_TP09") != "1" {
		t.Skip("T-P-09 runs with PHANTOM_TP09=1")
	}
	long := 10 * time.Minute
	r := newRig(t, tp09Conns, tp09HeaderBytes, timeouts{readHeader: long, read: long, write: long, idle: long}, okHandler)
	r.serve(t)
	// want is the open count that the form must reach: 2 000 for a form that
	// stays open, 0 for a form over a limit, -1 when the test only logs it.
	for _, f := range []struct {
		name string
		want int
	}{
		{"normal", tp09Conns}, {"hello_open", 0}, {"hello_pending", 0}, {"cert_tls12", 0},
		{"cert_tls13", 0}, {"hello_4k", tp09Conns}, {"record_header", tp09Conns}, {"mix", -1},
	} {
		before := memNow()
		stop := startClients(t, r.addr, f.name)
		open, pool := r.s.settle(t)
		heap := float64(int64(memNow())-int64(before)) / 1e6
		rss := float64(rssBytes(t)) / 1e6
		pass := heap <= 140 && rss <= 180
		if f.name == "normal" {
			pass = rss <= 150
		}
		pass = pass && (f.want < 0 || open == f.want)
		t.Logf("TP09 form=%s conns=%d open=%d pool=%d heap+stack=%.1f rss=%.1f pass=%t", f.name, tp09Conns, open, pool, heap, rss, pass)
		if !pass {
			t.Errorf("form %s: open %d (want %d), heap+stack %.1f MB, RSS %.1f MB", f.name, open, f.want, heap, rss)
		}
		stop()
		waitFor(t, "all connections closed", func() bool { return len(r.s.sem) == 0 })
		debug.FreeOSMemory()
	}
}
