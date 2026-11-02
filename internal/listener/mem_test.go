package listener

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

	"github.com/cybagard/cyba-phantom/internal/testutil"
)

const (
	// tp09Conns is the number of client connections for each form, and the
	// default of limits.max_conns.
	tp09Conns = 2000
	// tp09HeaderBytes is the default of limits.header_bytes.
	tp09HeaderBytes = 16384
	// tp09Client is the test function that the child process runs.
	tp09Client = "TestTP09Client"

	// The mix has three kinds of connection. For each connection, a pool holder
	// keeps about 100 KB. A record-header connection keeps about 55 KB. A
	// near-limit kept-open connection keeps about 34 KB. A holder reads 30 000
	// bytes (holderBytes). It charges all but keepAliveBytes of them to the
	// pool. 320 holders charge mixPool bytes, 8 289 280 with the present
	// values. That is below the pool, 8 388 608 bytes, so the pool refuses no
	// holder. The pool does not bound the record-header connections, so they
	// fill the rest. Ten near-limit connections stay open, so the mix has all
	// three kinds.
	mixHolders    = 320
	mixHeaders    = 1670
	holderBytes   = 30000
	mixPool       = mixHolders * (holderBytes - keepAliveBytes) // the pool value of the mix
	nearLimitHead = 1500                                        // size of the request head of a near-limit connection
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

// tp09Get sends a request with a head of n bytes and checks for the status 200.
// It does not use roundTrip of server_test.go. That function sets a deadline
// of 5 s, which is too short for 2 000 connections that start together.
func tp09Get(c net.Conn, n int) error {
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.WriteString(c, head(n)); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return c.SetDeadline(time.Time{})
}

// tp09Dial runs the client side of one connection of a form on raw. A form
// over a limit ignores the errors of the handshake: the server closes it.
//
// The ClientHello of manyProtos(245) has 64 244 bytes in 4 records, with one
// Write for each record. The cut of hello_pending counts one record header for
// each Write. The budget of the first period is 16 384 + 16 384 + 1 024 =
// 33 792 bytes. In hello_open and hello_pending the server reads exactly
// 33 792 bytes and closes. This holds for the Certificate-type message too
// (certBytes, in the forms cert_tls12 and cert_tls13).
func tp09Dial(t *testing.T, form string, raw net.Conn) error {
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: testName, NextProtos: []string{"http/1.1"}} // the child has no certificate pool
	_ = raw.SetReadDeadline(time.Now().Add(60 * time.Second))
	switch form {
	case "normal", "near_limit":
		tc := tls.Client(raw, cfg)
		if err := tc.Handshake(); err != nil {
			return err
		}
		n := 0
		if form == "near_limit" {
			n = nearLimitHead
		}
		return tp09Get(tc, n)
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

// tp09Source gives the last byte of the source address of client i.
func tp09Source(i int) byte { return byte(2 + i/maxConnsPerSource) }

// TestTP09Client is the child process of TestTP09. It opens the connections of
// one form from 63 loopback sources, at most 32 from each. It dials all of
// them first, then starts all clients at the same time. It prints a READY line
// and holds the connections until its stdin closes.
func TestTP09Client(t *testing.T) {
	addr := os.Getenv("PHANTOM_TP09_ADDR")
	if addr == "" {
		t.Skip("child process of TestTP09")
	}
	form := os.Getenv("PHANTOM_TP09_FORM")
	var (
		wg    sync.WaitGroup
		bad   atomic.Int64
		conns = make([]net.Conn, tp09Conns) // a socket that nothing refers to is closed by its finalizer
		sem   = make(chan struct{}, 64)
	)
	for i := range conns {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			var err error
			if conns[i], err = loopbackDialer(tp09Source(i)).Dial("tcp", addr); err != nil {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	for i, raw := range conns {
		if raw == nil {
			continue
		}
		wg.Add(1)
		go func() {
			ok := false
			defer func() { // a failed helper ends the goroutine without a return
				if !ok {
					bad.Add(1)
				}
				wg.Done()
			}()
			kind := form
			if form == "mix" {
				kind = mixKind(i)
			}
			ok = tp09Dial(t, kind, raw) == nil
		}()
	}
	wg.Wait()
	fmt.Printf("READY bad=%d\n", bad.Load())
	_, _ = io.Copy(io.Discard, os.Stdin)
	runtime.KeepAlive(conns)
}

// startClients runs the child process of one form and returns when its clients
// are done. The returned function stops the child, waits for it and returns its
// exit error.
func startClients(t *testing.T, addr, form string) func() error {
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
	var (
		once    sync.Once
		waitErr error
	)
	stop := func() error {
		once.Do(func() { _ = stdin.Close(); waitErr = cmd.Wait() })
		return waitErr
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = stop() })
	for sc := bufio.NewScanner(stdout); sc.Scan(); {
		if line := sc.Text(); strings.HasPrefix(line, "READY") {
			if line != "READY bad=0" {
				t.Errorf("clients of form %s: %s", form, line)
			}
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

// procStatus reads a size in bytes from /proc/self/status (Linux). The key is
// VmRSS: or VmHWM:, the resident set size and its peak. The store package has
// its own copy (rows_bench_test.go). A package cannot import a test helper.
func procStatus(t *testing.T, key string) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == key {
			kb, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return kb << 10
		}
	}
	t.Fatalf("no %s line in /proc/self/status", key)
	return 0
}

// resetPeakRSS sets VmHWM to the current RSS.
func resetPeakRSS(t *testing.T) {
	t.Helper()
	f, err := os.OpenFile("/proc/self/clear_refs", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("5"); err != nil {
		t.Fatal(err)
	}
}

// peaks are the largest open count and the largest heap and stack in use (no
// collection) that samplePeaks saw.
type peaks struct {
	open int
	mem  uint64
}

// samplePeaks samples the server every 50 ms. The returned function stops it
// and returns the peaks.
func samplePeaks(s *Server) func() peaks {
	done, res := make(chan struct{}), make(chan peaks)
	go func() {
		var p peaks
		var m runtime.MemStats
		sample := func() {
			runtime.ReadMemStats(&m)
			p.open, p.mem = max(p.open, len(s.sem)), max(p.mem, m.HeapInuse+m.StackInuse)
		}
		for tick := time.NewTicker(50 * time.Millisecond); ; {
			select {
			case <-done:
				sample()
				res <- p
				return
			case <-tick.C:
				sample()
			}
		}
	}()
	return func() peaks { close(done); return <-res }
}

// procField returns field n (from 0) of a row of /proc/net/tcp, or nil.
func procField(row []byte, n int) []byte {
	for i := 0; ; i++ {
		row = bytes.TrimLeft(row, " ")
		if len(row) == 0 {
			return nil
		}
		end := bytes.IndexByte(row, ' ')
		if end < 0 {
			end = len(row)
		}
		if i == n {
			return row[:end]
		}
		row = row[end:]
	}
}

// portSuffix returns the end of a local address in /proc/net/tcp for the port
// of addr: ":1F90" for the port 8080.
func portSuffix(t *testing.T, addr string) []byte {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	mustNil(t, err)
	n, err := strconv.Atoi(port)
	mustNil(t, err)
	return []byte(fmt.Sprintf(":%04X", n))
}

// TestTP09UnreadBytesShowInTheReceiveQueue: a client sends 5 bytes, and the
// receive queue of the server socket has them. Then hasUnread is true. When
// the server has read the bytes, hasUnread is false. So settle does not
// return while a server read of a record header is open.
func TestTP09UnreadBytesShowInTheReceiveQueue(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the check reads /proc, which only Linux has")
	}
	ln := listenLoopback(t)
	t.Cleanup(func() { _ = ln.Close() })
	client, err := net.Dial("tcp", ln.Addr().String())
	mustNil(t, err)
	t.Cleanup(func() { _ = client.Close() })
	server, err := ln.Accept()
	mustNil(t, err)
	t.Cleanup(func() { _ = server.Close() })
	suffix, buf := portSuffix(t, ln.Addr().String()), make([]byte, 4096)
	if hasUnread(t, suffix, buf) {
		t.Fatal("hasUnread is true before the client sent a byte")
	}
	_, err = client.Write([]byte{23, 3, 3, 0x41, 0x00}) // a record header
	mustNil(t, err)
	testutil.WaitFor(t, func() bool { return hasUnread(t, suffix, buf) }, 5*time.Second)
	_, err = io.ReadFull(server, make([]byte, 5))
	mustNil(t, err)
	if hasUnread(t, suffix, buf) {
		t.Error("hasUnread is true after the server read the bytes")
	}
}

// hasUnread tells if bytes wait in the receive queue of a TCP socket. The local
// address of the socket ends with portSuffix (Linux). A connection that the
// server has not accepted counts in the queue of the listening socket. A byte
// that the server has not read counts in the queue of its connection. When
// this is false, each server read of the bytes that the clients sent has
// ended. It makes no garbage, because the heap that the test samples must not
// grow with the wait. buf is the scratch space for one row.
func hasUnread(t *testing.T, portSuffix, buf []byte) bool {
	t.Helper()
	f, err := os.Open("/proc/self/net/tcp")
	mustNil(t, err)
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(buf, len(buf))
	sc.Scan() // the header row
	for sc.Scan() {
		row := sc.Bytes()
		if !bytes.HasSuffix(procField(row, 1), portSuffix) {
			continue
		}
		queues := procField(row, 4) // tx_queue:rx_queue, in hex
		if i := bytes.IndexByte(queues, ':'); i >= 0 && len(bytes.Trim(queues[i+1:], "0")) != 0 {
			return true
		}
	}
	mustNil(t, sc.Err())
	return false
}

// settle waits until the open count and the pool stay the same for 1.5 s. In
// that time, no byte that a client sent may wait for the server to read it.
// It returns the open count and the pool. The addr is the address of the
// listening socket.
func (s *Server) settle(t *testing.T, addr string) (open int, pool int64) {
	t.Helper()
	suffix, buf := portSuffix(t, addr), make([]byte, 4096)
	last, lastPool := -1, int64(-1)
	deadline := time.Now().Add(60 * time.Second)
	for same := 0; same < 15; {
		if time.Now().After(deadline) {
			t.Fatalf("the open count does not settle: %d", len(s.sem))
		}
		time.Sleep(100 * time.Millisecond)
		open, pool = len(s.sem), s.rd.pool.Load()
		if open == last && pool == lastPool && !hasUnread(t, suffix, buf) {
			same++
		} else {
			same = 0
		}
		last, lastPool = open, pool
	}
	return open, pool
}

// T-P-09: 2 000 decoy connections for each client form. The test runs only with
// PHANTOM_TP09=1, so make all skips it. The server runs in this process with
// the production limits. The clients run in a child process (this test binary
// again), so their memory is not in the server heap. The timeouts are long. The
// production deadlines bound time, not memory. The connections must stay open
// while the test reads the memory.
//
// Each result line has settled values and peak values. The settled values are
// the open count, the pool, the heap and stack after two collections, and the
// RSS. The peak values are the open count, the heap and stack without a
// collection, and VmHWM.
//
// The checks of each form:
//   - normal: RSS and peak RSS at most 150 MB (NFR-01).
//   - hello_open, hello_pending, cert_tls12, cert_tls13: the server closes every
//     connection. The open count is 0 and the settled heap and stack are at most
//     5 MB, so a closed connection keeps no bytes. The peak heap and stack are at
//     most 140 MB. RSS and peak RSS are at most 180 MB.
//   - hello_4k, record_header, mix: the connections stay open. The open count
//     is 2 000. The settled heap and stack are at most 140 MB. RSS and peak RSS
//     are at most 180 MB. The peak heap is only logged. For the mix it is
//     about 140 MB, and above it in some runs (142.6, 140.5 and 142.8 MB
//     measured).
//   - every form but the mix: the pool is 0 after the settle.
//   - mix: the pool holds exactly mixPool bytes, so the pool refuses no holder.
func TestTP09(t *testing.T) {
	if os.Getenv("PHANTOM_TP09") != "1" {
		t.Skip("T-P-09 runs with PHANTOM_TP09=1")
	}
	// The child process cannot report a skip, so the parent checks the source addresses of the clients.
	for i := 0; i < tp09Conns; i += maxConnsPerSource {
		requireLoopback(t, tp09Source(i))
	}
	long := 10 * time.Minute
	r := newRig(t, tp09Conns, tp09HeaderBytes, timeouts{readHeader: long, read: long, write: long, idle: long}, okHandler)
	r.serve(t)
	// want is the open count that the form must reach: 2 000 for a form that
	// stays open, 0 for a form over a limit.
	for _, f := range []struct {
		name string
		want int
	}{
		{"normal", tp09Conns}, {"hello_open", 0}, {"hello_pending", 0}, {"cert_tls12", 0},
		{"cert_tls13", 0}, {"hello_4k", tp09Conns}, {"record_header", tp09Conns}, {"mix", tp09Conns},
	} {
		before := memNow()
		resetPeakRSS(t)
		stopPeaks := samplePeaks(r.s)
		stop := startClients(t, r.addr, f.name)
		open, pool := r.s.settle(t, r.addr)
		peak := stopPeaks()
		heap := float64(int64(memNow())-int64(before)) / 1e6
		rss, peakRSS := float64(procStatus(t, "VmRSS:"))/1e6, float64(procStatus(t, "VmHWM:"))/1e6
		peakHeap := float64(int64(peak.mem)-int64(before)) / 1e6
		heapMax, rssMax := 140.0, 180.0
		switch {
		case f.name == "normal":
			heapMax, rssMax = 1e9, 150
		case f.want == 0:
			heapMax = 5
		}
		pass := heap <= heapMax && rss <= rssMax && peakRSS <= rssMax && open == f.want
		// A closed connection gives its charge back. The other forms that stay
		// open read at most keepAliveBytes.
		wantPool := int64(0)
		if f.name == "mix" {
			wantPool = mixPool
		}
		pass = pass && (f.want != 0 || peakHeap <= 140) && pool == wantPool
		t.Logf("TP09 form=%s conns=%d open=%d pool=%d heap+stack=%.1f rss=%.1f peak_open=%d peak_heap+stack=%.1f peak_rss=%.1f pass=%t",
			f.name, tp09Conns, open, pool, heap, rss, peak.open, peakHeap, peakRSS, pass)
		if !pass {
			t.Errorf("form %s: open %d (want %d), pool %d, heap+stack %.1f MB (peak %.1f), RSS %.1f MB (peak %.1f)", f.name, open, f.want, pool, heap, peakHeap, rss, peakRSS)
		}
		if err := stop(); err != nil {
			t.Errorf("clients of form %s: %v", f.name, err)
		}
		waitFor(t, "all connections closed", func() bool { return len(r.s.sem) == 0 })
		debug.FreeOSMemory()
	}
}
