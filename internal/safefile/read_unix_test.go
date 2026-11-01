//go:build unix && !aix && !solaris

package safefile

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// capRule is a rule for a file with a cap of 10 bytes.
var capRule = Rule{Type: Regular, Owner: OwnerSelf, MaxSize: 10}

// put writes content to the file name in dir.
func put(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// noLeak fails the test when the text of err holds one of the secrets.
func noLeak(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Error("no error to examine")
		return
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(err.Error(), s) {
			t.Errorf("error text %q holds %q", err, s)
		}
	}
}

func TestTS23_ReadFileCap(t *testing.T) {
	r, dir := root(t)
	put(t, dir, "at", "0123456789")
	put(t, dir, "over", "0123456789a")
	put(t, dir, "short", "012")
	put(t, dir, "empty", "")
	got, err := ReadFile(r, "at", capRule)
	if err != nil || string(got) != "0123456789" {
		t.Errorf("at the cap: %q, %v", got, err)
	}
	if _, err := ReadFile(r, "over", capRule); !errors.Is(err, ErrSize) {
		t.Errorf("cap + 1: err = %v, want ErrSize", err)
	}
	got, err = ReadFile(r, "short", capRule)
	if err != nil || string(got) != "012" {
		t.Errorf("under the cap: %q, %v", got, err)
	}
	got, err = ReadFile(r, "empty", capRule)
	if err != nil || len(got) != 0 {
		t.Errorf("empty file: %q, %v", got, err)
	}
	if _, err := ReadFile(r, "none", capRule); !errors.Is(err, ErrExamine) {
		t.Errorf("missing file: err = %v, want ErrExamine", err)
	}
	if _, err := ReadFile(r, "a/b", capRule); !errors.Is(err, ErrName) {
		t.Errorf("name with a slash: err = %v, want ErrName", err)
	}
}

func TestTS23_ReadAllGrowAfterOpen(t *testing.T) {
	r, dir := root(t)
	p := put(t, dir, "f", "0123456789")
	f, fi, err := Open(r, "f", capRule)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Open passed the file at the cap. ReadAll has its own cap.
	w, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("a"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if _, err := ReadAll(f, fi, capRule); !errors.Is(err, ErrSize) {
		t.Errorf("err = %v, want ErrSize", err)
	}
}

func TestTS23_ReadAllLimitsTheRead(t *testing.T) {
	r, dir := root(t)
	p := put(t, dir, "f", "0123456789")
	f, fi, err := Open(r, "f", capRule)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Open passed the file at the cap. The file then grows to 64 MiB. It is
	// sparse, so the test writes no data.
	const (
		big        = 64 << 20
		allocBound = 4 << 20
	)
	if err := os.Truncate(p, big); err != nil {
		t.Fatal(err)
	}
	// This check reads the process-wide TotalAlloc counter. The bound is
	// far above the noise of other goroutines. The check finds a buffer of
	// more than 1/16 of the file size. The rchar check below is exact.
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	if _, err := ReadAll(f, fi, capRule); !errors.Is(err, ErrSize) {
		t.Fatalf("err = %v, want ErrSize", err)
	}
	runtime.ReadMemStats(&m1)
	if d := m1.TotalAlloc - m0.TotalAlloc; d >= allocBound {
		t.Errorf("ReadAll allocated %d bytes, want less than %d", d, allocBound)
	}
	if runtime.GOOS != "linux" {
		t.Skip("the read count needs /proc/thread-self/io")
	}
	// The rchar line of /proc/thread-self/io counts the bytes that the read
	// system calls of this thread return. The test locks the thread, so no
	// other goroutine reads on it. The test reads the rchar value before and
	// after ReadAll. The second value also counts the bytes of the first
	// /proc read. The test subtracts them.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, own := threadRchar(t)
	_, err = ReadAll(f, fi, capRule)
	after, _ := threadRchar(t)
	if !errors.Is(err, ErrSize) {
		t.Fatalf("err = %v, want ErrSize", err)
	}
	if got, want := after-before-int64(own), capRule.MaxSize+1; got != want {
		t.Errorf("ReadAll read %d bytes, want %d", got, want)
	}
}

// threadRchar gives the rchar value of this thread, and the number of bytes
// that the read of /proc/thread-self/io returned. It fails the test when it
// finds no value.
func threadRchar(t *testing.T) (rchar int64, n int) {
	t.Helper()
	b, err := os.ReadFile("/proc/thread-self/io")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "rchar:"); ok {
			rchar, err = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return rchar, len(b)
		}
	}
	t.Fatal("no rchar line in /proc/thread-self/io")
	return 0, 0
}

func TestTS23_ReadAllStartsAtOffsetZero(t *testing.T) {
	r, dir := root(t)
	put(t, dir, "f", "0123456789")
	f, fi, err := Open(r, "f", capRule)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Read(make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	got, err := ReadAll(f, fi, capRule)
	if err != nil || string(got) != "0123456789" {
		t.Errorf("after a read of 3 bytes: %q, %v", got, err)
	}
	if off, err := f.Seek(0, io.SeekCurrent); err != nil || off != 3 {
		t.Errorf("offset after ReadAll = %d, %v, want 3", off, err)
	}
}

func TestTS23_ReadAllOtherFile(t *testing.T) {
	r, dir := root(t)
	put(t, dir, "checked", "01234")
	put(t, dir, "other", "abcde")
	_, fi, err := Open(r, "checked", capRule)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "other"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := ReadAll(f, fi, capRule)
	if !errors.Is(err, ErrChanged) || len(got) != 0 {
		t.Errorf("other file: %q, %v, want no bytes and ErrChanged", got, err)
	}
}

func TestTS23_ReadAllFIFO(t *testing.T) {
	r, dir := root(t)
	put(t, dir, "checked", "01234")
	_, fi, err := Open(r, "checked", capRule)
	if err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(dir, "p")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	// O_RDWR does not block the open of a FIFO.
	f, err := os.OpenFile(pipe, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pipeInfo, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		fi   fs.FileInfo
	}{
		{"FileInfo of another file", fi},
		{"FileInfo of the FIFO", pipeInfo},
	} {
		done := make(chan error, 1)
		go func() {
			_, err := ReadAll(f, tc.fi, capRule)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrType) {
				t.Errorf("%s: err = %v, want ErrType", tc.name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: ReadAll did not return before the deadline", tc.name)
		}
	}
}

func TestTS23_ReadAllChangedSize(t *testing.T) {
	r, dir := root(t)
	p := put(t, dir, "f", "01234")
	f, fi, err := Open(r, "f", capRule)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.WriteFile(p, []byte("012345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAll(f, fi, capRule); !errors.Is(err, ErrChanged) {
		t.Errorf("grown: err = %v, want ErrChanged", err)
	}
	if err := os.WriteFile(p, []byte("01"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAll(f, fi, capRule); !errors.Is(err, ErrChanged) {
		t.Errorf("shrunk: err = %v, want ErrChanged", err)
	}
}

func TestTS23_ReadAllRuleRefused(t *testing.T) {
	r, dir := root(t)
	put(t, dir, "f", "0123456789")
	f, fi, err := Open(r, "f", capRule)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	bad := []Rule{
		{},
		{Type: Regular, Owner: OwnerSelf},
		{Type: Dir, Owner: OwnerSelf, MaxSize: 10},
		{Type: Regular, Owner: OwnerSelf, MaxSize: -1},
		{Type: Regular, Owner: 4, MaxSize: 10},
	}
	for _, rule := range bad {
		if _, err := ReadAll(f, fi, rule); !errors.Is(err, ErrRule) {
			t.Errorf("rule %+v: err = %v, want ErrRule", rule, err)
		}
		if _, err := ReadFile(r, "f", rule); !errors.Is(err, ErrRule) {
			t.Errorf("ReadFile rule %+v: err = %v, want ErrRule", rule, err)
		}
	}
	if _, err := ReadAll(nil, fi, capRule); !errors.Is(err, ErrRule) {
		t.Errorf("nil file: err = %v, want ErrRule", err)
	}
	if _, err := ReadAll(f, nil, capRule); !errors.Is(err, ErrRule) {
		t.Errorf("nil FileInfo: err = %v, want ErrRule", err)
	}
	if _, err := ReadFile(nil, "f", capRule); !errors.Is(err, ErrRule) {
		t.Errorf("nil root: err = %v, want ErrRule", err)
	}
}

func TestTS23_ReadAllHugeCap(t *testing.T) {
	r, dir := root(t)
	put(t, dir, "f", "0123456789")
	rule := capRule
	rule.MaxSize = 1<<63 - 1
	got, err := ReadFile(r, "f", rule)
	if err != nil || string(got) != "0123456789" {
		t.Errorf("largest cap: %q, %v", got, err)
	}
}

func TestTS23_CheckPassAndRefusal(t *testing.T) {
	r, dir := root(t)
	put(t, dir, "f", "0123456789")
	put(t, dir, "wide", "0123456789")
	if err := os.Chmod(filepath.Join(dir, "wide"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	strict := base
	strict.Forbid = 0o077
	want, err := os.Lstat(filepath.Join(dir, "f"))
	if err != nil {
		t.Fatal(err)
	}
	fi, err := Check(r, "f", strict)
	if err != nil || !os.SameFile(fi, want) {
		t.Fatalf("pass: %v, %v", fi, err)
	}
	tests := []struct {
		name string
		file string
		rule Rule
		want error
	}{
		{"mode", "wide", strict, ErrMode},
		{"link", "l", base, ErrSymlink},
		{"type", "d", base, ErrType},
		{"size", "f", capRule2(9), ErrSize},
		{"missing", "none", base, ErrExamine},
		{"name", "a/b", base, ErrName},
		{"empty name", "", base, ErrName},
		{"rule", "f", Rule{}, ErrRule},
	}
	for _, tc := range tests {
		fi, err := Check(r, tc.file, tc.rule)
		if !errors.Is(err, tc.want) || fi != nil {
			t.Errorf("%s: %v, %v, want %v", tc.name, fi, err, tc.want)
		}
	}
	if _, err := Check(nil, "f", base); !errors.Is(err, ErrRule) {
		t.Errorf("nil root: err = %v, want ErrRule", err)
	}
	if _, err := Check(r, "none", base); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v does not hold fs.ErrNotExist", err)
	}
}

// capRule2 is a rule for a file with the cap n.
func capRule2(n int64) Rule {
	r := base
	r.MaxSize = n
	return r
}

// openFDs counts the entries in /proc/self/fd.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd:", err)
	}
	return len(ents)
}

func TestTS23_CheckFIFONoOpen(t *testing.T) {
	r, dir := root(t)
	if err := syscall.Mkfifo(filepath.Join(dir, "p"), 0o600); err != nil {
		t.Fatal(err)
	}
	var before int
	if runtime.GOOS == "linux" {
		before = openFDs(t)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Check(r, "p", base)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrType) {
			t.Errorf("err = %v, want ErrType", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Check did not return before the deadline")
	}
	// A FIFO is not a regular file, but a rule for it still must not open it.
	if runtime.GOOS != "linux" {
		t.Skip("the count of open files needs /proc/self/fd")
	}
	if after := openFDs(t); after != before {
		t.Errorf("open files: %d before, %d after", before, after)
	}
}

// Open fails on a file with mode 0, but Check only examines it.
func TestTS23_CheckOpensNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open a file with mode 0")
	}
	r, dir := root(t)
	p := put(t, dir, "f", "0123456789")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	want, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := Check(r, "f", base)
	if err != nil || !os.SameFile(fi, want) {
		t.Errorf("Check: %v, %v", fi, err)
	}
	if err := open(t, r, "f", base); !errors.Is(err, ErrOpen) {
		t.Errorf("Open: err = %v, want ErrOpen", err)
	}
}

func TestTS23_ErrorTextHoldsNoPathOrBytes(t *testing.T) {
	r, dir := root(t)
	const secret = "SECRETCONTENT"
	put(t, dir, "big", secret+secret)
	put(t, dir, "ok", secret)
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("d", filepath.Join(dir, "linkname")); err != nil {
		t.Fatal(err)
	}
	rule := capRule2(int64(len(secret)))
	dirRule := Rule{Type: Dir, Owner: OwnerSelf}

	_, err := ReadFile(r, "big", rule)
	noLeak(t, err, dir, secret, "big")
	_, err = ReadFile(r, "none", rule)
	noLeak(t, err, dir, secret, "none")
	_, err = Check(r, "none", rule)
	noLeak(t, err, dir, "none")
	_, err = Check(r, "big", Rule{Type: Dir, Owner: OwnerSelf})
	noLeak(t, err, dir, secret, "big")
	_, err = OpenRoot(r, "d/none", dirRule)
	noLeak(t, err, dir, "none")
	_, err = OpenRoot(r, "linkname", dirRule)
	noLeak(t, err, dir, "linkname")
	err = CheckParents(r, "none/x", dirRule)
	noLeak(t, err, dir, "none")

	// The stat of a closed file gives a path error with the path of the file.
	f, fi, err := Open(r, "ok", rule)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	_, perr := f.Read(make([]byte, 1))
	var pe *fs.PathError
	if !errors.As(perr, &pe) || !strings.Contains(pe.Path, dir) {
		t.Fatalf("closed read gave %v, want a path error with the path", perr)
	}
	_, err = ReadAll(f, fi, rule)
	if !errors.Is(err, ErrExamine) {
		t.Errorf("closed file: err = %v, want ErrExamine", err)
	}
	noLeak(t, err, dir, "ok", secret)
	var e *Error
	if errors.As(err, &e) && bytes.Contains([]byte(e.Cause.Error()), []byte(dir)) {
		t.Errorf("cause %q holds the path", e.Cause)
	}

	// A write-only file passes the stat and the identity check. Its read fails.
	_, fi, err = Open(r, "ok", rule)
	if err != nil {
		t.Fatal(err)
	}
	wf, err := os.OpenFile(filepath.Join(dir, "ok"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer wf.Close()
	_, err = ReadAll(wf, fi, rule)
	if !errors.Is(err, ErrExamine) {
		t.Errorf("write-only file: err = %v, want ErrExamine", err)
	}
	noLeak(t, err, dir, "ok", secret)
	e = nil
	if errors.As(err, &e) && e.Cause != nil && bytes.Contains([]byte(e.Cause.Error()), []byte(dir)) {
		t.Errorf("cause %q holds the path", e.Cause)
	}
}
