package bundle

import (
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/cybagard/cyba-phantom/internal/safefile"
)

// StateName is the fixed name of the version state in the bundle directory.
const StateName = "version.state"

// maxStateBytes is the longest state file that the reader accepts.
const maxStateBytes = 4096

// stateTempName is the name of the temporary file of a state write.
const stateTempName = StateName + ".tmp"

// ErrStateFault is the fault of a state file that the file rule refuses or that
// does not parse (SEC-24). It is not a rejection code: CodeOf gives false. The
// error holds no byte of the state file.
var ErrStateFault = errors.New("bundle: state fault")

// stateRule is the rule of a state file. It forbids each group and other bit,
// and the setuid, setgid and sticky bits.
var stateRule = safefile.Rule{
	Type:    safefile.Regular,
	Owner:   safefile.OwnerSelfOrRoot,
	Forbid:  0o077 | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky,
	OneLink: true,
	MaxSize: maxStateBytes,
}

// state is the version state: the highest accepted version, the SHA-256 of that
// bundle, and the class of its key.
type state struct {
	Version string
	SHA256  [32]byte
	Class   Class
}

type rawState struct {
	Version *string `json:"version"`
	SHA256  *string `json:"sha256"`
	Class   *string `json:"class"`
}

var classText = map[Class]string{ClassProprietary: "proprietary", ClassReference: "reference"}

// readState reads the version state through root. No state file (a first start)
// gives nil and no error. A file that the rule refuses, or that does not parse,
// gives ErrStateFault. A fault changes nothing on disk.
func readState(root *os.Root) (*state, error) {
	b, err := safefile.ReadFile(root, StateName, stateRule)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateFault, err)
	}
	var raw rawState
	if json.Unmarshal(b, &raw, parseOpts...) != nil || raw.Version == nil || raw.SHA256 == nil || raw.Class == nil {
		return nil, ErrStateFault
	}
	st := &state{Version: *raw.Version}
	sum, err := hex.DecodeString(*raw.SHA256)
	if err != nil || len(sum) != len(st.SHA256) || hex.EncodeToString(sum) != *raw.SHA256 || !validVersion(st.Version) {
		return nil, ErrStateFault
	}
	copy(st.SHA256[:], sum)
	for c, text := range classText {
		if text == *raw.Class {
			st.Class = c
		}
	}
	if st.Class == 0 {
		return nil, ErrStateFault
	}
	return st, nil
}

// writeState replaces the version state file.
func writeState(root *os.Root, st state) error {
	return writeFile(root, StateName, fmt.Appendf(nil, "{\"version\":%q,\"sha256\":\"%x\",\"class\":%q}\n", st.Version, st.SHA256, classText[st.Class]))
}

// tempFile is the part of the temporary file that writeFile uses after the
// create.
type tempFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// wrapTemp is nil, except in a test. A test sets it to make Write, Sync or
// Close of the temporary file fail.
var wrapTemp func(*os.File) tempFile

// writeFile writes data to the file with this name and replaces an old file.
// It makes a temporary file, with the name and ".tmp", and mode 0600 less the
// umask. It writes the temporary file, and calls Sync and Close. Then it
// renames the temporary file to name and calls Sync on the directory. First it
// removes a temporary file that a crash left, so that file does not block the
// write. O_EXCL means that the write never follows a symlink at the temporary
// name.
func writeFile(root *os.Root, name string, data []byte) error {
	tmp := name + ".tmp"
	if err := root.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	var w tempFile = f
	if wrapTemp != nil {
		w = wrapTemp(f)
	}
	_, err = w.Write(data)
	if err == nil {
		err = w.Sync()
	}
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmp, name)
	}
	if err != nil {
		_ = root.Remove(tmp)
		return err
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
