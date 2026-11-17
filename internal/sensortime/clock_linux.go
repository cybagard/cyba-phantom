//go:build linux

package sensortime

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultSource reads CLOCK_BOOTTIME, which counts a host suspend, and the
// boot id file. A boot id that cannot be read gives ErrBootID.
func DefaultSource() Source { return newSource(bootClock, bootID) }

func bootClock() (time.Duration, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return time.Duration(ts.Nano()), nil
}

func bootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return parseLinuxBootID(b, err)
}
