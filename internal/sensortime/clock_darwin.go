//go:build darwin

package sensortime

import (
	"time"

	"golang.org/x/sys/unix"
)

// DefaultSource reads CLOCK_MONOTONIC and kern.bootsessionuuid.
//
// CLOCK_MONOTONIC does not follow a wall step. This is a reading of source
// code, not a probe with a wall step. Libc clock_gettime.c, lines 148-156:
// the clock is the wall time minus the boot time.
// https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/gen/clock_gettime.c#L148-L156
// The kernel moves the boot time by the same delta at a wall step, in
// xnu clock.c, lines 787-797. So the difference of the two does not change.
// https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/clock.c#L787-L797
// The man page says that the clock counts while the system sleeps.
func DefaultSource() Source { return newSource(bootClock, bootID) }

func bootClock() (time.Duration, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return time.Duration(ts.Nano()), nil
}

func bootID() (string, error) {
	s, err := unix.Sysctl("kern.bootsessionuuid")
	return normalizeDarwinBootID(s, err)
}
