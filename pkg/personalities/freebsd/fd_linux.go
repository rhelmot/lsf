package freebsd

import (
	"fmt"
	"syscall"
	freebsd "github.com/AkihiroSuda/lsf/pkg/personalities/freebsd/systypes"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func openHandler(sc *tracer.SyscallCtx) error {
	//  int open(const char *pathname, int flags, mode_t mode);
	// FIXME: "Linux reserves the special, nonstandard access mode 3 (binary 11)"
	// https://man7.org/linux/man-pages/man2/open.2.html
	if sc.Entry {
		origFlags := sc.Regs.Arg(1)
		flags := openFlagsToFreeBSD(origFlags)
		sc.Regs.SetArg(1, flags)
	}
	return simpleHandler(unix.SYS_OPEN)(sc)
}

func openatHandler(sc *tracer.SyscallCtx) error {
	// int openat(int dirfd, const char *pathname, int flags, mode_t mode);
	if sc.Entry {
		origFlags := sc.Regs.Arg(2)
		flags := openFlagsToFreeBSD(origFlags)
		sc.Regs.SetArg(2, flags)
	}
	return simpleHandler(unix.SYS_OPENAT)(sc)
}

func pipe2Handler(sc *tracer.SyscallCtx) error {
	if sc.Entry {
		origFlags := sc.Regs.Arg(2)
		flags := openFlagsToFreeBSD(origFlags)
		sc.Regs.SetArg(2, flags)
	}
	return simpleHandler(unix.SYS_PIPE2)(sc)
}

func fcntlHander(sc *tracer.SyscallCtx) error {
	if sc.Entry {
		origCmd := sc.Regs.Arg(1)
		hostCmd, ok := freebsd.FcntlCmdMapping[origCmd]
		if !ok {
			return fmt.Errorf("Bad fcntl cmd: %d", origCmd)
		}
		sc.Regs.SetArg(1, hostCmd)

		switch hostCmd {
		case syscall.F_SETFD:
			sc.Regs.SetArg(2, convertFlagsAndWarn(sc.Regs.Arg(2), freebsd.FcntlFdFlagsMapping, "fcntl(F_SETFD)"))
		case syscall.F_SETFL:
			sc.Regs.SetArg(2, convertFlagsAndWarn(sc.Regs.Arg(2), freebsd.OpenFlagsMapping, "fcntl(F_SETFL)"))
		}
	} else {
		hostCmd := sc.Regs.Arg(0)
		switch hostCmd {
		case syscall.F_GETFD:
			sc.Regs.SetArg(2, convertFlagsReverseAndWarn(sc.Regs.Arg(2), freebsd.FcntlFdFlagsMapping, "fcntl(F_GETFD)"))
		case syscall.F_GETFL:
			sc.Regs.SetArg(2, convertFlagsReverseAndWarn(sc.Regs.Arg(2), freebsd.OpenFlagsMapping, "fcntl(F_SETFL)"))
		}
	}
	return simpleHandler(unix.SYS_FCNTL)(sc)
}

func convertFlags(origFlags uint64, bitMapping map[uint64]uint64) (uint64, uint64) {
	var newFlags uint64
	for k, v := range bitMapping {
		if origFlags & k != 0 {
			newFlags |= v
			origFlags &= ^k
		}
	}

	return newFlags, origFlags
}

func convertFlagsReverse(origFlags uint64, bitMapping map[uint64]uint64) (uint64, uint64) {
	var newFlags uint64
	for k, v := range bitMapping {
		if origFlags & v != 0 {
			newFlags |= k
			origFlags &= ^v
		}
	}

	return newFlags, origFlags
}

func convertFlagsAndWarn(origFlags uint64, bitMapping map[uint64]uint64, errCtx string) uint64 {
	flags, remainder := convertFlags(origFlags, bitMapping)
	if remainder != 0 {
		logrus.Debug("%s: ignoring unsupported flags 0x%x", errCtx, remainder)
	}
	return flags
}

func convertFlagsReverseAndWarn(origFlags uint64, bitMapping map[uint64]uint64, errCtx string) uint64 {
	flags, remainder := convertFlagsReverse(origFlags, bitMapping)
	if remainder != 0 {
		logrus.Debug("%s: ignoring unsupported flags 0x%x", errCtx, remainder)
	}
	return flags
}

func openFlagsToFreeBSD(origFlags uint64) uint64 {
	flags, remainder := convertFlags(origFlags, freebsd.OpenFlagsMapping)
	if remainder & freebsd.O_VERIFY != 0 {
		logrus.Debugf("SYS_OPEN*: ignoring O_VERIFY")
		remainder &= ^uint64(freebsd.O_VERIFY)
	}
	if remainder != 0 {
		logrus.Debugf("SYS_OPEN*: ignoring unsupported flags 0x%x", remainder)
	}
	return flags
}
