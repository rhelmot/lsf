package freebsd

import (
	"encoding/binary"
	"os"
	"runtime"
	"fmt"

	freebsd "github.com/AkihiroSuda/lsf/pkg/personalities/freebsd/systypes"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"github.com/sirupsen/logrus"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

func sysctlHandler(sc *tracer.SyscallCtx) error {
	mibPtr := uintptr(sc.Regs.Arg(0))
	mibN := sc.Regs.Arg(1) // the number of the integers
	if mibN >= 16 {
		if sc.Entry {
			logrus.Debugf("SYS___SYSCTL: unexpected mibN=%d", mibN)
		}
		return stubHandler(freebsd.EINVAL)(sc)
	}

	mibLen := mibN * 4
	mibB := make([]byte, mibLen)
	if _, err := unix.PtracePeekData(sc.Pid, mibPtr, mibB); err != nil {
		return err
	}
	mib := make([]uint32, mibN)
	for i := 0; i < int(mibN); i++ {
		mib[i] = binary.LittleEndian.Uint32(mibB[i*4 : (i+1)*4])
	}
	mibStr := freebsd.MibString(mib)
	if sc.Entry {
		logrus.Debugf("SYS___SYSCTL: MIB=%s (%v)", mibStr, mib)
	}
	return sysctlDispatcher(sc, mibStr)
}

func sysctlDispatcher(sc *tracer.SyscallCtx, mibStr string) error {
	switch mibStr {
	case "kern.ostype":
		return sysctlReturnString(sc, mibStr, "FreeBSD")
	case "kern.osrelease":
		return sysctlReturnString(sc, mibStr, KernOSRelease)
	case "kern.version":
		return sysctlReturnString(sc, mibStr, KernVersion)
	case "kern.hostname":
		v, err := os.Hostname()
		if err != nil {
			return stubHandler(freebsd.EIO, mibStr, err.Error())(sc)
		}
		return sysctlReturnString(sc, mibStr, v)
	case "kern.osreldate":
		return sysctlReturnUint32(sc, mibStr, KernOSRelDate)
	case "kern.usrstack":
		procFs, err := procfs.NewFS("/proc");
		if err != nil {
			return err;
		}
		proc, err := procFs.Proc(sc.Pid)
		if err != nil {
			return err;
		}
		maps, err := proc.ProcMaps()
		if err != nil {
			return err;
		}
		for _, line := range maps {
			if line.Pathname == "[stack]" {
				return sysctlReturnUint64(sc, mibStr, uint64(line.EndAddr))
			}
		}
		return fmt.Errorf("Can't find stack mapping")

	case "hw.machine":
		v := runtime.GOARCH
		return sysctlReturnString(sc, mibStr, v)
	case "hw.pagesizes":
		v := []uint32{uint32(os.Getpagesize())}
		return sysctlReturnUint32Array(sc, mibStr, v)
	case "hw.ncpu":
		v := uint32(runtime.NumCPU())
		return sysctlReturnUint32(sc, mibStr, v)
	default:
		return stubHandler(freebsd.ENOTSUP, mibStr)(sc)
	}
}

func sysctlReturnUint32(sc *tracer.SyscallCtx, mibStr string, value uint32) error {
	if sc.Entry {
		sc.Regs.SetSyscall(nopSyscall)
	} else {
		oldPtr := uintptr(sc.Regs.Arg(2))
		oldLenPtr := uintptr(sc.Regs.Arg(3))
		oldLenB := make([]byte, 8)
		if _, err := unix.PtracePeekData(sc.Pid, oldLenPtr, oldLenB); err != nil {
			return err
		}
		oldLen := binary.LittleEndian.Uint64(oldLenB)
		if oldLen != 4 {
			logrus.Debugf("unexpected oldLen=%d for uint32", oldLen)
			ret := -1 * int(freebsd.EINVAL)
			sc.Regs.SetRet(uint64(ret))
			return nil
		}
		oldB := make([]byte, 4)
		logrus.Debugf("SYS___SYSCTL: MIB=%s: returning %d", mibStr, value)
		binary.LittleEndian.PutUint32(oldB, value)
		if _, err := unix.PtracePokeData(sc.Pid, oldPtr, oldB); err != nil {
			return err
		}
		sc.Regs.SetRet(0)
	}
	return nil
}

func sysctlReturnUint64(sc *tracer.SyscallCtx, mibStr string, value uint64) error {
	if sc.Entry {
		sc.Regs.SetSyscall(nopSyscall)
	} else {
		oldPtr := uintptr(sc.Regs.Arg(2))
		oldLenPtr := uintptr(sc.Regs.Arg(3))
		oldLenB := make([]byte, 8)
		if _, err := unix.PtracePeekData(sc.Pid, oldLenPtr, oldLenB); err != nil {
			return err
		}
		oldLen := binary.LittleEndian.Uint64(oldLenB)
		if oldLen != 8 {
			logrus.Debugf("unexpected oldLen=%d for uint64", oldLen)
			ret := -1 * int(freebsd.EINVAL)
			sc.Regs.SetRet(uint64(ret))
			return nil
		}
		oldB := make([]byte, 8)
		logrus.Debugf("SYS___SYSCTL: MIB=%s: returning %d", mibStr, value)
		binary.LittleEndian.PutUint64(oldB, value)
		if _, err := unix.PtracePokeData(sc.Pid, oldPtr, oldB); err != nil {
			return err
		}
		sc.Regs.SetRet(0)
	}
	return nil
}

func sysctlReturnUint32Array(sc *tracer.SyscallCtx, mibStr string, value []uint32) error {
	if sc.Entry {
		sc.Regs.SetSyscall(nopSyscall)
	} else {
		oldPtr := uintptr(sc.Regs.Arg(2))
		oldLenPtr := uintptr(sc.Regs.Arg(3))
		oldLenB := make([]byte, 8)
		if _, err := unix.PtracePeekData(sc.Pid, oldLenPtr, oldLenB); err != nil {
			return err
		}
		oldLen := binary.LittleEndian.Uint64(oldLenB)
		if int(oldLen) < 4*len(value) {
			logrus.Debugf("unexpected oldLen=%d for []uint32", oldLen)
			ret := -1 * int(freebsd.EINVAL)
			sc.Regs.SetRet(uint64(ret))
			return nil
		}
		oldB := make([]byte, 4*len(value))
		logrus.Debugf("SYS___SYSCTL: MIB=%s: returning %v", mibStr, value)
		for i, subValue := range value {
			binary.LittleEndian.PutUint32(oldB[i*4:i*4+4], subValue)
		}
		if _, err := unix.PtracePokeData(sc.Pid, oldPtr, oldB); err != nil {
			return err
		}
		sc.Regs.SetRet(0)
	}
	return nil
}

func sysctlReturnString(sc *tracer.SyscallCtx, mibStr string, value string) error {
	if sc.Entry {
		sc.Regs.SetSyscall(nopSyscall)
	} else {
		oldPtr := uintptr(sc.Regs.Arg(2))
		oldLenPtr := uintptr(sc.Regs.Arg(3))
		oldLenB := make([]byte, 8)
		if _, err := unix.PtracePeekData(sc.Pid, oldLenPtr, oldLenB); err != nil {
			return err
		}
		oldLen := binary.LittleEndian.Uint64(oldLenB)
		if int(oldLen) < len(value)+1 {
			logrus.Debugf("unexpected oldLen=%d for %q", oldLen, value)
			ret := -1 * int(freebsd.EINVAL)
			sc.Regs.SetRet(uint64(ret))
			return nil
		}
		oldB := []byte(append([]byte(value), 0x00))
		logrus.Debugf("SYS___SYSCTL: MIB=%s: returning %q", mibStr, value)
		if _, err := unix.PtracePokeData(sc.Pid, oldPtr, oldB); err != nil {
			return err
		}
		sc.Regs.SetRet(0)
	}
	return nil
}

func sysctlbynameHandler(sc *tracer.SyscallCtx) error {
	namePtr := uintptr(sc.Regs.Arg(0))
	nameLen := uintptr(sc.Regs.Arg(1))
	nameBuf := make([]byte, nameLen)
	if _, err := unix.PtracePeekData(sc.Pid, namePtr, nameBuf); err != nil {
		return err
	}
	nameStr := string(nameBuf[:])  // moderately insane language
	return sysctlDispatcher(sc, nameStr)
}
