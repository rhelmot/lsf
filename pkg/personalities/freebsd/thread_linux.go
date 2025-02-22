package freebsd

import (
	"bytes"
	"encoding/binary"

	freebsd "github.com/AkihiroSuda/lsf/pkg/personalities/freebsd/systypes"
	"github.com/sirupsen/logrus"
	"github.com/lunixbochs/struc"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
	"golang.org/x/sys/unix"
)

type McontextAmd64 struct {
	Onstack uint64;
	Rdi uint64;		/* machine state (struct trapframe) */
	Rsi uint64;
	Rdx uint64;
	Rcx uint64;
	R8 uint64;
	R9 uint64;
	Rax uint64;
	Rbx uint64;
	Rbp uint64;
	R10 uint64;
	R11 uint64;
	R12 uint64;
	R13 uint64;
	R14 uint64;
	R15 uint64;
	Trapno uint32;
	Fs uint16;
	Gs uint16;
	Addr uint64;
	Flags uint32;
	Es uint16;
	Ds uint16;
	Err uint64;
	Rip uint64;
	Cs uint64;
	Rflags uint64;
	Rsp uint64;
	Ss uint64;

	Len uint64;			/* sizeof(mcontext_t) */

	Fpformat uint64;
	Ownedfp uint64;
	Fpstate tracer.SavefpuAmd64;  // make sure this is 512 bytes...

	Fsbase uint64;
	Gsbase uint64;

	Xfpustate uint64;
	Xfpustate_len uint64;

	Spare [4]uint64;
}

func ContextFromLinux(linux *tracer.UserStruct) (*McontextAmd64, error) {
	result := &McontextAmd64{}
	// mc_onstack not useful
	result.Rdi = linux.Regs.Rdi
	result.Rsi = linux.Regs.Rsi
	result.Rdx = linux.Regs.Rdx
	result.Rcx = linux.Regs.Rcx
	result.R8 = linux.Regs.R8
	result.R9 = linux.Regs.R8
	result.Rax = linux.Regs.Rax
	result.Rbp = linux.Regs.Rbp
	result.R10 = linux.Regs.R10
	result.R11 = linux.Regs.R11
	result.R12 = linux.Regs.R12
	result.R13 = linux.Regs.R13
	result.R14 = linux.Regs.R14
	result.R15 = linux.Regs.R15
	result.Trapno = uint32(linux.Regs.Orig_rax)
	result.Fs = uint16(linux.Regs.Fs)
	result.Gs = uint16(linux.Regs.Gs)
	// mc_addr unused?
	// mc_flags unknown...?
	result.Es = uint16(linux.Regs.Es)
	result.Ds = uint16(linux.Regs.Ds)
	// mc_err unknown...? hardware error flags?
	result.Rip = linux.Regs.Rip
	result.Cs = linux.Regs.Cs
	result.Rflags = linux.Regs.Eflags
	result.Rsp = linux.Regs.Rsp
	result.Ss = linux.Regs.Ss
	size, err := struc.Sizeof(result)
	if err != nil {
		return nil, err
	}
	result.Len = uint64(size)
	result.Fpformat = 0x10002  // xmm
	result.Ownedfp = 0x20001  // _MC_OWNED_FPU
	result.Fsbase = linux.Regs.Fs_base
	result.Gsbase = linux.Regs.Gs_base

	result.Fpstate = linux.I387

	return result, nil
}

func (result *McontextAmd64) ToLinux() (*tracer.UserStruct, error) {
	linux := &tracer.UserStruct{}
	linux.Regs.Rdi = result.Rdi
	linux.Regs.Rsi = result.Rsi
	linux.Regs.Rdx = result.Rdx
	linux.Regs.Rcx = result.Rcx
	linux.Regs.R8 = result.R8
	linux.Regs.R8 = result.R9
	linux.Regs.Rax = result.Rax
	linux.Regs.Rbp = result.Rbp
	linux.Regs.R10 = result.R10
	linux.Regs.R11 = result.R11
	linux.Regs.R12 = result.R12
	linux.Regs.R13 = result.R13
	linux.Regs.R14 = result.R14
	linux.Regs.R15 = result.R15
	linux.Regs.Orig_rax = uint64(result.Trapno)
	linux.Regs.Fs = uint64(result.Fs)
	linux.Regs.Gs = uint64(result.Gs)
	linux.Regs.Es = uint64(result.Es)
	linux.Regs.Ds = uint64(result.Ds)
	linux.Regs.Rip = result.Rip
	linux.Regs.Cs = result.Cs
	linux.Regs.Eflags = result.Rflags
	linux.Regs.Rsp = result.Rsp
	linux.Regs.Ss = result.Ss
	linux.Regs.Fs_base = result.Fsbase
	linux.Regs.Gs_base = result.Gsbase

	linux.I387 = result.Fpstate

	return linux, nil
}

func thrSelfHandler(sc *tracer.SyscallCtx) error {
	// FreeBSD: int thr_self(long *id)
	// Linux:   pid_t gettid(void)
	switch sc.Entry {
	case true:
		sc.Regs.SetSyscall(unix.SYS_GETTID)
	case false:
		linuxTID := sc.Regs.Ret()
		thr := tidToFreeBSD(linuxTID)
		thrB := make([]byte, 8)
		binary.LittleEndian.PutUint64(thrB, thr)
		thrPtr := uintptr(sc.Regs.Arg(0))
		if _, err := unix.PtracePokeData(sc.Pid, thrPtr, thrB); err != nil {
			return err
		}
		sc.Regs.SetRet(0)
	}
	return nil
}

func thrKillHandler(sc *tracer.SyscallCtx) error {
	// FreeBSD: int thr_kill(long id, int sig);
	// Linux:   int kill(pid_t pid, int sig);
	if sc.Entry {
		sc.Regs.SetArg(0, tidFromFreeBSD(sc.Regs.Arg(0)))
	}
	return simpleHandler(unix.SYS_KILL)(sc)
}

// https://www.freebsd.org/cgi/man.cgi?query=thr_self&sektion=2&apropos=0&manpath=FreeBSD+13.1-RELEASE+and+Ports
const freeBSDTIDMin = 100001

func tidToFreeBSD(linuxTID uint64) uint64 {
	return linuxTID + freeBSDTIDMin
}

func tidFromFreeBSD(freeBSDTID uint64) uint64 {
	return freeBSDTID - freeBSDTIDMin
}

func getcontextHandler(sc *tracer.SyscallCtx) error {
	if sc.Entry {
		sc.Regs.SetSyscall(nopSyscall)
	} else {
		structPtr := sc.Regs.Arg(0)
		linuxContext, err := tracer.PeekUser(sc.Pid, false)
		if err != nil {
			return err
		}
		bsdContext, err := ContextFromLinux(linuxContext)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		err = struc.Pack(&buf, bsdContext)
		if err != nil {
			return err
		}
		_, err = unix.PtracePokeData(sc.Pid, uintptr(structPtr), buf.Bytes())
		if err != nil {
			return err
		}
		sc.Regs.SetRet(0)
	}
	return nil
}

func setcontextHandler(sc *tracer.SyscallCtx) error {
	if sc.Entry {
		sc.Regs.SetSyscall(nopSyscall)
	} else {
		structPtr := sc.Regs.Arg(0)
		bsdContext := &McontextAmd64{}
		size, err := struc.Sizeof(bsdContext)
		if err != nil {
			return err
		}
		rawBuf := make([]byte, size)
		_, err = unix.PtracePeekData(sc.Pid, uintptr(structPtr), rawBuf)
		if err != nil {
			return err
		}
		buf := bytes.NewBuffer(rawBuf)
		err = struc.Unpack(buf, bsdContext)
		if err != nil {
			return err
		}
		linuxContext, err := bsdContext.ToLinux()
		if err != nil {
			return err
		}
		err = linuxContext.PokeUser(sc.Pid)
		if err != nil {
			return err
		}
		sc.Regs.SetRet(0)
	}
	return nil
}

func umtxopHandler(sc *tracer.SyscallCtx) error {
	obj := sc.OldRegs.Arg(0)
	op := sc.OldRegs.Arg(1)
	val := sc.OldRegs.Arg(2)
	//uaddr1 := sc.Regs.Arg(3)
	uaddr2 := sc.OldRegs.Arg(4)
	if sc.Entry {
		switch op {
		case freebsd.UMTX_OP_WAIT:
			logrus.Debugf("UMTX_OP_WAIT on 0x%x with val 0x%x", obj, val)
			sc.Regs.SetSyscall(unix.SYS_FUTEX)
			sc.Regs.SetArg(1, 0)  // FUTEX_WAIT
			sc.Regs.SetArg(3, uaddr2) // timeout
			// rest of args are same :0
		case freebsd.UMTX_OP_WAKE:
			logrus.Debugf("UMTX_OP_WAKE on 0x%x", obj)
			sc.Regs.SetSyscall(unix.SYS_FUTEX)
			sc.Regs.SetArg(1, 1)  // FUTEX_WAKE
			// rest of args are same :0
		default:
			sc.Regs.SetSyscall(unix.SYS_GETPID)
		}
	} else {
		linuxResult := sc.Regs.Ret()
		switch op {
		case freebsd.UMTX_OP_WAIT:
			if int64(linuxResult) >= 0 {
				sc.Regs.SetRet(0)
			} else {
				// TOOD errno...
			}
		case freebsd.UMTX_OP_WAKE:
			// TOOD errno...
		default:
			ret := -1 * int(unix.ENOSYS)
			sc.Regs.SetRet(uint64(ret))
		}
	}
	return nil
}

func suspendHandler(sc *tracer.SyscallCtx) error {
	return nil
}
