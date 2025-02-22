package tracer

import (
	"bytes"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/lunixbochs/struc"
	"golang.org/x/sys/unix"
)

// Regs is partially specific to the FreeBSD ABI
// FIXME: FreeBSD-specific part has to be moved to personalities/freebsd
type Regs struct {
	unix.PtraceRegs
}

func (regs *Regs) String() string {
	s := "["
	s += fmt.Sprintf("RAX=0x%x ORIG_RAX=0x%x RBX=0x%x RCX=0x%x RDX=0x%x RSI=0x%x RDI=0x%x RBP=0x%x RSP=0x%x ",
		regs.Rax, regs.Orig_rax, regs.Rbx, regs.Rcx, regs.Rdx, regs.Rsi, regs.Rdi, regs.Rbp, regs.Rsp)
	s += fmt.Sprintf("R8=0x%x R9=0x%x R10=0x%x R11=0x%x R12=0x%x R13=0x%x R14=0x%x R15=0x%x ",
		regs.R8, regs.R9, regs.R10, regs.R11, regs.R12, regs.R13, regs.R14, regs.R15)
	s += fmt.Sprintf("RIP=0x%x EFLAGS=0x%x CS=0x%x SS=0x%x DS=0x%x ES=0x%x FS=0x%x FSBASE=0x%x GS=0x%x GSBASE=0x%x",
		regs.Rip, regs.Eflags, regs.Cs, regs.Ss, regs.Ds, regs.Es, regs.Fs, regs.Fs_base, regs.Gs, regs.Gs_base)
	s += "]"
	return s
}

func (regs *Regs) Syscall() uint64 {
	return regs.Orig_rax
}

func (regs *Regs) SetSyscall(x uint64) {
	regs.Orig_rax = x
}

func (regs *Regs) Ret() uint64 {
	return regs.Rax
}

const EflagsCF = 0x1

func (regs *Regs) AdjustRet() {
	if int(regs.Ret()) < 0 {
		regs.SetError()
	} else {
		regs.ClearError()
	}
}

// SetError is specific to the FreeBSD ABI
func (regs *Regs) SetError() {
	regs.Eflags |= EflagsCF
}

// ClearError is specific to the FreeBSD ABI
func (regs *Regs) ClearError() {
	regs.Eflags = uint64(int64(regs.Eflags) & ^EflagsCF)
}

func (regs *Regs) SetRet(x uint64) {
	regs.Rax = x
	regs.AdjustRet()
}

func (regs *Regs) SetErrno(x uint64) {
	regs.SetRet(uint64(-1 * int(x)))
}

func (regs *Regs) Arg(i int) uint64 {
	// FreeBSD syscall: RDI, RSI, RDX, RCX, R8, R9
	// But RCX is internally changed into R10:
	// https://github.com/freebsd/freebsd-src/blob/release/13.1.0/sys/amd64/amd64/exception.S#L582
	//
	// See also:
	// https://www.felixcloutier.com/x86/syscall
	// https://stackoverflow.com/questions/66878250/freebsd-syscall-clobbering-more-registers-than-linux-inline-asm-different-behav
	switch i {
	case 0:
		return regs.Rdi
	case 1:
		return regs.Rsi
	case 2:
		return regs.Rdx
	case 3:
		return regs.R10 // Not RCX!
	case 4:
		return regs.R8
	case 5:
		return regs.R9
	default:
		panic(fmt.Errorf("unexpected Arg %d", i))
	}
}

func (regs *Regs) SetArg(i int, x uint64) {
	// Linux user:    RDI, RSI, RDX, RCX, R8, R9
	// Linux syscall: RDI, RSI, RDX, R10 (Not RCX!), R8, R9
	switch i {
	case 0:
		regs.Rdi = x
	case 1:
		regs.Rsi = x
	case 2:
		regs.Rdx = x
	case 3:
		regs.R10 = x // Not RCX!
	case 4:
		regs.R8 = x
	case 5:
		regs.R9 = x
	default:
		panic(fmt.Errorf("unexpected Arg %d", i))
	}
}

func PeekUser(pid int, forceFp bool) (*UserStruct, error) {
	result := &UserStruct{}
	size, err := struc.Sizeof(result)
	if err != nil {
		return nil, err
	}
	rawBuf := make([]byte, size)
	_, err = unix.PtracePeekUser(pid, 0, rawBuf)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(rawBuf)
	err = struc.Unpack(buf, result)
	if err != nil {
		return nil, err
	}
	if result.U_fpvalid == 0 && forceFp {
		fp, err := PeekUserFp(pid)
		if err != nil {
			return nil, err
		}
		result.I387 = *fp;
		result.U_fpvalid = 1
	}
	return result, nil
}

func PeekUserFp(pid int) (*SavefpuAmd64, error) {
	result := &SavefpuAmd64{}
	size, err := struc.Sizeof(result)
	if err != nil {
		return nil, err
	}
	rawBuf := make([]byte, size)
	_, _, syserr := syscall.Syscall6(syscall.SYS_PTRACE, syscall.PTRACE_GETFPREGS, uintptr(pid), 0, uintptr(unsafe.Pointer(&rawBuf[0])), 0, 0)
	if syserr != 0 {
		return nil, syserr
	}
	buf := bytes.NewBuffer(rawBuf)
	err = struc.Unpack(buf, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (user *UserStruct) PokeUser(pid int) error {
	var buf bytes.Buffer
	err := struc.Pack(&buf, &user.U_fpstate)
	if err != nil {
		return err
	}
	_, _, syserr := syscall.Syscall6(syscall.SYS_PTRACE, syscall.PTRACE_SETFPREGS, uintptr(pid), 0, uintptr(unsafe.Pointer(&buf.Bytes()[0])), 0, 0)
	if syserr != 0 {
		return syserr
	}

	buf.Truncate(0)
	err = struc.Pack(&buf, user)
	if err != nil {
		return err
	}
	_, err = unix.PtracePokeUser(pid, 0, buf.Bytes())
	if err != nil {
		return err
	}
	return nil
}

type UserRegsStruct struct {
	R15 uint64;
	R14 uint64;
	R13 uint64;
	R12 uint64;
	Rbp uint64;
	Rbx uint64;
	R11 uint64;
	R10 uint64;
	R9 uint64;
	R8 uint64;
	Rax uint64;
	Rcx uint64;
	Rdx uint64;
	Rsi uint64;
	Rdi uint64;
	Orig_rax uint64;
	Rip uint64;
	Cs uint64;
	Eflags uint64;
	Rsp uint64;
	Ss uint64;
	Fs_base uint64;
	Gs_base uint64;
	Ds uint64;
	Es uint64;
	Fs uint64;
	Gs uint64;
}

type Fpacc87 struct {
	Bytes [10]uint8;
}

type Fpacc87Padded struct {
	Acc Fpacc87;
	Pad [6]uint8;
}

type Xmmac struct {
	Bytes [16]uint8;
}

type Envxmm64 struct {
	Cw uint16;		/* control word (16bits) */
	Sw uint16;		/* status word (16bits) */
	Tw uint8;		/* tag word (8bits) */
	Zero uint8;
	Opcode uint16;	/* opcode last executed (11 bits ) */
	Rip uint64;		/* fp instruction pointer */
	Rdp uint64;		/* fp operand pointer */
	Mxcsr uint32;	/* SSE control/status register */
	Mxcsr_mask uint32;	/* valid bits in mxcsr */
}

type SavefpuAmd64 struct {
	Env Envxmm64;
	Fp [8]Fpacc87Padded;
	Xmm [16]Xmmac;
	Pad [96]uint8;
}


type UserStruct struct {
	Regs UserRegsStruct;
	U_fpvalid uint32;
	I387 SavefpuAmd64;
	U_tsize uint64;
	U_dsize uint64;
	U_ssize uint64;
	Start_code uint64;
	Start_stack uint64;
	Signal int64;
	Reserved int32;
	U_ar0 uint64;
	U_fpstate uint64;
	Magic uint64;
	U_comm [32]uint8;
	U_debugreg [8]uint64;
}

func asmCpuidex(op, op2 uint32) (eax, ebx, ecx, edx uint32)

var xsaveSizeCache int64 = -1

func XsaveSize() uint32 {
	if xsaveSizeCache != -1 {
		return uint32(xsaveSizeCache)
	}
	_, size, _, _ := asmCpuidex(0xd, 0x0)
	xsaveSizeCache = int64(size)
	return size
}
