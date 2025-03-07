package tracer

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/AkihiroSuda/lsf/pkg/procutil"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func New(personality Personality, args []string) (*Tracer, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &unix.SysProcAttr{Ptrace: true}
	tracer := &Tracer{
		personality: personality,
		cmd:         cmd,
	}
	return tracer, nil
}

type Personality interface {
	HandleSyscall(sc *SyscallCtx) error
	InitNewProc(wPid int, regs *Regs) (error)
}

type Tracer struct {
	personality Personality
	cmd         *exec.Cmd
}

type SyscallCtx struct {
	Personality Personality
	Pid         int
	Entry       bool
	Num         uint64
	Regs        Regs
	OldRegs     Regs
	Scratch     uint64
}

type SyscallHandler func(sc *SyscallCtx) error

func (tracer *Tracer) Trace() error {
	scRoot := &SyscallCtx{
		Personality: tracer.personality,
	}
	runtime.LockOSThread()
	err := tracer.cmd.Start()
	if err != nil {
		return err
	}
	pGid, err := unix.Getpgid(tracer.cmd.Process.Pid)
	if err != nil {
		return err
	}

	// Catch the birtycry before setting up the ptrace options
	wPid, sig, err := procutil.WaitForStopSignal(-1 * pGid)
	if err != nil {
		return err
	}
	if sig != unix.SIGTRAP {
		return fmt.Errorf("birthcry: expected SIGTRAP, got %+v", sig)
	}
	logrus.Debugf("Got birthcry, pid=%d", wPid)
	scRoot.Pid = wPid

	// Set up the ptrace options
	// PTRACE_O_EXITKILL: since Linux 3.8
	ptraceOptions := unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACEVFORK |
		unix.PTRACE_O_TRACECLONE |
		unix.PTRACE_O_TRACEEXEC |
		unix.PTRACE_O_TRACEEXIT |
		unix.PTRACE_O_TRACESYSGOOD |
		unix.PTRACE_O_EXITKILL
	if err := unix.PtraceSetOptions(wPid, ptraceOptions); err != nil {
		return fmt.Errorf("failed to set ptrace options: %w", err)
	}

	if err = unix.PtraceGetRegs(wPid, &scRoot.Regs.PtraceRegs); err != nil {
		return fmt.Errorf("failed to read registers for %d: %w", wPid, err)
	}
	if scRoot.Scratch, err = AllocScratch(wPid, &scRoot.Regs, 0x1000); err != nil {
		return err
	}
	if err = tracer.personality.InitNewProc(wPid, &scRoot.Regs); err != nil {
		return err
	}
	if err = unix.PtraceSetRegs(wPid, &scRoot.Regs.PtraceRegs); err != nil {
		return fmt.Errorf("failed to set registers for %d: %w", wPid, err)
	}
	logrus.Debugf("Starting loop")
	scMap := map[int]*SyscallCtx {
		wPid: scRoot,
	}
	if err := unix.PtraceSyscall(wPid, 0); err != nil {
		return fmt.Errorf("failed to call PTRACE_SYSCALL (pid=%d) %w", wPid, err)
	}
	for {
		var ws unix.WaitStatus
		wPid, err = unix.Wait4(-1*pGid, &ws, unix.WALL, nil)
		if err != nil {
			return err
		}
		sc, ok := scMap[wPid]
		if !ok {
			logrus.Errorf("Got ptrace event from unknown process %d", wPid)
			continue
		}
		switch uint32(ws) >> 8 {
		case uint32(unix.SIGTRAP) | (unix.PTRACE_EVENT_CLONE << 8):
			forkPid, err := unix.PtraceGetEventMsg(wPid)
			if err != nil {
				return err
			}
			logrus.Debugf("CLONE %d -> %d", wPid, forkPid)
			//if err := unix.PtraceSetOptions(int(forkPid), ptraceOptions); err != nil {
			//	logrus.Debugf("failed to set ptrace options for a forked process %d: %v", forkPid, err)
			//}
			scMap[int(forkPid)] = &SyscallCtx{
				Personality: tracer.personality,
				Pid: int(forkPid),
			}
		case uint32(unix.SIGTRAP) | (unix.PTRACE_EVENT_FORK << 8):
			forkPid, err := unix.PtraceGetEventMsg(wPid)
			if err != nil {
				return err
			}
			logrus.Debugf("FORK %d -> %d", wPid, forkPid)
			//if err := unix.PtraceSetOptions(int(forkPid), ptraceOptions); err != nil {
			//	logrus.Debugf("failed to set ptrace options for a forked process %d: %v", forkPid, err)
			//}
			scMap[int(forkPid)] = &SyscallCtx{
				Personality: tracer.personality,
				Pid: int(forkPid),
			}
		case uint32(unix.SIGTRAP) | (unix.PTRACE_EVENT_VFORK << 8):
			logrus.Debugf("VFORK")
		case uint32(unix.SIGTRAP) | (unix.PTRACE_EVENT_EXEC << 8):
			logrus.Debugf("EXEC")
			sc.Entry = false;
			if err := unix.PtraceSingleStep(wPid); err != nil {
				return err
			}
			_, _, err := procutil.WaitForStopSignal(wPid)
			if err != nil {
				return err
			}
			if err = unix.PtraceGetRegs(wPid, &sc.Regs.PtraceRegs); err != nil {
				return fmt.Errorf("failed to read registers for %d: %w", wPid, err)
			}
			if sc.Scratch, err = AllocScratch(wPid, &sc.Regs, 0x1000); err != nil {
				return err
			}
			if err = tracer.personality.InitNewProc(wPid, &sc.Regs); err != nil {
				return err
			}
			if err = unix.PtraceSetRegs(wPid, &sc.Regs.PtraceRegs); err != nil {
				return fmt.Errorf("failed to set registers for %d: %w", wPid, err)
			}
			if err := unix.PtraceSyscall(wPid, 0); err != nil {
				return fmt.Errorf("failed to call PTRACE_SYSCALL (pid=%d) %w", wPid, err)
			}
			continue
		default:
			switch {
			case ws.Exited():
				exitStatus := ws.ExitStatus()
				logrus.Debugf("Process %d exited with status %d", wPid, exitStatus)
				if wPid == tracer.cmd.Process.Pid {
					logrus.Debugf("Exiting... (%d)", exitStatus)
					os.Exit(exitStatus)
				}
				if err := unix.PtraceDetach(wPid); err != nil {
					logrus.Debugf("ptrace_detach: %v", err)
				}
				delete(scMap, wPid)
				continue
			case ws.Stopped():
				sig := ws.StopSignal()
				switch sig {
				// magic value 0x80: see ptrace(2), O_TRACESYSGOOD
				case 0x80 | unix.SIGTRAP:
					if err = unix.PtraceGetRegs(wPid, &sc.Regs.PtraceRegs); err != nil {
						return fmt.Errorf("failed to read registers for %d: %w", wPid, err)
					}
					sc.Entry = !sc.Entry
					if sc.Entry {
						sc.Num = sc.Regs.Syscall()
						sc.OldRegs = sc.Regs
					}
					if err := tracer.personality.HandleSyscall(sc); err != nil {
						return err
					}
					if err = unix.PtraceSetRegs(sc.Pid, &sc.Regs.PtraceRegs); err != nil {
						return fmt.Errorf("failed to set regs %s: %w", sc.Regs.String(), err)
					}
				case unix.SIGTRAP:
					logrus.Debugf("Got real SIGTRAP from %d - program is in trouble.", wPid)
					val, _ := os.LookupEnv("LSF_SIGTRAP_GDB")
					if val == "1" {
						logrus.Debugf("LSF_SIGTRAP_GDB set - Handing off to gdb")
						err = unix.PtraceSyscall(wPid, int(unix.SIGSTOP))
						if err != nil {
							return err
						}
						err = unix.PtraceDetach(wPid)
						if err != nil {
							return err
						}
						binary, err := exec.LookPath("gdb")
						if err != nil {
							return err
						}
						args := []string{"gdb", "-ex", "set osabi none", "-ex", fmt.Sprintf("attach %d", wPid)}
						env := os.Environ()
						panic(syscall.Exec(binary, args, env))
					}
				case unix.SIGSEGV, unix.SIGABRT, unix.SIGILL:
					if getRegErr := unix.PtraceGetRegs(wPid, &sc.Regs.PtraceRegs); getRegErr == nil {
						return fmt.Errorf("got signal %v PC=0x%x (regs: %s)", sig, sc.Regs.PC(), sc.Regs.String())
					}
					return fmt.Errorf("got signal %v (regs: N/A)", sig)
				default:
					logrus.Debugf("ignoring SIGSTOP (ws=%+v (0x%x))", ws, ws)
				}
			}
		}
		if err := unix.PtraceSyscall(wPid, 0); err != nil {
			return fmt.Errorf("failed to call PTRACE_SYSCALL (pid=%d) %w", wPid, err)
		}
	}
}

func AllocScratch(pid int, regs *Regs, size uint64) (uint64, error) {
	mmapIn := regs.PtraceRegs
	mmapIn.Rax = unix.SYS_MMAP
	mmapIn.Rdi = 0
	mmapIn.Rsi = size
	mmapIn.Rdx = unix.PROT_READ | unix.PROT_WRITE
	mmapIn.R10 = unix.MAP_ANON | unix.MAP_PRIVATE
	mmapIn.R8 = 0xffffffff
	mmapIn.R9 = 0
	mmapOut, err := procutil.InjectSyscall(pid, mmapIn)
	if err != nil {
		return 0, err
	}
	if int64(mmapOut.Rax) < 0 {
		return 0, fmt.Errorf("Failed to mmap scratch space: %d", mmapOut.Rax)
	}
	return mmapOut.Rax, nil
}
