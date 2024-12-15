package freebsd

import (
	"fmt"
	freebsd "github.com/AkihiroSuda/lsf/pkg/personalities/freebsd/systypes"
	"github.com/AkihiroSuda/lsf/pkg/tracer"
)

func rlimitHandler(sysno uint64) tracer.SyscallHandler {
	return func(sc *tracer.SyscallCtx) error {
		if sc.Entry {
			bsdRlimit := sc.Regs.Arg(0)
			linuxRlimit, ok := freebsd.RlimitMapping[bsdRlimit]
			if !ok {
				return stubHandler(freebsd.EINVAL, fmt.Sprintf("Invalid rlimit %d", bsdRlimit))(sc)
			} else {
				sc.Regs.SetArg(0, linuxRlimit)
			}
		}
		return simpleHandler(sysno)(sc)
	}
}
