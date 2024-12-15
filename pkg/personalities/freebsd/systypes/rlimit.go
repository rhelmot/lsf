package freebsd

import (
	"syscall"
)

var RlimitMapping = map[uint64]uint64 {
	RLIMIT_AS: syscall.RLIMIT_AS,
	RLIMIT_CORE: syscall.RLIMIT_CORE,
	RLIMIT_CPU: syscall.RLIMIT_CPU,
	RLIMIT_DATA: syscall.RLIMIT_DATA,
	RLIMIT_FSIZE: syscall.RLIMIT_FSIZE,
	RLIMIT_NOFILE: syscall.RLIMIT_NOFILE,
	RLIMIT_STACK: syscall.RLIMIT_STACK,
}
