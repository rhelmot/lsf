package freebsd

import (
	"syscall"
)

var FcntlCmdMapping = map[uint64]uint64 {
	F_DUPFD: syscall.F_DUPFD,
	F_DUPFD_CLOEXEC: syscall.F_DUPFD_CLOEXEC,
	F_GETFD: syscall.F_GETFD,
	F_SETFD: syscall.F_SETFD,
	F_GETFL: syscall.F_GETFL,
	F_SETFL: syscall.F_SETFL,
	F_SETOWN: syscall.F_SETOWN,
	//F_READAHEAD:
	//F_FDAHEAD:
	//F_ADD_SEALS:
	//F_ISUNIONSTACK:
	//F_KINFO:
}

var OpenFlagsMapping = map[uint64]uint64 {
	// O_ACCMODE: N/A
	O_APPEND:    syscall.O_APPEND,
	O_ASYNC:     syscall.O_ASYNC,
	O_CLOEXEC:   syscall.O_CLOEXEC,
	O_CREAT:     syscall.O_CREAT,
	O_DIRECT:    syscall.O_DIRECT,
	O_DIRECTORY: syscall.O_DIRECTORY,
	O_EXCL:      syscall.O_EXCL,
	// O_EXEC: N/A
	// O_EXLOCK: N/A
	O_FSYNC:    syscall.O_FSYNC,
	O_NDELAY:   syscall.O_NDELAY,
	O_NOCTTY:   syscall.O_NOCTTY,
	O_NOFOLLOW: syscall.O_NOFOLLOW,
	// O_NONBLOCK: an alias of O_NDELAY
	O_RDONLY: syscall.O_RDONLY,
	O_RDWR:   syscall.O_RDWR,
	// O_RESOLVE_BENEATH: N/A
	// O_SEARCH: N/A
	// O_SHLOCK: N/A
	// O_SYNC: an alias of O_FSYNC
	O_TRUNC: syscall.O_TRUNC,
	// O_TTY_INIT: N/A
	// O_VERIFY: N/A
	O_WRONLY: syscall.O_WRONLY,
}

var FcntlFdFlagsMapping = map[uint64]uint64 {
	FD_CLOEXEC: syscall.FD_CLOEXEC,
}
