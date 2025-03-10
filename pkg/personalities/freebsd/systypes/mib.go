package freebsd

import "fmt"

// https://github.com/freebsd/freebsd-src/blob/release/13.1.0/sys/sys/sysctl.h
const (
	CTL_SYSCTL = 0
	// CTL_KERN = 1 is defiend in zerrors_*.go
	CTL_VM  = 2
	CTL_VFS = 3
	// CTL_NET  = 4 is defiend in zerrors_*.go
	CTL_DEBUG = 5
	// CTL_HW   = 6 is defiend in zerrors_*.go
	CTL_MACHDEP = 7
	CTL_USER    = 8

	CTL_SYSCTL_DEBUG    = 0
	CTL_SYSCTL_NAME     = 1
	CTL_SYSCTL_NEXT     = 2
	CTL_SYSCTL_NAME2OID = 3

	KERN_OSTYPE                    = 1
	KERN_OSRELEASE                 = 2
	KERN_OSREV                     = 3
	KERN_VERSION                   = 4
	KERN_MAXVNODES                 = 5
	KERN_MAXPROC                   = 6
	KERN_MAXFILES                  = 7
	KERN_ARGMAX                    = 8
	KERN_SECURELVL                 = 9
	KERN_HOSTNAME                  = 10
	KERN_HOSTID                    = 11
	KERN_CLOCKRATE                 = 12
	KERN_VNODE                     = 13
	KERN_PROC                      = 14
	KERN_FILE                      = 15
	KERN_PROF                      = 16
	KERN_POSIX1                    = 17
	KERN_NGROUPS                   = 18
	KERN_JOB_CONTROL               = 19
	KERN_SAVED_IDS                 = 20
	KERN_BOOTTIME                  = 21
	KERN_NISDOMAINNAME             = 22
	KERN_UPDATEINTERVAL            = 23
	KERN_OSRELDATE                 = 24
	KERN_NTP_PLL                   = 25
	KERN_BOOTFILE                  = 26
	KERN_MAXFILESPERPROC           = 27
	KERN_MAXPROCPERUID             = 28
	KERN_DUMPDEV                   = 29
	KERN_IPC                       = 30
	KERN_DUMMY                     = 31
	KERN_PS_STRINGS                = 32
	KERN_USRSTACK                  = 33
	KERN_LOGSIGEXIT                = 34
	KERN_IOV_MAX                   = 35
	KERN_HOSTUUID                  = 36
	KERN_ARND                      = 37
	KERN_MAXPHYS                   = 38
	KERN_LOCKF                     = 39
	KERN_PROC_OSREL = 40

	VM_OVERCOMMIT = 12

	// HW_MACHINE = 1 is defined in zerrors_*.go
)

func MibString(mib []uint32) string {
	// FIXME: hash
	m0 := map[int]string{
		CTL_SYSCTL:  "sysctl",
		CTL_KERN:    "kern",
		CTL_VM:      "vm",
		CTL_DEBUG:   "debug",
		CTL_HW:      "hw",
		CTL_MACHDEP: "machdep",
		CTL_USER:    "user",
	}
	m1 := map[int]map[int]string{
		CTL_SYSCTL: map[int]string{
			CTL_SYSCTL_DEBUG:    "debug",
			CTL_SYSCTL_NAME:     "name",
			CTL_SYSCTL_NEXT:     "next",
			CTL_SYSCTL_NAME2OID: "name2oid",
		},
		CTL_KERN: map[int]string{
			KERN_OSTYPE:    "ostype",
			KERN_OSRELEASE: "osrelease",
			KERN_OSREV:     "osrev",
			KERN_VERSION:   "version",
			KERN_HOSTNAME:  "hostname",
			KERN_PROC:      "proc",
			KERN_OSRELDATE: "osreldate",
			KERN_ARND:      "arnd",
			KERN_MAXPHYS:   "maxphys",
			KERN_USRSTACK:  "usrstack",
		},
		CTL_VM: map[int]string{
			VM_OVERCOMMIT: "overcommit",
		},
		CTL_HW: map[int]string{
			HW_MACHINE: "machine",
			HW_PAGESIZE: "pagesizes",
			HW_NCPU: "ncpu",
		},
	}
	m2 := map[int]map[int]map[int]string{
		CTL_KERN: map[int]map[int]string{
			KERN_PROC: map[int]string{
				KERN_PROC_OSREL: "osrel",
			},
		},
	}

	var s string
	for i := range mib {
		switch i {
		case 0:
			if comp, ok := m0[int(mib[0])]; ok {
				s = comp
			} else {
				s = fmt.Sprintf("%d", mib[0])
			}
		case 1:
			if comp, ok := m1[int(mib[0])][int(mib[1])]; ok {
				s += "." + comp
			} else {
				s += fmt.Sprintf(".%d", mib[1])
			}
		case 2:
			if comp, ok := m2[int(mib[0])][int(mib[1])][int(mib[2])]; ok {
				s += "." + comp
			} else {
				s += fmt.Sprintf(".%d", mib[2])
			}
		default:
			s += fmt.Sprintf(".%d", mib[i])
		}
	}
	return s
}
