package freebsd

// https://github.com/freebsd/freebsd-src/blob/release/13.1.0/sys/x86/include/sysarch.h#L59
const (
	AMD64_GET_FSBASE = 128
	AMD64_SET_FSBASE = 129
	AMD64_GET_GSBASE = 130
	AMD64_SET_GSBASE = 131
	AMD64_GET_XFPUSTATE = 132
	AMD64_SET_PKRU = 133
	AMD64_CLEAR_PKRU = 134
)
