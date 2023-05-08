#include <runtime.hpp>

#include <sys/syscall.h>
#include <cxx-syscall.hpp>

#define FREEBSD_SYS_EXIT 1
#define FREEBSD_SYS_SYSARCH 165

// from freebsd sources
#define	AMD64_GET_FSBASE	128
#define	AMD64_SET_FSBASE	129
#define	AMD64_GET_GSBASE	130
#define	AMD64_SET_GSBASE	131
#define	AMD64_GET_XFPUSTATE	132
#define	AMD64_SET_PKRU		133
#define	AMD64_CLEAR_PKRU	134

namespace mlibc::runtime {

void enter() {

}

[[noreturn]] void exit() {
	do_syscall(FREEBSD_SYS_EXIT, 0);
	__builtin_unreachable();
}

};