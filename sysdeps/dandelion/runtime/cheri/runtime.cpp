#include <runtime.hpp>

extern "C" {

const void * __capability __dandelion_return_address;

};

namespace mlibc::runtime {

void enter() {

}

[[noreturn]] void exit() {
	__asm__ volatile(
		"ldr c0, [%0] \n"
		"ldpbr c29, [c0] \n"
		: : "r" (&__dandelion_return_address) : "c0"
	);
    __builtin_unreachable();
}

};