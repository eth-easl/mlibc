#ifndef __MLIBC_DANDELION_RUNTIME_H
#define __MLIBC_DANDELION_RUNTIME_H

#include "dandelion.h"
// convenience alias to avoid polluting global namespace
#define dandelion __dandelion_global_data

namespace mlibc::runtime {

void enter();
[[noreturn]] void exit();

};

#endif