#ifndef MLIBC_DANDELION_H
#define MLIBC_DANDELION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

struct io_buf {
	struct io_buf* next;
	const char* ident;

	void* buffer;
	size_t size;
};

struct io_set {
	struct io_set* next;
	const char* ident;

	struct io_buf* buf_head;
};

struct dandelion {
	const void * __capability return_pair;
	int exit_code;

	size_t heap_offset;

	struct io_buf stdin;
	struct io_buf stdout;
	struct io_buf stderr;

	struct io_set input_root;
	struct io_set output_root;
};

extern struct dandelion dandelion;

#ifdef __cplusplus
}; // extern "C"
#endif

#endif
