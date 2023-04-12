#ifndef MLIBC_DANDELION_H
#define MLIBC_DANDELION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

struct io_buf {
	io_buf* next;
	const char* ident;

	void* buffer;
	size_t size;
};

struct io_set {
	io_set* next;
	const char* ident;

	io_buf* buf_head;
};

struct dandelion {
	io_buf stdin;
	io_buf stdout;
	io_buf stderr;

	io_set input_root;
	io_set output_root;
};

extern struct dandelion dandelion;

#ifdef __cplusplus
}; // extern "C"
#endif

#endif