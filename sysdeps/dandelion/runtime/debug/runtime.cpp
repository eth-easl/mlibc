#include <cstddef>
#include <cstdint>
#include <string.h>
#include <sys/types.h>

#include <sys/syscall.h>
#include <cxx-syscall.hpp>
#include <runtime.hpp>

namespace mlibc::runtime {

namespace debug {

int write(int fd, const void *buffer, size_t size, ssize_t *bytes_written) {
	auto ret = do_cp_syscall(SYS_write, fd, buffer, size);
	if(int e = sc_error(ret); e)
		return e;
	*bytes_written = sc_int_result<ssize_t>(ret);
	return 0;
}

int write_all(int fd, const void *buffer, size_t size) {
	size_t written = 0;
	while (written < size) {
		ssize_t bytes_written;
		int e = write(fd, (const char*)buffer + written, size - written, &bytes_written);
		if (e < 0) {
			return e;
		}
		written += bytes_written;
	}
	return 0;
}

void dump_io_buf(const char* setid, io_buf* buf) {
	char tmp[256];
	size_t setidlen = 0;
	if (setid) {
		setidlen = strlen(setid);
		memcpy(tmp, setid, setidlen);
	}
	size_t identlen = 0;
	if (buf->ident) {
		tmp[setidlen] = ' ';
		identlen = strlen(buf->ident);
		memcpy(tmp + setidlen + 1, buf->ident, identlen);
		++identlen;
	}
	tmp[setidlen + identlen] = ':';
	tmp[setidlen + identlen + 1] = '\n';
	write_all(1, tmp, setidlen + identlen + 2);
	write_all(1, buf->buffer, buf->size);
	write_all(1, "\n", 1);
}

void dump_io_set(io_set* set) {
	for (io_buf* buf = set->buf_head; buf; buf = buf->next) {
		dump_io_buf(set->ident, buf);
	}
}

void dump_global_data() {
	debug::dump_io_buf("stdout", &dandelion.stdout);
	debug::dump_io_buf("stderr", &dandelion.stderr);

	for (auto* set = &dandelion.output_root; set != nullptr; set = set->next) {
		debug::dump_io_set(set);
	}
}

}; // namespace debug

void enter() {
	static const char input_file_content[] = "This is an example input file";
	static io_buf example_input_file{nullptr, "input.txt", (void*)input_file_content, sizeof(input_file_content)};
	static io_buf example_output_file{nullptr, "root_output.txt", nullptr, 0};
	static io_set out_set{nullptr, "output", nullptr};

	dandelion.stdin = {nullptr, nullptr, nullptr, 0};
	dandelion.input_root = {nullptr, "", &example_input_file};
	dandelion.output_root = {&out_set, "", &example_output_file};
}

[[noreturn]] void exit() {
    debug::dump_global_data();
	do_syscall(SYS_exit_group, 0);
    __builtin_unreachable();
}

};