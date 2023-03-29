#include <errno.h>
#include <limits.h>
#include <linux/reboot.h>

#include <type_traits>

#include <mlibc-config.h>
#include <bits/ensure.h>
#include <abi-bits/fcntl.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/thread-entry.hpp>
#include <mlibc/allocator.hpp>
#include <limits.h>
#include <sys/syscall.h>
#include "cxx-syscall.hpp"
#include "frg/string.hpp"
#include "mlibc/posix-sysdeps.hpp"
#include "refcounted.hpp"

#include <frg/vector.hpp>
#include <frg/variant.hpp>
#include <frg/hash_map.hpp>

#include <dandelion.h>

#define STUB_ONLY { __ensure(!"STUB_ONLY function was called"); __builtin_unreachable(); }
#define UNUSED(x) (void)(x);

#ifndef MLIBC_BUILDING_RTDL
extern "C" long __do_syscall_ret(unsigned long ret) {
	if(ret > -4096UL) {
		errno = -ret;
		return -1;
	}
	return ret;
}
#endif

namespace mlibc {

namespace vfs {

void test_init_dandelion() {

	static const char input_file_content[] = "This is an example input file";
	static io_buf example_input_file{nullptr, "input.txt", (void*)input_file_content, sizeof(input_file_content), sizeof(input_file_content)};

	dandelion.stdin = {nullptr, nullptr, nullptr, 0, 0};
	dandelion.root_input_set = {nullptr, "/", &example_input_file};
	dandelion.root_output_set = {nullptr, "/", nullptr};
}

void init_io_buf(io_buf* buf, const char* ident, io_buf* next) {
	constexpr size_t initial_bufsize = 1024;

	if (ident) {
		char* owned_ident = static_cast<char*>(getAllocator().allocate(strlen(ident) + 1));
		strcpy(owned_ident, ident);
		buf->ident = owned_ident;
	} else {
		buf->ident = nullptr;
	}

	buf->next = next;
	buf->buffer = getAllocator().allocate(initial_bufsize);
	buf->size = 0;
	buf->capacity = initial_bufsize;
}

io_buf* find_buf_in_set(io_set* set, const char* buf_ident) {
	for (io_buf* current = set->buf_head; current != nullptr; current = current->next) {
		if (current->ident && strcmp(current->ident, buf_ident) == 0) {
			return current;
		}
	}
	return nullptr;
}

io_set* find_set(io_set* root, const char* set_ident, size_t ident_len) {
	// we skip the root set, because it doesn't have an identifier
	for (io_set* current = root->next; current != nullptr; current = current->next) {
		if (strncmp(current->ident, set_ident, ident_len) == 0) {
			return current;
		}
	}
	return nullptr;
}

io_buf* add_buf_to_set(io_set* set, const char* buf_ident) {
	auto* buf = static_cast<io_buf*>(getAllocator().allocate(sizeof(io_buf)));
	::new (buf) io_buf;
	init_io_buf(buf, buf_ident, set->buf_head);
	set->buf_head = buf;
	return buf;
}

char* normalize_path(const char* dir, const char* path) {
	struct PathSegment {
		size_t begin;
		size_t end; // exclusive
	};

	char* base;
	if (path[0] == '/') {
		base = static_cast<char*>(getAllocator().allocate(strlen(path) + 1));
		strcpy(base, path);
	} else {
		size_t dir_len = strlen(dir) + 1;
		size_t path_len = strlen(path) + 1;

		base = static_cast<char*>(getAllocator().allocate(dir_len + path_len));
		memcpy(base, dir, dir_len);
		base[dir_len - 1] = '/';
		memcpy(base + dir_len, path, path_len);
	}

	frg::vector<PathSegment, MemoryAllocator> segs{getAllocator()};
	size_t i = 0;
	while (base[i] != '\0') {
		while (base[i] == '/') {
			++i;
		}
		if (base[i] == '.') {
			// ../ pattern
			if (base[i + 1] == '.' && base[i + 2] == '/') {
				i += 2;
				if (segs.size() > 0) {
					segs.pop();
				}
				continue;
			}
			// ./ pattern - skip
			if (base[i + 1] == '/') {
				i += 1;
				continue;
			}
		}
		size_t begin_idx = i;
		while (base[i] != '/' && base[i] != '\0') {
			++i;
		}
		if (i > begin_idx) {
			segs.emplace_back(begin_idx, i);
		}
	}

	// if there are no segments, simply return a root path
	if (segs.size() == 0) {
		base[0] = '/';
		base[1] = '\0';
		return base;
	}

	size_t write_offset = 0;
	for (const PathSegment& seg : segs) {
		base[write_offset++] = '/';
		memmove(base + write_offset, base + seg.begin, seg.end - seg.begin);
		write_offset += seg.end - seg.begin;
	}
	base[write_offset++] = '\0';

	return base;
}

struct NoEntry {};

class File {
	bool is_static{false};

	std::byte* buf{nullptr};
	size_t bufsize{0};
	size_t bufcap{0};

	void ensure_capacity(size_t target) {
		if (this->bufcap < target) {
			size_t new_cap = 2 * this->bufcap;
			if (new_cap < target) {
				new_cap = target;
			}
			std::byte* new_buf = static_cast<std::byte*>(getAllocator().allocate(new_cap));
			if (this->buf != nullptr) {
				memcpy(new_buf, this->buf, this->bufsize);
				getAllocator().free(this->buf);
			}
			this->buf = new_buf;
			this->bufcap = new_cap;
		}
	}

public:
	File() {}
	File(io_buf* iobuf) : is_static{true}, buf{static_cast<std::byte*>(iobuf->buffer)}, bufsize{iobuf->size} {}

	~File() {
		if (!is_static) {
			getAllocator().free(this->buf);
		}
	}

	size_t size() const {
		return this->bufsize;
	}

	std::byte* buffer() {
		return this->buf;
	}

	void truncate(size_t size) {
		if (size <= this->bufsize) {
			this->bufsize = size;
		} else {
			this->ensure_capacity(size);
			memset(this->buf + this->bufsize, 0, size - this->bufsize);
			this->bufsize = size;
		}
	}

	int read_offset(void* buffer, size_t size, size_t offset, ssize_t* bytes_read) {
		size_t to_read = 0;
		if (offset <= this->bufsize) {
			to_read = std::min(size, this->bufsize - offset);
		}
		memcpy(buffer, this->buf + offset, to_read);
		*bytes_read = to_read;
		return 0;
	}

	int write_offset(const void* buffer, size_t size, size_t offset, ssize_t* bytes_written) {
		if (this->is_static) {
			*bytes_written = -1;
			return EBADF;
		}
		size_t required_size = offset + size;
		ensure_capacity(required_size);
		if (offset > this->bufsize) {
			memset(this->buf + this->bufsize, 0, offset - this->bufsize);
		}
		memcpy(this->buf + offset, buffer, size);
		this->bufsize = required_size;
		*bytes_written = size;
		return 0;
	}
};

using string = frg::string<MemoryAllocator>;

class Directory {
	template <typename T>
	using entry_map = frg::hash_map<string, T, frg::hash<frg::string_view>, MemoryAllocator>;
	
	Rc<Directory> parent;
	entry_map<Rc<File>> files{frg::hash<frg::string_view>(), getAllocator()};
	entry_map<Rc<Directory>> dirs{frg::hash<frg::string_view>(), getAllocator()};

public:
	// Directory() : parent{this} {}
	Directory(Rc<Directory> parent) : parent{parent} {}

	void set_parent(Rc<Directory> parent) {
		this->parent = parent;
	}

	bool is_empty() {
		return this->files.empty() && this->dirs.empty();
	}

	static Rc<File> create_file(Rc<Directory> self, auto name) {
		auto file = Rc<File>::make();
		self->files.insert(string{std::move(name), getAllocator()}, file);
		return file;
	}

	static Rc<Directory> create_dir(Rc<Directory> self, auto name) {
		auto dir = Rc<Directory>::make(self);
		self->dirs.insert(string{std::move(name), getAllocator()}, dir);
		return dir;
	}

	static int remove_file(Rc<Directory> self, frg::string_view name) {
		// TODO
		return 0;
	}

	static int remove_dir(Rc<Directory> self, frg::string_view name) {
		auto dir = self->dirs.get(name);
		if (dir != nullptr) {
			// TODO implement
			if ((*dir)->is_empty()) {
				self->dirs.remove(string{name, getAllocator()});
				return 0;
			} else {
				return ENOTEMPTY;
			}
		}
		auto file = self->files.get(name);
		if (file) {
			return ENOTDIR;
		}
		return ENOENT;
	}

	static frg::variant<NoEntry, Rc<File>, Rc<Directory>> find(Rc<Directory> base, frg::string_view path) {
		for (size_t i = 0;;) {
			// skip slashes
			while (i < path.size() && path[i] == '/') {
				++i;
			}
			// ends with a slash, so is a directory
			if (i == path.size()) {
				return base;
			}
			// check if special dir
			if (path[i] == '.') {
				if (i + 2 < path.size() && path[i + 1] == '.' && path[i + 2] == '/') {
					base = base->parent;
					i += 2;
					continue;
				}
				if (i + 1 < path.size() && path[i + 1] == '/') {
					++i;
					continue;
				}
			}
			// find 
			size_t begin = i;
			while (i < path.size() && path[i] != '/') {
				++i;
			}
			auto sub_path = path.sub_string(begin, i - begin);
			// can only be file if name goes to the very end
			if (i == path.size()) {
				Rc<File>* file = base->files.get(sub_path);
				if (file != nullptr) {
					return *file;
				}
			}

			Rc<Directory>* dir = base->dirs.get(sub_path);
			if (dir != nullptr) {
				base = *dir;
			} else {
				return NoEntry{};
			}
		}
		// should be unreachable
		return NoEntry{};
	}

};

// void add_set_bufs(Directory* dir, io_set& set, int access) {
// 	for (auto* buf = set.buf_head; buf != nullptr; buf = buf->next) {
// 		if (buf->ident != nullptr) {
// 			dir->create_file(buf->ident, buf, access);
// 		}
// 	}
// };

// void add_sets(io_set& setroot, int access) {
// 	add_set_bufs(this->root, setroot, access);
// 	for (auto* set = setroot.next; set != nullptr; set = set->next) {
// 		if (set->ident != nullptr) {
// 			auto* dir = this->root->create_dir(set->ident);
// 			add_set_bufs(dir, *set, access);
// 		}

// 	}
// }

// add_set_bufs(this->root, dandelion.root_input_set, O_RDONLY);
// this->add_sets(dandelion.root_input_set, O_RDONLY);

// add_set_bufs(this->root, dandelion.root_output_set, O_RDWR);
// this->add_sets(dandelion.root_output_set, O_RDWR);


class FileTableEntry {
public:
	struct OpenFile {
		Rc<File> data;
		size_t offset;
		int flags;

		int access() {
			return this->flags & 0b11;
		}
	};

	struct OpenDir {
		Rc<Directory> dir;
	};
private:

	frg::variant<OpenFile, OpenDir> internal;
	
	friend class FileTable;
	friend void sys_exit(int status);

public:
	FileTableEntry(OpenFile fdata) : internal{std::move(fdata)} {};
	FileTableEntry(OpenDir dirdata) : internal{std::move(dirdata)} {};

	int read(void* buffer, size_t size, ssize_t* bytes_read) {
		if (this->internal.is<OpenDir>()) {
			*bytes_read = -1;
			return EISDIR;
		} else if (this->internal.is<OpenFile>()) {
			OpenFile& file = this->internal.get<OpenFile>();
			if (!(file.access() == O_RDWR || file.access() == O_RDONLY)) {
				*bytes_read = -1;
				return EBADF;
			}
			int code = file.data->read_offset(buffer, size, file.offset, bytes_read);
			if (code == 0) {
				file.offset += *bytes_read;
			}
			return code;
		} else {
			*bytes_read = -1;
			mlibc::panicLogger() << "Invalid FileTableEntry type encountered" << frg::endlog;
			return EIO;
		}
	}

	int write(const void* buffer, size_t size, ssize_t* bytes_written) {
		if (this->internal.is<OpenDir>()) {
			*bytes_written = -1;
			return EISDIR;
		} else if (this->internal.is<OpenFile>()) {
			OpenFile& file = this->internal.get<OpenFile>();
			if (!(file.access() == O_RDWR || file.access() == O_WRONLY)) {
				*bytes_written = -1;
				return EBADF;
			}
			if (file.flags & O_APPEND) {
				file.offset = file.data->size();
			}
			int code = file.data->write_offset(buffer, size, file.offset, bytes_written);
			if (code == 0) {
				file.offset += *bytes_written;
			}
			return code;
		} else {
			mlibc::panicLogger() << "Invalid FileTableEntry type encountered" << frg::endlog;
			return EIO;
		}
	}

	int seek(off_t offset, int whence, off_t *new_offset) {
		if (this->internal.is<OpenDir>()) {
			*new_offset = -1;
			// TODO: check: is EISDIR a valid error of seek?
			return EISDIR;
		} else if (this->internal.is<OpenFile>()) {
			OpenFile& openfile = this->internal.get<OpenFile>();
			if (whence == SEEK_SET && offset >= 0) {
				openfile.offset = static_cast<size_t>(offset);
			} else if (whence == SEEK_CUR && (offset >= 0  || (openfile.offset >= static_cast<size_t>(-offset)))) {
				openfile.offset += offset;
			} else if (whence == SEEK_END && (offset >= 0 || static_cast<size_t>(-offset) <= openfile.data->size())) {
				openfile.offset = openfile.data->size() + offset;
			} else {
				*new_offset = -1;
				return EINVAL;
			}
			return 0;
		} else {
			mlibc::panicLogger() << "Invalid FileTableEntry type encountered" << frg::endlog;
			return EIO;
		}
	}

	Rc<File> get_file() {
		if (this->internal.is<OpenFile>()) {
			return this->internal.get<OpenFile>().data;
		}
		return nullptr;
	}

	Rc<Directory> get_dir() {
		if (this->internal.is<OpenDir>()) {
			return this->internal.get<OpenDir>().dir;
		}
		return nullptr;
	}
};

frg::string_view path_filename(const char* path) {
	size_t dirname_len = strlen(path);
	while (dirname_len > 0 && path[dirname_len - 1] != '/') {
		--dirname_len;
	}
	return {path + dirname_len};
}

frg::string_view path_dirname(const char* path) {
	size_t dirname_len = strlen(path);
	while (dirname_len > 0 && path[dirname_len - 1] != '/') {
		--dirname_len;
	}
	return {path, dirname_len};
}

class FileTable {
	frg::vector<Rc<FileTableEntry>, MemoryAllocator> open_files{getAllocator()};
	Rc<Directory> working_dir;
	Rc<Directory> fs_root;

	size_t find_free_slot() {
		for (size_t i = 0; i < open_files.size(); ++i) {
			if (open_files[i] == nullptr) {
				return i;
			}
		}
		open_files.push_back(nullptr);
		return open_files.size() - 1;
	}

	void ensure_slot(int slot) {
		size_t target_len = static_cast<size_t>(slot) + 1;
		this->open_files.resize(target_len, nullptr);
	}

	int check_fd(int fd) {
		if (fd < 0 || static_cast<size_t>(fd) >= this->open_files.size()) {
			return EBADF;
		}
		return 0;
	}

	void set_entry_at(size_t idx, Rc<FileTableEntry> entry) {
		this->open_files[idx] = std::move(entry);
	}

	int create_entry(auto&&... args) {
		size_t idx = this->find_free_slot();
		this->create_entry_at(idx, std::forward<decltype(args)>(args)...);
		return static_cast<int>(idx);
	}

	void create_entry_at(size_t idx, auto&&... args) {
		if (this->open_files.size() < idx + 1) {
			this->open_files.resize(idx + 1);
		}
		auto entry = Rc<FileTableEntry>::make(std::forward<decltype(args)>(args)...);
		this->open_files[idx] = std::move(entry);
	}

	Rc<Directory> get_base(int dirfd, const char* path) {
		Rc<Directory> base;
		if (dirfd == AT_FDCWD) {
			base = this->working_dir;
		} else if (path[0] == '/') {
			base = this->fs_root;
		} else {
			auto entry = this->get(dirfd);
			if (entry == nullptr) {
				return nullptr;
			}
			base = entry->get_dir();
			if (base == nullptr) {
				return nullptr;
			}
		}
		return base;
	}

public:
	FileTable() {
		// test_init_dandelion();

		this->fs_root = Rc<Directory>::make(Rc<Directory>{nullptr});
		this->fs_root->set_parent(this->fs_root);
		this->working_dir = this->fs_root;


		this->create_entry_at(0,
			FileTableEntry::OpenFile {
				Rc<File>::make(),
				0,
				O_RDONLY
		});

		this->create_entry_at(1,
			FileTableEntry::OpenFile {
				Rc<File>::make(),
				0,
				O_WRONLY
		});
		this->create_entry_at(2,
			FileTableEntry::OpenFile {
				Rc<File>::make(),
				0,
				O_WRONLY
		});

		// TESTING
		// __ensure(!strcmp(normalize_path("/hello/world", "../testpath/./file.txt"), "/hello/testpath/file.txt"));
		// __ensure(!strcmp(normalize_path("/hello/.loca/", "../testpath/./../end/./file.txt"), "/hello/end/file.txt"));
		// add_buf_to_set(&dandelion.root_output_set, "hello.txt");
	}

	int set_cwd(const char* path) {
		return 0;
	}

	const char* get_cwd() const {
		return nullptr;
	}

	int openat(int dirfd, const char* path, int flags, int* fd) {
		auto base = this->get_base(dirfd, path);

		int access = flags & 0b11;

		auto res = Directory::find(base, path);

		if (res.is<Rc<Directory>>()) {
			auto dir = res.get<Rc<Directory>>();

			*fd = this->create_entry(FileTableEntry::OpenDir{dir});
			return 0;
		} 

		Rc<File> file;
		if (res.is<Rc<File>>()) {
			file = res.get<Rc<File>>();

			if ((flags & O_CREAT) && (flags & O_EXCL)) {
				*fd = -1;
				return EEXIST;
			}
		} else if (res.is<NoEntry>()) {
			if (!(flags & O_CREAT)) {
				*fd = -1;
				return EACCES;
			}

			auto dirname = path_dirname(path);
			Rc<Directory> loc = base;
			if (dirname.size() > 0) {
				auto res = Directory::find(base, dirname);
				if (res.is<Rc<Directory>>()) {
					loc = res.get<Rc<Directory>>();
				} else {
					*fd = -1;
					return EINVAL;
				}
			}

			file = Directory::create_file(loc, path_filename(path));
		}

		// if we're opening in truncation mode, set the size of the file to 0
		// note that this doesn't actually modify the file buffer
		if ((flags & O_TRUNC) && (access == O_RDWR || access == O_WRONLY)) {
			file->truncate(0);
		}

		*fd = this->create_entry(
			FileTableEntry::OpenFile {
				file,
				flags & O_APPEND ? file->size() : 0,
				flags,
			}
		);

		return 0;
	}

	int mkdirat(int dirfd, const char* path) {
		auto base = this->get_base(dirfd, path);
		auto loc = Directory::find(base, path_dirname(path));
		if (loc.is<Rc<Directory>>()) {
			auto locdir = loc.get<Rc<Directory>>();
			// TODO remove trailing slash from pathname
			// TODO check that filename isn't empty
			// TODO chck if exists 
			Directory::create_dir(locdir, path_filename(path));
			return 0;
		} else {
			// TODO correct error code
			return ENOTDIR;
		}
	}

	int unlinkat(int dirfd, const char* path, int flags) {
		auto base = this->get_base(dirfd, path);
		auto loc = Directory::find(base, path_dirname(path));
		if (loc.is<Rc<Directory>>()) {
			auto locdir = loc.get<Rc<Directory>>();
			// TODO remove trailing slash from pathname
			// TODO check that filename isn't empty
			if (flags & AT_REMOVEDIR) {
				return Directory::remove_dir(locdir, path_filename(path));
			} else {
				return Directory::remove_file(locdir, path_filename(path));
			}
		} else if (loc.is<Rc<File>>()) {
			return ENOTDIR;
		} else {
			return ENOENT;
		}
	}

	Rc<FileTableEntry> get(int fd) {
		if (check_fd(fd)) {
			return nullptr;
		}
		return this->open_files[fd];
	}

	int dup2(int srcfd, int targetfd) {
		if (srcfd == targetfd) {
			return 0;
		}
		auto source = this->get(srcfd);
		if (source == nullptr) {
			return EBADF;
		}
		this->close(targetfd);
		this->set_entry_at(targetfd, source);
		return 0;
	}

	int dup(int srcfd, int* outfd) {
		int newfd = this->find_free_slot();
		if (int e = dup2(srcfd, newfd); e) {
			return e;
		}
		*outfd = newfd;
		return 0;
	}

	int close(int fd) {
		if (fd <= 0 && static_cast<size_t>(fd) < this->open_files.size()) {
			this->open_files[fd] = nullptr;
			return 0;
		}
		return EBADF;
	}
};

FileTable& get_file_table() {
	static frg::eternal<FileTable> list;
	return *list;
}


};

void sys_libc_log(const char *message) {
	size_t n = 0;
	while(message[n])
		n++;
	char lf = '\n';
	ssize_t written;
	sys_write(2, message, n, &written);
	sys_write(2, &lf, 1, &written);
}

void sys_libc_panic() {
	// __builtin_trap();
	// try exiting abnormally instead of causing trap
	sys_exit(6); 
}

int sys_tcb_set(void *pointer) {
#if defined(__x86_64__)
	auto ret = do_syscall(SYS_arch_prctl, 0x1002 /* ARCH_SET_FS */, pointer);
	if(int e = sc_error(ret); e)
		return e;
#elif defined(__riscv)
	uintptr_t thread_data = reinterpret_cast<uintptr_t>(pointer) + sizeof(Tcb);
	asm volatile ("mv tp, %0" :: "r"(thread_data));
#elif defined (__aarch64__)
	uintptr_t thread_data = reinterpret_cast<uintptr_t>(pointer) + sizeof(Tcb) - 0x10;
	asm volatile ("msr tpidr_el0, %0" :: "r"(thread_data));
#else
#error "Missing architecture specific code."
#endif
	return 0;
}

int sys_anon_allocate(size_t size, void **pointer) {
	return sys_vm_map(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			-1, 0, pointer);
}

int sys_anon_free(void *pointer, size_t size) {
	return sys_vm_unmap(pointer, size);
}

int sys_fadvise(int fd, off_t offset, off_t length, int advice) {
	(void)fd, (void)offset, (void)length, (void)advice;
	return 0;
}

int sys_open(const char *path, int flags, mode_t mode, int *fd) {
	(void)mode;
	return vfs::get_file_table().openat(AT_FDCWD, path, flags, fd);
}

int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
	(void)mode;
	return vfs::get_file_table().openat(dirfd, path, flags, fd);
}

int sys_close(int fd) {
	return vfs::get_file_table().close(fd);
}

int sys_dup2(int fd, int flags, int newfd) {
	(void)flags;
	return vfs::get_file_table().dup2(fd, newfd);
}

int sys_read(int fd, void *buffer, size_t size, ssize_t *bytes_read) {
	auto file = vfs::get_file_table().get(fd);
	if (file == nullptr) {
		return EBADF;
	}
	return file->read(buffer ,size, bytes_read);
}

int sys_read_old(int fd, void *buffer, size_t size, ssize_t *bytes_read) {
	auto ret = do_cp_syscall(SYS_read, fd, buffer, size);
	if(int e = sc_error(ret); e)
		return e;
	*bytes_read = sc_int_result<ssize_t>(ret);
	return 0;
}

int sys_write(int fd, const void *buffer, size_t size, ssize_t *bytes_written) {
	auto file = vfs::get_file_table().get(fd);
	if (file == nullptr) {
		return EBADF;
	}
	return file->write(buffer, size, bytes_written);
}

int sys_write_old(int fd, const void *buffer, size_t size, ssize_t *bytes_written) {
	auto ret = do_cp_syscall(SYS_write, fd, buffer, size);
	if(int e = sc_error(ret); e)
		return e;
	*bytes_written = sc_int_result<ssize_t>(ret);
	return 0;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
	auto file = vfs::get_file_table().get(fd);
	if (file == nullptr) {
		return EBADF;
	}
	return file->seek(offset, whence, new_offset);
}

int sys_seek_old(int fd, off_t offset, int whence, off_t *new_offset) {
	auto ret = do_syscall(SYS_lseek, fd, offset, whence);
	if(int e = sc_error(ret); e)
		return e;
	*new_offset = sc_int_result<off_t>(ret);
	return 0;
}

int sys_chmod(const char *pathname, mode_t mode) {
	(void)pathname;
	(void)mode;
	return 0;
}

int sys_fchmod(int fd, mode_t mode) {
	(void)fd;
	(void)mode;
	return 0;
}

int sys_fchmodat(int fd, const char *pathname, mode_t mode, int flags) {
	(void)fd;
	(void)pathname;
	(void)mode;
	(void)flags;
	return 0;
}

int sys_fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {
	(void)dirfd;
	(void)pathname;
	(void)owner;
	(void)group;
	(void)flags;
	return 0;
}

int sys_utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) {
	(void)dirfd, (void)pathname, (void)times, (void)flags;
	return 0;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags,
		int fd, off_t offset, void **window) {
	auto ret = do_syscall(SYS_mmap, hint, size, prot, flags, fd, offset);
	// TODO: musl fixes up EPERM errors from the kernel.
	if(int e = sc_error(ret); e)
		return e;
	*window = sc_ptr_result<void>(ret);
	return 0;
}

int sys_vm_unmap(void *pointer, size_t size) {
	auto ret = do_syscall(SYS_munmap, pointer, size);
	if(int e = sc_error(ret); e)
		return e;
	return 0;
}

// All remaining functions are disabled in ldso.
#ifndef MLIBC_BUILDING_RTDL

int sys_clock_get(int clock, time_t *secs, long *nanos) {
	struct timespec tp = {};
	auto ret = do_syscall(SYS_clock_gettime, clock, &tp);
	if (int e = sc_error(ret); e)
		return e;
	*secs = tp.tv_sec;
	*nanos = tp.tv_nsec;
	return 0;
}

int sys_clock_getres(int clock, time_t *secs, long *nanos) {
	(void)clock;
	// pretend that all clocks have microsecond precision
	*secs = 0;
	*nanos = 1000;
	return 0;
}

int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
	if (fsfdt == fsfd_target::path)
		fd = AT_FDCWD;
	else if (fsfdt == fsfd_target::fd)
		flags |= AT_EMPTY_PATH;
	else
		__ensure(fsfdt == fsfd_target::fd_path);

	auto ret = do_cp_syscall(SYS_newfstatat, fd, path, statbuf, flags);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_statfs(const char *path, struct statfs *buf) {
	auto ret = do_cp_syscall(SYS_statfs, path, buf);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_fstatfs(int fd, struct statfs *buf) {
	auto ret = do_cp_syscall(SYS_fstatfs, fd, buf);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

// extern "C" void __mlibc_signal_restore(void);

int sys_sigaction(int signum, const struct sigaction *act,
                struct sigaction *oldact) {
	(void)signum, (void)act, (void)oldact;
	// pretend that we installed the signal handler
	return 0; 
	// struct ksigaction {
	// 	void (*handler)(int);
	// 	unsigned long flags;
	// 	void (*restorer)(void);
	// 	sigset_t mask;
	// };

	// struct ksigaction kernel_act, kernel_oldact;
	// if (act) {
	// 	kernel_act.handler = act->sa_handler;
	// 	kernel_act.flags = act->sa_flags | SA_RESTORER;
	// 	kernel_act.restorer = __mlibc_signal_restore;
	// 	kernel_act.mask = act->sa_mask;
	// }
    //     auto ret = do_syscall(SYS_rt_sigaction, signum, act ?
	// 		&kernel_act : NULL, oldact ?
	// 		&kernel_oldact : NULL, sizeof(sigset_t));
    //     if (int e = sc_error(ret); e)
    //             return e;

	// if (oldact) {
	// 	oldact->sa_handler = kernel_oldact.handler;
	// 	oldact->sa_flags = kernel_oldact.flags;
	// 	oldact->sa_restorer = kernel_oldact.restorer;
	// 	oldact->sa_mask = kernel_oldact.mask;
	// }
    //     return 0;
}

int sys_socket(int domain, int type, int protocol, int *fd) {
        auto ret = do_syscall(SYS_socket, domain, type, protocol);
        if (int e = sc_error(ret); e)
                return e;
        *fd = sc_int_result<int>(ret);
        return 0;
}

int sys_msg_send(int sockfd, const struct msghdr *msg, int flags, ssize_t *length) {
        auto ret = do_cp_syscall(SYS_sendmsg, sockfd, msg, flags);
        if (int e = sc_error(ret); e)
                return e;
        *length = sc_int_result<ssize_t>(ret);
        return 0;
}

int sys_msg_recv(int sockfd, struct msghdr *msg, int flags, ssize_t *length) {
        auto ret = do_cp_syscall(SYS_recvmsg, sockfd, msg, flags);
        if (int e = sc_error(ret); e)
                return e;
        *length = sc_int_result<ssize_t>(ret);
        return 0;
}

int sys_fcntl(int fd, int cmd, va_list args, int *result) {
        auto arg = va_arg(args, unsigned long);
        // TODO: the api for linux differs for each command so fcntl()s might fail with -EINVAL
        // we should implement all the different fcntl()s
	// TODO(geert): only some fcntl()s can fail with -EINTR, making do_cp_syscall useless
	// on most fcntls(). Another reason to handle different fcntl()s seperately.
        auto ret = do_cp_syscall(SYS_fcntl, fd, cmd, arg);
        if (int e = sc_error(ret); e)
                return e;
        *result = sc_int_result<int>(ret);
        return 0;
}

int sys_getcwd(char *buf, size_t size) {
	const char* cwd = vfs::get_file_table().get_cwd();
	size_t cwd_len = strlen(cwd) + 1;
	if (size < cwd_len) {
		return ERANGE;
	}
	strcpy(buf, cwd);
	return 0;
}

int sys_unlinkat(int dfd, const char *path, int flags) {
	return vfs::get_file_table().unlinkat(dfd, path, flags);
}

int sys_sleep(time_t *secs, long *nanos) {
	(void)secs;
	(void)nanos;
	return 0;
}

int sys_isatty(int fd) {
	(void)fd;
	return ENOTTY;
}

#if __MLIBC_POSIX_OPTION

#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <fcntl.h>

int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
	(void)fd;
	(void)request;
	(void)arg;
	(void)result;
	return ENOTTY;
}

int sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
        auto ret = do_cp_syscall(SYS_connect, sockfd, addr, addrlen);
        if (int e = sc_error(ret); e)
                return e;
        return 0;
}

int sys_pselect(int nfds, fd_set *readfds, fd_set *writefds,
                fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask, int *num_events) {
        // The Linux kernel really wants 7 arguments, even tho this is not supported
        // To fix that issue, they use a struct as the last argument.
        // See the man page of pselect and the glibc source code
        struct {
                sigset_t ss;
                size_t ss_len;
        } data;
        data.ss = (uintptr_t)sigmask;
        data.ss_len = NSIG / 8;

        auto ret = do_cp_syscall(SYS_pselect6, nfds, readfds, writefds,
                        exceptfds, timeout, &data);
        if (int e = sc_error(ret); e)
                return e;
        *num_events = sc_int_result<int>(ret);
        return 0;
}

int sys_pipe(int *fds, int flags) {
        if(flags) {
                auto ret = do_syscall(SYS_pipe2, fds, flags);
                if (int e = sc_error(ret); e)
                        return e;
                return 0;
        } else {
				auto ret = do_syscall(SYS_pipe2, fds, 0);
                if (int e = sc_error(ret); e)
                        return e;
                return 0;
        }
}

int sys_fork(pid_t *child) {
	(void)child;
	return ENOSYS;
}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	(void)pid;
	(void)status;
	(void)flags;
	(void)ru;
	(void)ret_pid;
	return ECHILD;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
	(void)path;
	(void)argv;
	(void)envp;
	return EACCES;
}

int sys_sigprocmask(int how, const sigset_t *set, sigset_t *old) {
        auto ret = do_syscall(SYS_rt_sigprocmask, how, set, old, NSIG / 8);
        if (int e = sc_error(ret); e)
                return e;
	return 0;
}

int sys_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
	auto ret = do_syscall(SYS_setresuid, ruid, euid, suid);
        if (int e = sc_error(ret); e)
                return e;
	return 0;
}

int sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
	auto ret = do_syscall(SYS_setresgid, rgid, egid, sgid);
        if (int e = sc_error(ret); e)
                return e;
	return 0;
}

int sys_setreuid(uid_t ruid, uid_t euid) {
	auto ret = do_syscall(SYS_setreuid, ruid, euid);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_setregid(gid_t rgid, gid_t egid) {
	auto ret = do_syscall(SYS_setregid, rgid, egid);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_sysinfo(struct sysinfo *info) {
	auto ret = do_syscall(SYS_sysinfo, info);
        if (int e = sc_error(ret); e)
                return e;
	return 0;
}

void sys_yield() {
	// do_syscall(SYS_sched_yield);
}

int sys_clone(void *tcb, pid_t *pid_out, void *stack) {
	unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
		| CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_SETTLS
		| CLONE_PARENT_SETTID;

#if defined(__riscv)
	// TP should point to the address immediately after the TCB.
	// TODO: We should change the sysdep so that we don't need to do this.
	auto tls = reinterpret_cast<char *>(tcb) + sizeof(Tcb);
	tcb = reinterpret_cast<void *>(tls);
#elif defined(__aarch64__)
	// TP should point to the address 16 bytes before the end of the TCB.
	// TODO: We should change the sysdep so that we don't need to do this.
	auto tp = reinterpret_cast<char *>(tcb) + sizeof(Tcb) - 0x10;
	tcb = reinterpret_cast<void *>(tp);
#endif

	auto ret = __mlibc_spawn_thread(flags, stack, pid_out, NULL, tcb);
	if (ret < 0)
		return ret;

        return 0;
}

extern "C" const char __mlibc_syscall_begin[1];
extern "C" const char __mlibc_syscall_end[1];

#if defined(__riscv)
// Disable UBSan here to work around qemu-user misaligning ucontext_t.
// https://github.com/qemu/qemu/blob/2bf40d0841b942e7ba12953d515e62a436f0af84/linux-user/riscv/signal.c#L68-L69
[[gnu::no_sanitize("undefined")]]
#endif
int sys_before_cancellable_syscall(ucontext_t *uct) {
#if defined(__x86_64__)
	auto pc = reinterpret_cast<void*>(uct->uc_mcontext.gregs[REG_RIP]);
#elif defined(__riscv)
	auto pc = reinterpret_cast<void*>(uct->uc_mcontext.sc_regs.pc);
#elif defined(__aarch64__)
	auto pc = reinterpret_cast<void*>(uct->uc_mcontext.pc);
#else
#error "Missing architecture specific code."
#endif
	if (pc < __mlibc_syscall_begin || pc > __mlibc_syscall_end)
		return 0;
	return 1;
}

int sys_tgkill(int tgid, int tid, int sig) {
	auto ret = do_syscall(SYS_tgkill, tgid, tid, sig);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_tcgetattr(int fd, struct termios *attr) {
	auto ret = do_syscall(SYS_ioctl, fd, TCGETS, attr);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_tcsetattr(int fd, int optional_action, const struct termios *attr) {
	int req;

	switch (optional_action) {
		case TCSANOW: req = TCSETS; break;
		case TCSADRAIN: req = TCSETSW; break;
		case TCSAFLUSH: req = TCSETSF; break;
		default: return EINVAL;
	}

	auto ret = do_syscall(SYS_ioctl, fd, req, attr);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_tcdrain(int fd) {
	auto ret = do_syscall(SYS_ioctl, fd, TCSBRK, 1);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_tcflow(int fd, int action) {
	auto ret = do_syscall(SYS_ioctl, fd, TCXONC, action);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_access(const char *path, int mode) {
	auto ret = do_syscall(SYS_faccessat, AT_FDCWD, path, mode, 0);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) {
	auto ret = do_syscall(SYS_faccessat, dirfd, pathname, mode, flags);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_accept(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length) {
	auto ret = do_syscall(SYS_accept, fd, addr_ptr, addr_length, 0, 0, 0);
	if (int e = sc_error(ret); e)
		return e;
	*newfd = sc_int_result<int>(ret);
	return 0;
}

int sys_bind(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
	auto ret = do_syscall(SYS_bind, fd, addr_ptr, addr_length, 0, 0, 0);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_setsockopt(int fd, int layer, int number, const void *buffer, socklen_t size) {
	auto ret = do_syscall(SYS_setsockopt, fd, layer, number, buffer, size, 0);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_sockname(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length,
		socklen_t *actual_length) {
	auto ret = do_syscall(SYS_getsockname, fd, addr_ptr, &max_addr_length);
	if (int e = sc_error(ret); e)
		return e;
	*actual_length = max_addr_length;
	return 0;
}

int sys_peername(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length,
		socklen_t *actual_length) {
	auto ret = do_syscall(SYS_getpeername, fd, addr_ptr, &max_addr_length);
	if (int e = sc_error(ret); e)
		return e;
	*actual_length = max_addr_length;
	return 0;
}

int sys_listen(int fd, int backlog) {
	auto ret = do_syscall(SYS_listen, fd, backlog, 0, 0, 0, 0);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_getpriority(int which, id_t who, int *value) {
	(void)which;
	(void)who;
	*value = 0;
	return 0;
}

int sys_setpriority(int which, id_t who, int prio) {
	(void)which;
	(void)who;
	(void)prio;
	return 0;
}

int sys_setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value) {
	(void)which;
	(void)new_value;
	(void)old_value;
	return 0;
}

int sys_ptrace(long req, pid_t pid, void *addr, void *data, long *out) {
	(void)req;
	(void)pid;
	(void)addr;
	(void)data;
	(void)out;
	return EPERM;
}

int sys_open_dir(const char *path, int *fd) {
	return sys_open(path, O_DIRECTORY, 0, fd);
}

int sys_read_entries(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
	auto ret = do_syscall(SYS_getdents64, handle, buffer, max_size);
	if(int e = sc_error(ret); e)
		return e;
	*bytes_read = sc_int_result<int>(ret);
	return 0;
}

int sys_prctl(int op, va_list ap, int *out) {
	unsigned long x[4];
	for(int i = 0; i < 4; i++)
		x[i] = va_arg(ap, unsigned long);

	auto ret = do_syscall(SYS_prctl, op, x[0], x[1], x[2], x[3]);
	if (int e = sc_error(ret); e)
		return e;
	*out = sc_int_result<int>(ret);
	return 0;
}

int sys_uname(struct utsname *buf) {
	auto ret = do_syscall(SYS_uname, buf);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_gethostname(char *buf, size_t bufsize) {
	struct utsname uname_buf;
	if (auto e = sys_uname(&uname_buf); e)
		return e;

	auto node_len = strlen(uname_buf.nodename);
	if (node_len >= bufsize)
		return ENAMETOOLONG;

	memcpy(buf, uname_buf.nodename, node_len);
	buf[node_len] = '\0';
	return 0;
}

int sys_pread(int fd, void *buf, size_t n, off_t off, ssize_t *bytes_read) {
	auto ret = do_syscall(SYS_pread64, fd, buf, n, off);
	if (int e = sc_error(ret); e)
		return e;
	*bytes_read = sc_int_result<ssize_t>(ret);
	return 0;
}

int sys_pwrite(int fd, const void *buf, size_t n, off_t off, ssize_t *bytes_written) {
	auto ret = do_syscall(SYS_pwrite64, fd, buf, n, off);
	if (int e = sc_error(ret); e)
		return e;
	*bytes_written = sc_int_result<ssize_t>(ret);
	return 0;
}

int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
	struct timespec tm;
	tm.tv_sec = timeout / 1000;
	tm.tv_nsec = timeout % 1000 * 1000000;
	auto ret = do_syscall(SYS_ppoll, fds, count, timeout >= 0 ? &tm : nullptr, 0, NSIG / 8);
	if (int e = sc_error(ret); e)
		return e;
	*num_events = sc_int_result<int>(ret);
	return 0;
}

int sys_getrusage(int scope, struct rusage *usage) {
	auto ret = do_syscall(SYS_getrusage, scope, usage);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_madvise(void *addr, size_t length, int advice) {
	auto ret = do_syscall(SYS_madvise, addr, length, advice);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_msync(void *addr, size_t length, int flags) {
	auto ret = do_syscall(SYS_msync, addr, length, flags);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_reboot(int cmd) {
	auto ret = do_syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, cmd, nullptr);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
	auto ret = do_syscall(SYS_sched_getaffinity, pid, cpusetsize, mask);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_mount(const char *source, const char *target,
	const char *fstype, unsigned long flags, const void *data) {
	auto ret = do_syscall(SYS_mount, source, target, fstype, flags, data);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_umount2(const char *target, int flags) {
	auto ret = do_syscall(SYS_umount2, target, flags);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_sethostname(const char *buffer, size_t bufsize) {
	auto ret = do_syscall(SYS_sethostname, buffer, bufsize);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_epoll_create(int flags, int *fd) {
	auto ret = do_syscall(SYS_epoll_create1, flags);
	if (int e = sc_error(ret); e)
		return e;
	*fd = sc_int_result<int>(ret);
	return 0;
}

int sys_epoll_ctl(int epfd, int mode, int fd, struct epoll_event *ev) {
	auto ret = do_syscall(SYS_epoll_ctl, epfd, mode, fd, ev);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_epoll_pwait(int epfd, struct epoll_event *ev, int n, int timeout, const sigset_t *sigmask, int *raised) {
	auto ret = do_syscall(SYS_epoll_pwait, epfd, ev, n, timeout, sigmask, NSIG / 8);
	if (int e = sc_error(ret); e)
		return e;
	*raised = sc_int_result<int>(ret);
	return 0;
}

int sys_eventfd_create(unsigned int initval, int flags, int *fd) {
	auto ret = do_syscall(SYS_eventfd2, initval, flags);
	if (int e = sc_error(ret); e)
		return e;
	*fd = sc_int_result<int>(ret);
	return 0;
}

int sys_signalfd_create(const sigset_t *masks, int flags, int *fd) {
	auto ret = do_syscall(SYS_signalfd4, *fd, masks, sizeof(sigset_t), flags);
	if (int e = sc_error(ret); e)
		return e;
	*fd = sc_int_result<int>(ret);
	return 0;
}

int sys_timerfd_create(int clockid, int flags, int *fd) {
	auto ret = do_syscall(SYS_timerfd_create, clockid, flags);
	if (int e = sc_error(ret); e)
		return e;
	*fd = sc_int_result<int>(ret);
	return 0;
}

int sys_timerfd_settime(int fd, int flags, const struct itimerspec *value, struct itimerspec *oldvalue) {
	auto ret = do_syscall(SYS_timerfd_settime, fd, flags, value, oldvalue);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_inotify_create(int flags, int *fd) {
	auto ret = do_syscall(SYS_inotify_init1, flags);
	if (int e = sc_error(ret); e)
		return e;
	*fd = sc_int_result<int>(ret);
	return 0;
}

int sys_init_module(void *module, unsigned long length, const char *args) {
	auto ret = do_syscall(SYS_init_module, module, length, args);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_delete_module(const char *name, unsigned flags) {
	auto ret = do_syscall(SYS_delete_module, name, flags);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_klogctl(int type, char *bufp, int len, int *out) {
	auto ret = do_syscall(SYS_syslog, type, bufp, len);
	if (int e = sc_error(ret); e)
		return e;
	*out = sc_int_result<int>(ret);
	return 0;
}

int sys_getcpu(int *cpu) {
	auto ret = do_syscall(SYS_getcpu, cpu, NULL, NULL);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_socketpair(int domain, int type_and_flags, int proto, int *fds) {
	auto ret = do_syscall(SYS_socketpair, domain, type_and_flags, proto, fds, 0, 0);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_getsockopt(int fd, int layer, int number, void *__restrict buffer, socklen_t *__restrict size) {
	auto ret = do_syscall(SYS_getsockopt, fd, layer, number, buffer, size, 0);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_inotify_add_watch(int ifd, const char *path, uint32_t mask, int *wd) {
	auto ret = do_syscall(SYS_inotify_add_watch, ifd, path, mask);
	if (int e = sc_error(ret); e)
		return e;
	*wd = sc_int_result<int>(ret);
	return 0;
}

int sys_inotify_rm_watch(int ifd, int wd) {
	auto ret = do_syscall(SYS_inotify_rm_watch, ifd, wd);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_ttyname(int fd, char *buf, size_t size) {
	(void)fd;
	(void)buf;
	(void)size;
	return ENOTTY;
}

int sys_pause() {
	return EINTR;
}

int sys_mlockall(int flags) {
	(void)flags;
	return 0;
}

#endif // __MLIBC_POSIX_OPTION

int sys_times(struct tms *tms, clock_t *out) {
	auto ret = do_syscall(SYS_times, tms);
	if (int e = sc_error(ret); e)
		return e;
	*out = sc_int_result<long>(ret);
	return 0;
}

pid_t sys_getpid() {
	return 1;
}

pid_t sys_gettid() {
	// dandelion is single-threaded by design
	return 1;
	// auto ret = do_syscall(SYS_gettid);
	// // gettid() always succeeds.
	// return sc_int_result<pid_t>(ret);
}

uid_t sys_getuid() {
	return 1;
}

uid_t sys_geteuid() {
	return 1;
}

gid_t sys_getgid() {
	return 1;
}

gid_t sys_getegid() {
	return 1;
}

int sys_kill(int pid, int sig) {
	(void)pid;
	(void)sig;
	return EPERM;
}

int sys_vm_protect(void *pointer, size_t size, int prot) {
	auto ret = do_syscall(SYS_mprotect, pointer, size, prot);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

void sys_thread_exit() {
	do_syscall(SYS_exit, 0);
	__builtin_trap();
}

void sys_exit(int status) {
	ssize_t written;
	auto& f = *vfs::get_file_table().get(1)->get_file();
	sys_write_old(1, f.buffer(), f.size(), &written);
	do_syscall(SYS_exit_group, status);
	__builtin_trap();
}

#endif // MLIBC_BUILDING_RTDL

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

int sys_futex_tid() {
	auto ret = do_syscall(SYS_gettid);
	// gettid() always succeeds.
	return sc_int_result<pid_t>(ret);
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
	auto ret = do_cp_syscall(SYS_futex, pointer, FUTEX_WAIT, expected, time);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_futex_wake(int *pointer) {
	auto ret = do_syscall(SYS_futex, pointer, FUTEX_WAKE, INT_MAX);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_sigsuspend(const sigset_t *set) {
	(void)set;
	return EINTR;
}

int sys_sigaltstack(const stack_t *ss, stack_t *oss) {
	(void)ss;
	(void)oss;
	return EPERM;
}

int sys_mkdir(const char *path, mode_t mode) {
	(void)mode;
	return vfs::get_file_table().mkdirat(AT_FDCWD, path);
}


int sys_mkdirat(int dirfd, const char *path, mode_t mode) {
	(void)mode;
	return vfs::get_file_table().mkdirat(dirfd, path);
}

int sys_mknodat(int dirfd, const char *path, int mode, int dev) {
	auto ret = do_syscall(SYS_mknodat, dirfd, path, mode, dev);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_mkfifoat(int dirfd, const char *path, int mode) {
	return sys_mknodat(dirfd, path, mode | S_IFIFO, 0);
}

int sys_symlink(const char *target_path, const char *link_path) {
	auto ret = do_syscall(SYS_symlinkat, target_path, AT_FDCWD, link_path);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_symlinkat(const char *target_path, int dirfd, const char *link_path) {
	auto ret = do_syscall(SYS_symlinkat, target_path, dirfd, link_path);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_umask(mode_t mode, mode_t *old) {
	(void)mode;
	*old = 0777;
	return 0;
}

int sys_chdir(const char *path) {
	return vfs::get_file_table().set_cwd(path);
}

int sys_fchdir(int fd) {
	return EBADF;
	// auto* entry = vfs::get_file_table().get(fd);
	// if (entry == nullptr) {
	// 	return EBADF;
	// }
	// auto* path = entry->get_dirpath();
	// if (path == nullptr) {
	// 	return ENOTDIR;
	// }
	// return sys_chdir(path);
}

int sys_rename(const char *old_path, const char *new_path) {
	return sys_renameat(AT_FDCWD, old_path, AT_FDCWD, new_path);
}

int sys_renameat(int old_dirfd, const char *old_path, int new_dirfd, const char *new_path) {
#ifdef SYS_renameat2
	auto ret = do_syscall(SYS_renameat2, old_dirfd, old_path, new_dirfd, new_path, 0);
#else
	auto ret = do_syscall(SYS_renameat, old_dirfd, old_path, new_dirfd, new_path);
#endif /* defined(SYS_renameat2) */
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_rmdir(const char *path) {
	return vfs::get_file_table().unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
}

int sys_ftruncate(int fd, size_t size) {
	auto ret = do_syscall(SYS_ftruncate, fd, size);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_readlink(const char *path, void *buf, size_t bufsiz, ssize_t *len) {
	auto ret = do_syscall(SYS_readlinkat, AT_FDCWD, path, buf, bufsiz);
	if (int e = sc_error(ret); e)
		return e;
	*len = sc_int_result<ssize_t>(ret);
	return 0;
}

int sys_getrlimit(int resource, struct rlimit *limit) {
	auto ret = do_syscall(SYS_getrlimit, resource, limit);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

int sys_setrlimit(int resource, const struct rlimit *limit) {
	auto ret = do_syscall(SYS_setrlimit, resource, limit);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

pid_t sys_getppid() {
	auto ret = do_syscall(SYS_getppid);
	// getppid() always succeeds.
	return sc_int_result<pid_t>(ret);
}

int sys_setpgid(pid_t pid, pid_t pgid) {
	auto ret = do_syscall(SYS_setpgid, pid, pgid);
	if (int e = sc_error(ret); e)
		return e;
	return 0;
}

pid_t sys_getsid(pid_t pid, pid_t *sid) {
	auto ret = do_syscall(SYS_getsid, pid);
	if (int e = sc_error(ret); e)
		return e;
	*sid = sc_int_result<pid_t>(ret);
	return 0;
}

int sys_setsid(pid_t *sid) {
	(void)sid;
	return EPERM;
}

int sys_setuid(uid_t uid) {
	(void)uid;
	return EINVAL;
}

int sys_getpgid(pid_t pid, pid_t *out) {
	(void)pid;
	*out = 0;
	return 0;
}

int sys_getgroups(size_t size, const gid_t *list, int *retval) {
	(void)size;
	(void)list;
	*retval = 0;
	return 0;
}

int sys_dup(int fd, int flags, int *newfd) {
	(void)flags;
	return vfs::get_file_table().dup(fd, newfd);
}

void sys_sync() {}

int sys_fsync(int fd) {
	(void)fd;
	return 0;
}

int sys_fdatasync(int fd) {
	(void)fd;
	return 0;
}

int sys_getrandom(void *buffer, size_t length, int flags, ssize_t *bytes_written) {
	auto ret = do_syscall(SYS_getrandom, buffer, length, flags);
	if (int e = sc_error(ret); e)
		return e;
	*bytes_written = sc_int_result<ssize_t>(ret);
	return 0;
}

int sys_getentropy(void *buffer, size_t length) {
	ssize_t written;
	return sys_getrandom(buffer, length, 0, &written);
}

} // namespace mlibc
