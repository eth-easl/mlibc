#include <dirent.h>
#include <errno.h>
#include <limits.h>

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
#include "abi-bits/errno.h"
#include "abi-bits/fcntl.h"
#include "cxx-syscall.hpp"
#include "frg/string.hpp"
#include "mlibc/posix-sysdeps.hpp"
#include "refcounted.hpp"

#include <frg/vector.hpp>
#include <frg/variant.hpp>
#include <frg/hash_map.hpp>

#include <dandelion.h>

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
		if (e) {
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

void test_init_dandelion() {
	static const char input_file_content[] = "This is an example input file";
	static io_buf example_input_file{nullptr, "input.txt", (void*)input_file_content, sizeof(input_file_content)};
	static io_buf example_output_file{nullptr, "root_output.txt", nullptr, 0};
	static io_set out_set{nullptr, "output", nullptr};

	dandelion.stdin = {nullptr, nullptr, nullptr, 0};
	dandelion.input_root = {nullptr, "", &example_input_file};
	dandelion.output_root = {&out_set, "", &example_output_file};
}

}; // namespace debug

namespace vfs {

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

	int truncate(size_t size) {
		if (this->is_static) {
			return EPERM;
		}
		if (size <= this->bufsize) {
			this->bufsize = size;
		} else {
			this->ensure_capacity(size);
			memset(this->buf + this->bufsize, 0, size - this->bufsize);
			this->bufsize = size;
		}
		return 0;
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

struct Symlink {
	string target;
};

class Directory {
	template <typename T>
	using entry_map = frg::hash_map<string, T, frg::hash<frg::string_view>, MemoryAllocator>;
	
	Rc<Directory> parent;
	entry_map<Rc<File>> files{frg::hash<frg::string_view>(), getAllocator()};
	entry_map<Rc<Directory>> dirs{frg::hash<frg::string_view>(), getAllocator()};
	entry_map<Symlink> symlinks{frg::hash<frg::string_view>(), getAllocator()};

	size_t read_func(auto begin, auto end, char*& buf, const char* bufend, unsigned char type) {
		size_t num_read = 0;
		for (; begin != end; ++begin, ++num_read) {
			size_t namelen = begin->template get<0>().size();
			size_t total_len = offsetof(struct dirent, d_name) + namelen + 1;
			if (total_len > static_cast<size_t>(bufend - buf)) {
				// this entry would overflow the buffer, so stop here
				break;
			}

			// TODO check for integer overflow on total_len
			// TODO implement offset
			::new (buf + offsetof(struct dirent, d_ino)) ino_t{0};
			::new (buf + offsetof(struct dirent, d_off)) off_t{0};
			::new (buf + offsetof(struct dirent, d_reclen)) unsigned short{(unsigned short)total_len};
			::new (buf + offsetof(struct dirent, d_type)) unsigned char{type};

			buf += offsetof(struct dirent, d_name);
			memcpy(buf, begin->template get<0>().data(), namelen);
			buf += namelen;
			*buf = '\0';
			buf += 1;
		}
		return num_read;
	}

	static size_t file_offset(size_t offset) {
		return offset & static_cast<uint32_t>(~0);
	}

	static size_t dir_offset(size_t offset) {
		return offset >> 32;
	}

	static size_t create_offset(size_t fileoffset, size_t diroffset) {
		return (diroffset << 32) | fileoffset;
	}

public:
	Directory(Rc<Directory> parent) : parent{parent} {}

	void set_parent(Rc<Directory> parent) {
		this->parent = parent;
	}

	bool is_empty() {
		return this->files.empty() && this->dirs.empty();
	}

	int read_entries_offset(void* buffer, size_t maxsize, size_t* bytes_read, size_t& offset) {
		char* bufp = static_cast<char*>(buffer);
		const char* endp = bufp + maxsize;

		// needing to advance these iterators is a bit awkward, but hash maps don't support
		// random access iterators. this should not be a problem in practice, though, as huge
		// directories are quite rare.

		auto filebegin = this->files.begin();
		for (size_t i = 0; i < file_offset(offset); ++i) {
			++filebegin;
		}

		auto dirbegin = this->dirs.begin();
		for (size_t i = 0; i < dir_offset(offset); ++i) {
			++dirbegin;
		}

		size_t files_read = this->read_func(filebegin, this->files.end(), bufp, endp, DT_REG);
		size_t dirs_read = this->read_func(dirbegin, this->dirs.end(), bufp, endp, DT_DIR);

		offset = create_offset(file_offset(offset) + files_read, dir_offset(offset) + dirs_read);
		*bytes_read = bufp - static_cast<char*>(buffer);

		return 0;
	}

	// TODO all of these should somehow handle the case where the file/dir already exists differently

	static int link_file(Rc<Directory> self, frg::string_view name, Rc<File> file) {
		self->files.insert(string{name, getAllocator()}, file);
		return 0;
	}

	static int link_dir(Rc<Directory> self, frg::string_view name, Rc<Directory> dir) {
		self->dirs.insert(string{name, getAllocator()}, dir);
		return 0;
	}

	static Rc<File> create_file(Rc<Directory> self, frg::string_view name) {
		auto file = Rc<File>::make();
		self->files.insert(string{name, getAllocator()}, file);
		return file;
	}

	static Rc<Directory> create_dir(Rc<Directory> self, frg::string_view name) {
		auto dir = Rc<Directory>::make(self);
		self->dirs.insert(string{name, getAllocator()}, dir);
		return dir;
	}

	static int remove_file(Rc<Directory> self, frg::string_view name) {
		auto removed = self->files.remove(string{name, getAllocator()});
		if (removed) {
			return 0;
		} else {
			return ENOENT;
		}
	}

	static int remove_dir(Rc<Directory> self, frg::string_view name) {
		auto dir = self->dirs.get(name);
		if (dir != nullptr) {
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

	void for_each(auto file_func, auto dir_func) {
		for (auto& file : this->files) {
			file_func(file.get<0>(), file.get<1>());
		}
		for (auto& dir : this->dirs) {
			dir_func(dir.get<0>(), dir.get<1>());
		}
	}

};

class FileTableEntry {
public:
	struct OpenFile {
		Rc<File> data;
		size_t offset{0};
		int flags{0};

		int access() {
			return this->flags & 0b11;
		}
	};

	struct OpenDir {
		Rc<Directory> dir;
		size_t offset{0};
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
			if (whence != SEEK_SET || offset < 0) {
				return EINVAL;
			}
			OpenDir& dir = this->internal.get<OpenDir>();
			dir.offset = static_cast<size_t>(offset);
			return 0;
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
			*new_offset = openfile.offset;
			return 0;
		} else {
			mlibc::panicLogger() << "Invalid FileTableEntry type encountered" << frg::endlog;
			return EIO;
		}
	}

	int read_entries(void* buffer, size_t size, size_t* bytes_read) {
		if (this->internal.is<OpenDir>()) {
			OpenDir& opendir = this->internal.get<OpenDir>();
			// NOTE: opendir.offset is modified by read_entries_offset
			return opendir.dir->read_entries_offset(buffer, size, bytes_read, opendir.offset);
		} else {
			*bytes_read = -1;
			return ENOTDIR;
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

struct path_split_result {
	bool is_dir;
	frg::string_view dir;
	frg::string_view base;
};

path_split_result path_split(frg::string_view path) {
	size_t end_idx = path.size();
	if (path[end_idx - 1] == '/') {
		--end_idx;
	}
	size_t start_idx = end_idx;
	while (start_idx > 0 && path[start_idx - 1] != '/') {
		--start_idx;
	}
	return {
		path.size() > 0 && path[path.size() - 1] == '/',
		path.sub_string(0, start_idx),
		path.sub_string(start_idx, end_idx - start_idx),
	};
}

class PathComponents {
	frg::string_view path;
public:
	PathComponents(frg::string_view path) : path(path) {}
	frg::string_view next() {
		size_t start_idx = 0;
		while (start_idx < path.size() && path[start_idx] == '/') {
			++start_idx;
		}
		size_t end_idx = start_idx;
		while (end_idx < path.size() && path[end_idx] != '/') {
			++end_idx;
		}
		auto ret = path.sub_string(start_idx, end_idx - start_idx);
		path = path.sub_string(end_idx, path.size() - end_idx);
		return ret;
	}
};

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

	Rc<Directory> get_origin(int dirfd, const char* path) {
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

	int create_file_from_buf(const char* set_ident, io_buf* buf) {
		auto path = string{set_ident, getAllocator()} + string{buf->ident, getAllocator()};
		auto pathinfo = path_split(path);
		PathComponents components{pathinfo.dir};

		auto current = this->fs_root;
		for (auto component = components.next(); component.size() > 0; component = components.next()) {
			auto next = Directory::find(current, component);
			if (next.is<Rc<Directory>>()) {
				current = next.get<Rc<Directory>>();
			} else if (next.is<NoEntry>()) {
				current = Directory::create_dir(current, component);
			} else {
				return 1;
			}
		}

		auto file = Rc<File>::make(buf);
		Directory::link_file(current, pathinfo.base, file);
		return 0;
	}

	void create_bufs_from_dir(io_set* set, Rc<Directory> dir, frg::string_view path) {
		dir->for_each([&](const string& name, Rc<File>& file) {
			char* buf_ident = (char*)getAllocator().allocate(path.size() + name.size() + 2);
			memcpy(buf_ident, path.data(), path.size());
			buf_ident[path.size()] = '/';
			memcpy(buf_ident + path.size() + 1, name.data(), name.size());
			buf_ident[path.size() + name.size() + 1] = '\0';

			io_buf* buf = (io_buf*)getAllocator().allocate(sizeof(io_buf));
			buf = ::new (buf) io_buf{set->buf_head, buf_ident, file->buffer(), file->size()};
			set->buf_head = buf;
		}, [&](const string& name, Rc<Directory>& subdir) {
			string new_path{path, getAllocator()};
			new_path += '/';
			new_path += name;
			create_bufs_from_dir(set, subdir, new_path);
		});
	}

public:
	FileTable() {
		debug::test_init_dandelion();

		this->fs_root = Rc<Directory>::make(Rc<Directory>{nullptr});
		this->fs_root->set_parent(this->fs_root);
		this->working_dir = this->fs_root;

		for (auto* set = &dandelion.input_root; set != nullptr; set = set->next) {
			for (auto* buf = set->buf_head; buf != nullptr; buf = buf->next) {
				create_file_from_buf(set->ident, buf);
			}
		}

		this->create_entry_at(0,
			FileTableEntry::OpenFile {
				Rc<File>::make(&dandelion.stdin),
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
	}

	void finalize() {
		for (auto* buf = dandelion.output_root.buf_head; buf != nullptr; buf = buf->next) {
			auto entry = Directory::find(this->fs_root, buf->ident);
			if (entry.is<Rc<File>>()) {
				auto& file = entry.get<Rc<File>>();
				buf->buffer = file->buffer();
				buf->size = file->size();
			}
		}

		for (auto* set = dandelion.output_root.next; set != nullptr; set = set->next) {
			auto entry = Directory::find(this->fs_root, set->ident);
			if (entry.is<Rc<Directory>>()) {
				create_bufs_from_dir(set, entry.get<Rc<Directory>>(), "");
			}
		}

		auto stdout_file = this->get(1)->get_file();
		dandelion.stdout.buffer = stdout_file->buffer();
		dandelion.stdout.size = stdout_file->size();

		auto stderr_file = this->get(2)->get_file();
		dandelion.stderr.buffer = stderr_file->buffer();
		dandelion.stderr.size = stderr_file->size();
	}

	FileTable(const FileTable&) = delete;
	FileTable(FileTable&&) = delete;

	int set_cwd(int dirfd, const char* path) {
		auto base = this->get_origin(dirfd, path);
		if (base == nullptr) {
			return ENOENT;
		}
		this->working_dir = base;
		return 0;
	}

	int openat(int dirfd, const char* path, int flags, int* fd) {
		auto pathinfo = path_split(path);

		auto origin = this->get_origin(dirfd, path);

		int access = flags & 0b11;

		auto res = Directory::find(origin, path);

		if (res.is<Rc<Directory>>()) {
			if (access != O_RDONLY) {
				*fd = -1;
				return EISDIR;
			}

			auto dir = res.get<Rc<Directory>>();

			*fd = this->create_entry(FileTableEntry::OpenDir{dir});
			return 0;
		} else if (flags & O_DIRECTORY) {
			*fd = -1;
			return ENOTDIR;
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

			Rc<Directory> loc = origin;
			if (pathinfo.dir.size() > 0) {
				auto res = Directory::find(origin, pathinfo.dir);
				if (res.is<Rc<Directory>>()) {
					loc = res.get<Rc<Directory>>();
				} else {
					*fd = -1;
					return EINVAL;
				}
			}

			file = Directory::create_file(loc, pathinfo.base);
		}

		// if we're opening in truncation mode, set the size of the file to 0
		// note that this doesn't actually modify the file buffer
		if ((flags & O_TRUNC) && (access == O_RDWR || access == O_WRONLY)) {
			// TODO check if we can write to the file
			int res = file->truncate(0);
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
		auto pathinfo = path_split(path);
		// TODO more general way to handle empty paths
		if (pathinfo.base.size() == 0) {
			return ENOENT;
		}
		auto origin = this->get_origin(dirfd, path);
		auto loc = Directory::find(origin, pathinfo.dir);
		if (loc.is<Rc<Directory>>()) {
			auto locdir = loc.get<Rc<Directory>>();
			// TODO check that filename isn't empty
			// TODO chck if exists 
			Directory::create_dir(locdir, pathinfo.base);
			return 0;
		} else {
			// TODO correct error code
			return ENOTDIR;
		}
	}

	int unlinkat(int dirfd, const char* path, int flags) {
		auto pathinfo = path_split(path);
		auto origin = this->get_origin(dirfd, path);
		auto loc = Directory::find(origin, pathinfo.dir);
		if (loc.is<Rc<Directory>>()) {
			auto locdir = loc.get<Rc<Directory>>();
			if (flags & AT_REMOVEDIR) {
				return Directory::remove_dir(locdir, pathinfo.base);
			} else if (!pathinfo.is_dir) {
				return Directory::remove_file(locdir, pathinfo.base);
			} else {
				return EISDIR;
			}
		} else if (loc.is<Rc<File>>()) {
			return ENOTDIR;
		} else {
			return ENOENT;
		}
	}

	int linkat(int old_dirfd, const char* old_path, int new_dirfd, const char* new_path, int flags) {
		return ENOSYS;
	}

	int renameat(int old_dirfd, const char* old_path, int new_dirfd, const char* new_path) {
		return ENOSYS;
	}

	int fcntl(int fd, int cmd, int arg, int* result) {
		return ENOSYS;
		// auto entry = this->get(fd);
		// if (entry == nullptr) {
		// 	return EBADF;
		// }
		// auto file = entry->get_file();
		// if (file == nullptr) {
		// 	return EISDIR;
		// }
		// // TODO implement more commands
		// switch (cmd) {
		// 	case F_GETFL:
		// 		*result = file->get_flags();
		// 		return 0;
		// 	case F_SETFL:
		// 		file->set_flags(arg);
		// 		return 0;
		// 	default:
		// 		return EINVAL;
		// }
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

}; // namespace vfs

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

int sys_write(int fd, const void *buffer, size_t size, ssize_t *bytes_written) {
	auto file = vfs::get_file_table().get(fd);
	if (file == nullptr) {
		return EBADF;
	}
	return file->write(buffer, size, bytes_written);
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
	auto file = vfs::get_file_table().get(fd);
	if (file == nullptr) {
		return EBADF;
	}
	return file->seek(offset, whence, new_offset);
}

int sys_chmod(const char *pathname, mode_t mode) {
	(void)pathname, (void)mode;
	return 0;
}

int sys_fchmod(int fd, mode_t mode) {
	(void)fd, (void)mode;
	return 0;
}

int sys_fchmodat(int fd, const char *pathname, mode_t mode, int flags) {
	(void)fd, (void)pathname, (void)mode, (void)flags;
	return 0;
}

int sys_fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {
	(void)dirfd, (void)pathname, (void)owner, (void)group, (void)flags;
	return 0;
}

int sys_utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags) {
	(void)dirfd, (void)pathname, (void)times, (void)flags;
	return 0;
}

// All remaining functions are disabled in ldso.
#ifndef MLIBC_BUILDING_RTDL

int sys_clock_get(int clock, time_t *secs, long *nanos) {
	// TODO get initial time from auxv
	(void)clock;
	*secs = 0;
	*nanos = 0;
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
	// SYS_newfstatat
	if (fsfdt == fsfd_target::path)
		fd = AT_FDCWD;
	else if (fsfdt == fsfd_target::fd)
		flags |= AT_EMPTY_PATH;
	else
		__ensure(fsfdt == fsfd_target::fd_path);
	return EACCES;
}

int sys_statfs(const char *path, struct statfs *buf) {
	(void)path, (void)buf;
	return ENOSYS;
}

int sys_fstatfs(int fd, struct statfs *buf) {
	(void)fd, (void)buf;
	return ENOSYS;
}

// extern "C" void __mlibc_signal_restore(void);

int sys_sigaction(int signum, const struct sigaction *act,
                struct sigaction *oldact) {
	(void)signum, (void)act, (void)oldact;
	// pretend that we installed the signal handler
	return 0; 
}

int sys_socket(int domain, int type, int protocol, int *fd) {
	(void)domain;
	(void)type;
	(void)protocol;
	*fd = -1;
	return EACCES;
}

int sys_msg_send(int sockfd, const struct msghdr *msg, int flags, ssize_t *length) {
	(void)sockfd;
	(void)msg;
	(void)flags;
	*length = -1;
	return EBADF;
}

int sys_msg_recv(int sockfd, struct msghdr *msg, int flags, ssize_t *length) {
	(void)sockfd;
	(void)msg;
	(void)flags;
	*length = -1;
	return EBADF;
}

int sys_fcntl(int fd, int cmd, va_list args, int *result) {
	auto arg = va_arg(args, unsigned long);
	return vfs::get_file_table().fcntl(fd, cmd, arg, result);
}

int sys_getcwd(char *buf, size_t size) {
	// TODO implement this
	return ENOSYS;
	// const char* cwd = vfs::get_file_table().get_cwd();
	// size_t cwd_len = strlen(cwd) + 1;
	// if (size < cwd_len) {
	// 	return ERANGE;
	// }
	// strcpy(buf, cwd);
	// return 0;
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
	(void)sockfd, (void)addr, (void)addrlen;
	return EACCES;
}

int sys_pselect(int nfds, fd_set *readfds, fd_set *writefds,
                fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask, int *num_events) {
	return ENOSYS;
}

int sys_pipe(int *fds, int flags) {
	// TODO we might want to support pipes. It should be relatively simple to implement,
	// but it is unclear whether many single-process applications actually use it.
	return ENOSYS;
}

int sys_fork(pid_t *child) {
	(void)child;
	return ENOSYS;
}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	(void)pid, (void)status, (void)flags, (void)ru, (void)ret_pid;
	return ECHILD;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
	(void)path, (void)argv, (void)envp;
	return EACCES;
}

int sys_sigprocmask(int how, const sigset_t *set, sigset_t *old) {
	(void)how, (void)set, (void)old;
	return EINVAL;
}

int sys_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
	(void)ruid, (void)euid, (void)suid;
	return 0;
}

int sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
	(void)rgid, (void)egid, (void)sgid;
	return 0;
}

int sys_setreuid(uid_t ruid, uid_t euid) {
	(void)ruid, (void)euid;
	return 0;
}

int sys_setregid(gid_t rgid, gid_t egid) {
	(void)rgid, (void)egid;
	return 0;
}

int sys_sysinfo(struct sysinfo *info) {
	// todo return actually interesting information
	memset(info, 0, sizeof(*info));
	info->mem_unit = 1;
	return 0;
}

void sys_yield() {}

int sys_clone(void *tcb, pid_t *pid_out, void *stack) {
	(void)tcb, (void)pid_out, (void)stack;
	return ENOSYS;
// 	unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
// 		| CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_SETTLS
// 		| CLONE_PARENT_SETTID;

// #if defined(__riscv)
// 	// TP should point to the address immediately after the TCB.
// 	// TODO: We should change the sysdep so that we don't need to do this.
// 	auto tls = reinterpret_cast<char *>(tcb) + sizeof(Tcb);
// 	tcb = reinterpret_cast<void *>(tls);
// #elif defined(__aarch64__)
// 	// TP should point to the address 16 bytes before the end of the TCB.
// 	// TODO: We should change the sysdep so that we don't need to do this.
// 	auto tp = reinterpret_cast<char *>(tcb) + sizeof(Tcb) - 0x10;
// 	tcb = reinterpret_cast<void *>(tp);
// #endif

// 	auto ret = __mlibc_spawn_thread(flags, stack, pid_out, NULL, tcb);
// 	if (ret < 0)
// 		return ret;

//         return 0;
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
	(void)tgid, (void)tid, (void)sig;
	return 0;
}

int sys_tcgetattr(int fd, struct termios *attr) {
	(void)fd, (void)attr;
	return ENOSYS;
}

int sys_tcsetattr(int fd, int optional_action, const struct termios *attr) {
	(void)fd, (void)optional_action, (void)attr;
	return ENOSYS;
}

int sys_tcdrain(int fd) {
	(void)fd;
	return ENOSYS;
}

int sys_tcflow(int fd, int action) {
	(void)fd, (void)action;
	return ENOSYS;
}

int sys_access(const char *path, int mode) {
	return sys_faccessat(AT_FDCWD, path, mode, 0);
}

int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) {
	int fd;
	auto ret = sys_openat(dirfd, pathname, flags, mode, &fd);
	if (ret == 0) {
		sys_close(fd);
	} 
	return ret;
}

int sys_accept(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length) {
	(void)fd, (void)addr_ptr, (void)addr_length;
	*newfd = -1;
	// we allow no sockets to be created, so any fd must be bad
	return EBADF;
}

int sys_bind(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
	(void)fd, (void)addr_ptr, (void)addr_length;
	// we allow no sockets to be created, so any fd must be bad
	return EBADF;
}

int sys_setsockopt(int fd, int layer, int number, const void *buffer, socklen_t size) {
	(void)fd, (void)layer, (void)number, (void)buffer, (void)size;
	return EBADF;
}

int sys_sockname(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length,
		socklen_t *actual_length) {
	(void)fd, (void)addr_ptr, (void)max_addr_length, (void)actual_length;
	return EBADF;
}

int sys_peername(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length,
		socklen_t *actual_length) {
	(void)fd, (void)addr_ptr, (void)max_addr_length, (void)actual_length;
	return EBADF;
}

int sys_listen(int fd, int backlog) {
	(void)fd, (void)backlog;
	return EBADF;
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
	auto entry = vfs::get_file_table().get(handle);
	if (entry == nullptr) {
		return EBADF;
	}
	return entry->read_entries(buffer, max_size, bytes_read);
}

int sys_prctl(int op, va_list ap, int *out) {
	(void)op, (void)ap, (void)out;
	return EINVAL;
}

int sys_uname(struct utsname *buf) {
	memset(buf, 0, sizeof(*buf));
	return 0;
}

int sys_gethostname(char *buf, size_t bufsize) {
	(void)buf, (void)bufsize;
	return ENAMETOOLONG;
}

int sys_pread(int fd, void *buf, size_t n, off_t off, ssize_t *bytes_read) {
	auto entry = vfs::get_file_table().get(fd);
	if (entry == nullptr) {
		return EBADF;
	}
	auto file = entry->get_file();
	if (file == nullptr) {
		return EISDIR;
	}
	return file->read_offset(buf, n, off, bytes_read);
}

int sys_pwrite(int fd, const void *buf, size_t n, off_t off, ssize_t *bytes_written) {
	auto entry = vfs::get_file_table().get(fd);
	if (entry == nullptr) {
		return EBADF;
	}
	auto file = entry->get_file();
	if (file == nullptr) {
		return EISDIR;
	}
	return file->write_offset(buf, n, off, bytes_written);
}

int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
	// NOTE timeout is specified in milliseconds
	return ENOSYS;
}

int sys_getrusage(int scope, struct rusage *usage) {
	(void)scope, (void)usage;
	// TODO this might be useful to implement
	return ENOSYS;
}

int sys_madvise(void *addr, size_t length, int advice) {
	(void)addr, (void)length, (void)advice;
	return 0;
}

int sys_msync(void *addr, size_t length, int flags) {
	(void)addr, (void)length, (void)flags;
	return 0;
}

int sys_reboot(int cmd) {
	(void)cmd;
	return EPERM;
}

int sys_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
	(void)pid, (void)cpusetsize, (void)mask;
	return ENOSYS;
}

int sys_mount(const char *source, const char *target,
	const char *fstype, unsigned long flags, const void *data) {
	(void)source, (void)target, (void)fstype, (void)flags, (void)data;
	return EPERM;
}

int sys_umount2(const char *target, int flags) {
	(void)target, (void)flags;
	return EPERM;
}

int sys_sethostname(const char *buffer, size_t bufsize) {
	(void)buffer, (void)bufsize;
	return EPERM;
}

// int sys_epoll_create(int flags, int *fd) {
// 	auto ret = do_syscall(SYS_epoll_create1, flags);
// 	if (int e = sc_error(ret); e)
// 		return e;
// 	*fd = sc_int_result<int>(ret);
// 	return 0;
// }

// int sys_epoll_ctl(int epfd, int mode, int fd, struct epoll_event *ev) {
// 	auto ret = do_syscall(SYS_epoll_ctl, epfd, mode, fd, ev);
// 	if (int e = sc_error(ret); e)
// 		return e;
// 	return 0;
// }

// int sys_epoll_pwait(int epfd, struct epoll_event *ev, int n, int timeout, const sigset_t *sigmask, int *raised) {
// 	auto ret = do_syscall(SYS_epoll_pwait, epfd, ev, n, timeout, sigmask, NSIG / 8);
// 	if (int e = sc_error(ret); e)
// 		return e;
// 	*raised = sc_int_result<int>(ret);
// 	return 0;
// }

// int sys_eventfd_create(unsigned int initval, int flags, int *fd) {
// 	auto ret = do_syscall(SYS_eventfd2, initval, flags);
// 	if (int e = sc_error(ret); e)
// 		return e;
// 	*fd = sc_int_result<int>(ret);
// 	return 0;
// }

// int sys_signalfd_create(const sigset_t *masks, int flags, int *fd) {
// 	auto ret = do_syscall(SYS_signalfd4, *fd, masks, sizeof(sigset_t), flags);
// 	if (int e = sc_error(ret); e)
// 		return e;
// 	*fd = sc_int_result<int>(ret);
// 	return 0;
// }

// int sys_timerfd_create(int clockid, int flags, int *fd) {
// 	auto ret = do_syscall(SYS_timerfd_create, clockid, flags);
// 	if (int e = sc_error(ret); e)
// 		return e;
// 	*fd = sc_int_result<int>(ret);
// 	return 0;
// }

// int sys_timerfd_settime(int fd, int flags, const struct itimerspec *value, struct itimerspec *oldvalue) {
// 	auto ret = do_syscall(SYS_timerfd_settime, fd, flags, value, oldvalue);
// 	if (int e = sc_error(ret); e)
// 		return e;
// 	return 0;
// }

// int sys_inotify_create(int flags, int *fd) {
// 	auto ret = do_syscall(SYS_inotify_init1, flags);
// 	if (int e = sc_error(ret); e)
// 		return e;
// 	*fd = sc_int_result<int>(ret);
// 	return 0;
// }

int sys_init_module(void *module, unsigned long length, const char *args) {
	(void)module, (void)length, (void)args;
	return EPERM;
}

int sys_delete_module(const char *name, unsigned flags) {
	(void)name, (void)flags;
	return EPERM;
}

int sys_klogctl(int type, char *bufp, int len, int *out) {
	(void)type, (void)bufp, (void)len, (void)out;
	return ENOSYS;
}

int sys_getcpu(int *cpu) {
	if (cpu != nullptr) {
		*cpu = 0;
	}
	return 0;
}

int sys_socketpair(int domain, int type_and_flags, int proto, int *fds) {
	(void)domain, (void)type_and_flags, (void)proto, (void)fds;
	return EPROTONOSUPPORT;
}

int sys_getsockopt(int fd, int layer, int number, void *__restrict buffer, socklen_t *__restrict size) {
	(void)fd, (void)layer, (void)number, (void)buffer, (void)size;
	return EBADF;
}

int sys_inotify_add_watch(int ifd, const char *path, uint32_t mask, int *wd) {
	(void)ifd, (void)path, (void)mask, (void)wd;
	*wd = -1;
	return ENOSPC;
}

int sys_inotify_rm_watch(int ifd, int wd) {
	(void)ifd, (void)wd;
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
	// TODO fill tms
	(void)tms;
	*out = 0;
	return 0;
}

pid_t sys_getpid() {
	return 1;
}

pid_t sys_gettid() {
	return 1;
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
	(void)pointer, (void)size, (void)prot;
	return 0;
}

void sys_thread_exit() {
	sys_exit(0);
	__builtin_trap();
}

void sys_exit(int status) {
	vfs::get_file_table().finalize();

	// dump stdout file to console

	debug::dump_io_buf("stdout", &dandelion.stdout);
	debug::dump_io_buf("stderr", &dandelion.stderr);

	for (auto* set = &dandelion.output_root; set != nullptr; set = set->next) {
		debug::dump_io_set(set);
	}

	do_syscall(SYS_exit_group, status);
	__builtin_trap();
}

#endif // MLIBC_BUILDING_RTDL

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

int sys_futex_tid() {
	return 1;
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
	(void)time;
	if (*pointer != expected) {
		return EAGAIN;
	} else {
		return EINTR;
	}
}

int sys_futex_wake(int *pointer) {
	(void)pointer;
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
	(void)dev;
	// TODO: handle permissions
	if (mode & S_IFREG) {
		auto& tab = vfs::get_file_table();
		int fd = 0;
		int res = tab.openat(dirfd, path, O_CREAT | O_EXCL, &fd);
		if (!res) {
			tab.close(fd);
		}
		return res;
	} else if (mode & S_IFDIR) {
		return mkdirat(dirfd, path, 0);
	} else {
		return EINVAL;
	}
}

int sys_mkfifoat(int dirfd, const char *path, int mode) {
	(void)dirfd, (void)path, (void)mode;
	return ENOSYS;
}

int sys_symlink(const char *target_path, const char *link_path) {
	return ENOSYS;
}

int sys_symlinkat(const char *target_path, int dirfd, const char *link_path) {
	return ENOSYS;
}

int sys_umask(mode_t mode, mode_t *old) {
	(void)mode;
	*old = 0777;
	return 0;
}

int sys_chdir(const char *path) {
	return vfs::get_file_table().set_cwd(AT_FDCWD, path);
}

int sys_fchdir(int fd) {
	return vfs::get_file_table().set_cwd(fd, "");
}

int sys_rename(const char *old_path, const char *new_path) {
	return sys_renameat(AT_FDCWD, old_path, AT_FDCWD, new_path);
}

int sys_renameat(int old_dirfd, const char *old_path, int new_dirfd, const char *new_path) {
	return vfs::get_file_table().renameat(old_dirfd, old_path, new_dirfd, new_path);
}

int sys_link(const char *old_path, const char *new_path) {
	return sys_linkat(AT_FDCWD, old_path, AT_FDCWD, new_path, 0);
}

int sys_linkat(int olddirfd, const char *old_path, int newdirfd, const char *new_path, int flags) {
	return vfs::get_file_table().linkat(olddirfd, old_path, newdirfd, new_path, flags);
}

int sys_rmdir(const char *path) {
	return vfs::get_file_table().unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
}

int sys_ftruncate(int fd, size_t size) {
	auto val = vfs::get_file_table().get(fd);
	if (val == nullptr) {
		return EBADF;
	}
	auto file = val->get_file();
	if (file == nullptr) {
		return EBADF;
	}
	return file->truncate(size);
}

int sys_readlink(const char *path, void *buf, size_t bufsiz, ssize_t *len) {
	// TODO implement once we have symlinks
	return ENOSYS;
}

int sys_getrlimit(int resource, struct rlimit *limit) {
	(void)resource, (void)limit;
	// TODO this might be useful to implement
	return ENOSYS;
}

int sys_setrlimit(int resource, const struct rlimit *limit) {
	(void)resource, (void)limit;
	return 0;
}

pid_t sys_getppid() {
	return 1;
}

int sys_setpgid(pid_t pid, pid_t pgid) {
	(void)pid, (void)pgid;
	return EPERM;
}

pid_t sys_getsid(pid_t pid, pid_t *sid) {
	(void)pid;
	*sid = 1;
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
	(void)size, (void)list;
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
