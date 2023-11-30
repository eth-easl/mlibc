#pragma once

#include <abi-bits/fcntl.h>
#include <abi-bits/stat.h>
#include <dandelion/runtime.h>
#include <dirent.h>

#include <cstddef>
#include <cstdint>
#include <frg/hash_map.hpp>
#include <frg/variant.hpp>
#include <frg/vector.hpp>
#include <mlibc/allocator.hpp>
#include <refcounted.hpp>

namespace mlibc::vfs {

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
      std::byte* new_buf =
          static_cast<std::byte*>(getAllocator().allocate(new_cap));
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
  File(io_buffer* iobuf)
      : is_static{true},
        buf{static_cast<std::byte*>(iobuf->data)},
        bufsize{iobuf->data_len} {}

  ~File() {
    if (!is_static) {
      getAllocator().free(this->buf);
    }
  }

  size_t size() const { return this->bufsize; }

  std::byte* buffer() { return this->buf; }

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

  int read_offset(void* buffer, size_t size, size_t offset,
                  ssize_t* bytes_read) {
    size_t to_read = 0;
    if (offset <= this->bufsize) {
      to_read = std::min(size, this->bufsize - offset);
    }
    memcpy(buffer, this->buf + offset, to_read);
    *bytes_read = to_read;
    return 0;
  }

  int write_offset(const void* buffer, size_t size, size_t offset,
                   ssize_t* bytes_written) {
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
  using entry_map =
      frg::hash_map<string, T, frg::hash<frg::string_view>, MemoryAllocator>;

  Rc<Directory> parent;
  entry_map<Rc<File>> files{frg::hash<frg::string_view>(), getAllocator()};
  entry_map<Rc<Directory>> dirs{frg::hash<frg::string_view>(), getAllocator()};
  entry_map<Symlink> symlinks{frg::hash<frg::string_view>(), getAllocator()};

  size_t read_func(auto begin, auto end, char*& buf, const char* bufend,
                   unsigned char type) {
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
      ::new (buf + offsetof(struct dirent, d_reclen)) unsigned short{
          (unsigned short)total_len};
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

  static size_t dir_offset(size_t offset) { return offset >> 32; }

  static size_t create_offset(size_t fileoffset, size_t diroffset) {
    return (diroffset << 32) | fileoffset;
  }

 public:
  Directory(Rc<Directory> parent) : parent{parent} {}

  void set_parent(Rc<Directory> parent) { this->parent = parent; }

  bool is_empty() { return this->files.empty() && this->dirs.empty(); }

  int read_entries_offset(void* buffer, size_t maxsize, size_t* bytes_read,
                          size_t& offset) {
    char* bufp = static_cast<char*>(buffer);
    const char* endp = bufp + maxsize;

    // needing to advance these iterators is a bit awkward, but hash maps don't
    // support random access iterators. this should not be a problem in
    // practice, though, as huge directories are quite rare.

    auto filebegin = this->files.begin();
    for (size_t i = 0; i < file_offset(offset); ++i) {
      ++filebegin;
    }

    auto dirbegin = this->dirs.begin();
    for (size_t i = 0; i < dir_offset(offset); ++i) {
      ++dirbegin;
    }

    size_t files_read =
        this->read_func(filebegin, this->files.end(), bufp, endp, DT_REG);
    size_t dirs_read =
        this->read_func(dirbegin, this->dirs.end(), bufp, endp, DT_DIR);

    offset = create_offset(file_offset(offset) + files_read,
                           dir_offset(offset) + dirs_read);
    *bytes_read = bufp - static_cast<char*>(buffer);

    return 0;
  }

  // TODO all of these should somehow handle the case where the file/dir already
  // exists differently

  static int link_file(Rc<Directory> self, frg::string_view name,
                       Rc<File> file) {
    self->files.insert(string{name, getAllocator()}, file);
    return 0;
  }

  static int link_dir(Rc<Directory> self, frg::string_view name,
                      Rc<Directory> dir) {
    self->dirs.insert(string{name, getAllocator()}, dir);
    return 0;
  }

  static int link(Rc<Directory> self, frg::string_view name,
                  frg::variant<NoEntry, Rc<File>, Rc<Directory>> new_entry) {
    if (new_entry.is<Rc<Directory>>()) {
      return Directory::link_dir(self, name, new_entry.get<Rc<Directory>>());
    } else {
      return Directory::link_file(self, name, new_entry.get<Rc<File>>());
    }
    return ENOENT;
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

  static int remove_dir(Rc<Directory> self, frg::string_view namesv) {
    string name{namesv, getAllocator()};
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

  static int remove(Rc<Directory> self, frg::string_view name) {
    auto to_remove = Directory::find(self, name);
    if (to_remove.is<Rc<Directory>>()) {
      return Directory::remove_dir(self, name);
    } else if (to_remove.is<Rc<File>>()) {
      return Directory::remove_file(self, name);
    }
    return ENOENT;
  }

  static frg::variant<NoEntry, Rc<File>, Rc<Directory>> find(
      Rc<Directory> base, frg::string_view path) {
    if (path.size() == 0) return NoEntry{};
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
      auto sub_path_sv = path.sub_string(begin, i - begin);
      string sub_path{sub_path_sv, getAllocator()};
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

    int access() { return this->flags & 0b11; }
  };

  struct OpenDir {
    Rc<Directory> dir;
    size_t offset{0};
  };

 private:
 private:
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
      mlibc::panicLogger() << "Invalid FileTableEntry type encountered"
                           << frg::endlog;
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
      int code =
          file.data->write_offset(buffer, size, file.offset, bytes_written);
      if (code == 0) {
        file.offset += *bytes_written;
      }
      return code;
    } else {
      mlibc::panicLogger() << "Invalid FileTableEntry type encountered"
                           << frg::endlog;
      return EIO;
    }
  }

  int seek(off_t offset, int whence, off_t* new_offset) {
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
      } else if (whence == SEEK_CUR &&
                 (offset >= 0 ||
                  (openfile.offset >= static_cast<size_t>(-offset)))) {
        openfile.offset += offset;
      } else if (whence == SEEK_END &&
                 (offset >= 0 ||
                  static_cast<size_t>(-offset) <= openfile.data->size())) {
        openfile.offset = openfile.data->size() + offset;
      } else {
        *new_offset = -1;
        return EINVAL;
      }
      *new_offset = openfile.offset;
      return 0;
    } else {
      mlibc::panicLogger() << "Invalid FileTableEntry type encountered"
                           << frg::endlog;
      return EIO;
    }
  }

  int read_entries(void* buffer, size_t size, size_t* bytes_read) {
    if (this->internal.is<OpenDir>()) {
      OpenDir& opendir = this->internal.get<OpenDir>();
      // NOTE: opendir.offset is modified by read_entries_offset
      return opendir.dir->read_entries_offset(buffer, size, bytes_read,
                                              opendir.offset);
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

inline path_split_result path_split(frg::string_view path) {
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

inline frg::string_view path_merge(frg::string_view previous,
                                   frg::string_view append) {
  // check if there is actually something to do
  if (append.size() < 1) return previous;
  // check if new path is absolute, if so return it
  if (append.data()[0] == '/') return append;
  auto append_components = PathComponents(append);
  for (auto component = append_components.next(); component.size() > 0;
       component = append_components.next()) {
    if (component.data()[0] == '.') {
      if (component.size() == 2 && component.data()[1] == '.') {
        previous = path_split(previous).dir;
        continue;
      }
      if (component.size() == 1) {
        continue;
      }
    }
    size_t prev_size = previous.size();
    size_t comp_size = component.size();
    char* new_path = (char*)getAllocator().reallocate(
        (void*)previous.data(), prev_size + 1 + comp_size);
    new_path[prev_size] = '/';
    strncpy(new_path + prev_size + 1, component.data(), comp_size);
    previous = frg::string_view(new_path, prev_size + comp_size + 1);
  }
}

class FileTable {
  frg::vector<Rc<FileTableEntry>, MemoryAllocator> open_files{getAllocator()};
  Rc<Directory> working_dir;
  frg::string_view working_dir_path = frg::string_view("/", 1);
  Rc<Directory> fs_root;

  size_t find_free_slot(size_t above = 0) {
    for (size_t i = above; i < open_files.size(); ++i) {
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
    auto entry =
        Rc<FileTableEntry>::make(std::forward<decltype(args)>(args)...);
    this->open_files[idx] = std::move(entry);
  }

  Rc<Directory> get_origin(int dirfd, const char* path) {
    Rc<Directory> base;
    if (path[0] == '/') {
      base = this->fs_root;
    } else if (dirfd == AT_FDCWD) {
      base = this->working_dir;
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

  frg::variant<NoEntry, Rc<Directory>> create_dirs_from_string(
      frg::string_view dir_path, Rc<Directory> current = nullptr) {
    PathComponents components{dir_path};

    if (current == nullptr) {
      current = this->fs_root;
    }

    for (auto component = components.next(); component.size() > 0;
         component = components.next()) {
      auto next = Directory::find(current, component);
      if (next.is<Rc<Directory>>()) {
        current = next.get<Rc<Directory>>();
      } else if (next.is<NoEntry>()) {
        current = Directory::create_dir(current, component);
      } else {
        return NoEntry{};
      }
    }
    return current;
  }

  int create_file_from_buf(size_t set_idx, io_buffer* buf) {
    auto basepath =
        string{dandelion_input_set_ident(set_idx),
               dandelion_input_set_ident_len(set_idx), getAllocator()};
    basepath += "/";
    basepath += string{buf->ident, buf->ident_len, getAllocator()};
    auto pathinfo = path_split(basepath);
    PathComponents components{pathinfo.dir};

    auto dir = create_dirs_from_string(pathinfo.dir);
    if (dir.is<NoEntry>()) return 1;
    auto current_dir = dir.get<Rc<Directory>>();

    auto file = Rc<File>::make(buf);
    Directory::link_file(current_dir, pathinfo.base, file);
    return 0;
  }

  size_t recursive_get_num_entries(Rc<Directory> dir) {
    size_t entries = 0;
    dir->for_each(
        [&](const string& name, Rc<File>& file) {
          (void)name, (void)file;
          ++entries;
        },
        [&](const string& name, Rc<Directory>& subdir) {
          (void)name;
          entries += recursive_get_num_entries(subdir);
        });
    return entries;
  }

  void create_bufs_from_dir(size_t setidx, Rc<Directory> dir,
                            frg::string_view path) {
    dir->for_each(
        [&](const string& name, Rc<File>& file) {
          char* buf_ident = NULL;
          char* name_offset = 0;
          size_t ident_len_with_null = 0;
          if (path.size() > 0) {
            ident_len_with_null = path.size() + name.size() + 1;
            buf_ident = (char*)getAllocator().allocate(ident_len_with_null);
            memcpy(buf_ident, path.data(), path.size());
            name_offset = buf_ident + path.size();
          } else {
            ident_len_with_null = name.size() + 1;
            buf_ident = (char*)getAllocator().allocate(ident_len_with_null);
            name_offset = buf_ident;
          }

          memcpy(name_offset, name.data(), name.size());
          buf_ident[path.size() + name.size()] = '\0';

          struct io_buffer buf {
            .ident = buf_ident, .ident_len = ident_len_with_null - 1,
            .data = file->buffer(), .data_len = file->size(), .key = 0
          };
          dandelion_add_output(setidx, buf);
        },
        [&](const string& name, Rc<Directory>& subdir) {
          string new_path{path, getAllocator()};
          new_path += name;
          new_path += '/';
          create_bufs_from_dir(setidx, subdir, new_path);
        });
  }

 public:
  FileTable() {
    this->fs_root = Rc<Directory>::make(Rc<Directory>{nullptr});
    this->fs_root->set_parent(this->fs_root);
    this->working_dir = this->fs_root;
    this->working_dir_path = frg::string_view("/", 1);

    // add output sets as directories do before inputs so
    // we can stdout or stderr during rest of bring up
    size_t num_ouput_sets = dandelion_output_set_count();
    for (size_t i = 0; i < num_ouput_sets; i++) {
      auto dirpath = string{dandelion_output_set_ident(i),
                            dandelion_output_set_ident_len(i), getAllocator()};
      create_dirs_from_string(dirpath);
    }
    // check add stdout and stderr
    char stdio_chars[] = "stdio";
    char stdout_chars[] = "stdout";
    char stderr_chars[] = "stderr";
    frg::string_view stdio_name = frg::string_view(stdio_chars, 5);
    frg::string_view stdout_name = frg::string_view(stdout_chars, 6);
    frg::string_view stderr_name = frg::string_view(stderr_chars, 6);
    auto stdio = Directory::find(this->fs_root, stdio_name);
    if (stdio.is<Rc<Directory>>()) {
      auto stdio_dir = stdio.get<Rc<Directory>>();
      auto out_file = Rc<File>::make();
      Directory::link_file(stdio_dir, stdout_name, out_file);
      this->create_entry_at(1, FileTableEntry::OpenFile{out_file, 0, O_WRONLY});

      auto err_file = Rc<File>::make();
      Directory::link_file(stdio_dir, stderr_name, err_file);
      this->create_entry_at(2, FileTableEntry::OpenFile{err_file, 0, O_WRONLY});
    } else {
      this->create_entry_at(
          1, FileTableEntry::OpenFile{Rc<File>::make(), 0, O_WRONLY});
      this->create_entry_at(
          2, FileTableEntry::OpenFile{Rc<File>::make(), 0, O_WRONLY});
    }

    // add input sets and files
    size_t num_input_sets = dandelion_input_set_count();
    for (size_t i = 0; i < num_input_sets; ++i) {
      size_t num_bufs = dandelion_input_buffer_count(i);
      ;
      for (size_t j = 0; j < num_bufs; ++j) {
        auto* buf = dandelion_get_input(i, j);

        if (create_file_from_buf(i, buf) != 0) {
          char panic_message[] = "Could not create files from buffer\n";
          ssize_t write_size;
          this->get(2)->write(panic_message, sizeof(panic_message),
                              &write_size);
          sys_libc_panic();
        }
      }
    }

    // check if there is a stdio dir
    // need to use char*, because string directly appends \0 which we don't want
    char stdin_chars[] = "stdin";
    char argv_chars[] = "argv";
    char env_chars[] = "environ";
    frg::string_view stdin_name = frg::string_view(stdin_chars, 5);
    frg::string_view argv_name = frg::string_view(argv_chars, 4);
    frg::string_view env_name = frg::string_view(env_chars, 7);
    if (stdio.is<Rc<Directory>>()) {
      auto stdio_dir = stdio.get<Rc<Directory>>();

      // remove argv and environ from the file tree
      Directory::remove_file(stdio_dir, argv_name);
      Directory::remove_file(stdio_dir, env_name);

      // check if stdin file exists and remove it if so
      auto stdin = Directory::find(stdio_dir, stdin_name);
      if (stdin.is<Rc<File>>()) {
        auto stdin_file = stdin.get<Rc<File>>();
        this->create_entry_at(
            0, FileTableEntry::OpenFile{stdin_file, 0, O_RDONLY});
        Directory::remove_file(stdio_dir, stdin_name);
      } else {
        this->create_entry_at(
            0, FileTableEntry::OpenFile{Rc<File>::make(), 0, O_RDONLY});
      }
    } else {
      this->create_entry_at(
          0, FileTableEntry::OpenFile{Rc<File>::make(), 0, O_RDONLY});
    }
  }

  void finalize() {
    size_t num_out_sets = dandelion_output_set_count();
    // we skip the root set
    for (size_t i = 0; i < num_out_sets; ++i) {
      auto set_path = frg::string_view{dandelion_output_set_ident(i),
                                       dandelion_output_set_ident_len(i)};
      auto entry = Directory::find(this->fs_root, set_path);
      if (entry.is<Rc<Directory>>()) {
        auto dir_entry = entry.get<Rc<Directory>>();
        create_bufs_from_dir(i, std::move(dir_entry), "");
      }
    }
  }

  FileTable(const FileTable&) = delete;
  FileTable(FileTable&&) = delete;

  int set_cwd(int dirfd, const char* path) {
    auto base = this->get_origin(dirfd, path);
    if (base == nullptr) {
      return ENOENT;
    }
    this->working_dir = base;
    // adapt current working directory path
    this->working_dir_path = path_merge(this->working_dir_path, path);
    return 0;
  }

  // TODO might want to replace with a call taking a buffer and a size
  // that directly assembles the string in the buffer
  // also give directories their names so we can just traverse the file system
  char* get_cwd() {
    size_t stringlen = this->working_dir_path.size();
    char* cwd = (char*)getAllocator().allocate(stringlen + 1);
    strncpy(cwd, this->working_dir_path.data(), stringlen);
    cwd[stringlen] = '\0';
    return cwd;
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
        return ENOENT;
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
      if (res != 0) {
        *fd = -1;
        return EACCES;
      }
    }

    *fd = this->create_entry(FileTableEntry::OpenFile{
        file,
        flags & O_APPEND ? file->size() : 0,
        flags,
    });

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
      // TODO check if exists
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

  int linkat(int old_dirfd, const char* old_path, int new_dirfd,
             const char* new_path, int flags) {
    (void)flags;
    // get file for old path
    auto old_origin = this->get_origin(old_dirfd, old_path);
    if (old_origin == nullptr) return EBADF;
    auto old_file = Directory::find(old_origin, old_path);
    if (old_file.is<NoEntry>()) {
      return ENOENT;
    }
    // have found directory or file, now need to insert it at new_path
    // make sure the new_path does not already exist
    auto new_origin = this->get_origin(new_dirfd, new_path);
    auto new_file = Directory::find(new_origin, new_path);
    if (new_file.is<NoEntry>() != 0) return EEXIST;
    auto new_path_split = path_split(new_path);
    auto new_dir_var = create_dirs_from_string(new_path_split.dir, new_origin);
    if (new_dir_var.is<NoEntry>()) return ENOENT;
    Rc<Directory> new_dir = new_dir_var.get<Rc<Directory>>();
    if (old_file.is<Rc<File>>()) {
      Directory::link_file(new_dir, new_path_split.base,
                           old_file.get<Rc<File>>());
    } else {
      Directory::link_dir(new_dir, new_path_split.base,
                          old_file.get<Rc<Directory>>());
    }
    return 0;
  }

  int renameat(int old_dirfd, const char* old_path, int new_dirfd,
               const char* new_path) {
    // get old file
    auto old_path_split = path_split(old_path);
    auto old_origin = this->get_origin(old_dirfd, old_path);
    if (old_origin == nullptr) return EBADF;
    // get old directory
    auto old_dir_entry = Directory::find(old_origin, old_path_split.dir);
    if (!old_dir_entry.is<Rc<Directory>>()) return ENOTDIR;
    Rc<Directory> old_dir = old_dir_entry.get<Rc<Directory>>();
    // get old file and remove it form directory
    auto old_file_entry = Directory::find(old_dir, old_path_split.base);
    int err = 0;
    // also checks that file exists
    err = Directory::remove(old_dir, old_path_split.base);
    if (err != 0) return err;
    // find new folder, do after remove to detect illegal moves
    auto new_origin = this->get_origin(new_dirfd, new_path);
    if (new_origin == nullptr) {
      Directory::link(old_dir, old_path_split.base, old_file_entry);
      return EBADF;
    }
    auto new_path_split = path_split(new_path);
    auto new_dir_entry = Directory::find(new_origin, new_path_split.dir);
    if (!new_dir_entry.is<Rc<Directory>>()) {
      Directory::link(old_dir, old_path_split.base, old_file_entry);
      return ENOTDIR;
    }
    Rc<Directory> new_dir = new_dir_entry.get<Rc<Directory>>();
    auto new_file_entry = Directory::find(new_dir, new_path_split.base);
    // do not replace if the current path points to non empty directory
    if (new_file_entry.is<Rc<Directory>>()) {
      Rc<Directory> new_file_dir = new_dir_entry.get<Rc<Directory>>();
      if (!new_file_dir->is_empty()) {
        Directory::link(old_dir, old_path_split.base, old_file_entry);
        return ENOTEMPTY;
      }
    }
    Directory::remove(new_dir, new_path_split.base);
    Directory::link(new_dir, new_path_split.base, old_dir_entry);
    return 0;
  }

  int fcntl(int fd, int cmd, int arg, int* result) {
    (void)fd, (void)arg;
    *result = 0;
    auto entry = this->get(fd);
    if (entry == nullptr) {
      return EBADF;
    }
    // TODO implement more commands
    switch (cmd) {
      case F_DUPFD:
      case F_DUPFD_CLOEXEC:
        *result = this->find_free_slot((int)arg);
        this->dup2(fd, *result);
        return 0;
      case F_GETFD:
        *result = FD_CLOEXEC;
        return 0;
        // case F_GETFL:
        // 		*result = file->get_flags();
        // 		return 0;
        // 	case F_SETFL:
        // 		file->set_flags(arg);
        // 		return 0;
        // 	default:
        // return EINVAL;
        // }
      default:
        mlibc::infoLogger()
            << "fcntl switch default cmd on " << cmd << frg::endlog;
    }
    return ENOKEY;
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
    if (check_fd(fd) != 0) {
      return EBADF;
    }
    this->open_files[fd] = nullptr;
    return 0;
  }

  int stat(int fd, struct stat* statbuf) {
    if (statbuf == NULL) return EBADF;
    int ret_val = check_fd(fd);
    if (ret_val != 0) return EBADF;
    *statbuf = {0};
    FileTableEntry* current_file = this->open_files[fd].get();
    if (current_file->internal.is<FileTableEntry::OpenFile>()) {
      Rc<File> file = current_file->get_file();
      if (file != nullptr) {
        statbuf->st_size = file->size();
        statbuf->st_mode =
            S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
      }
    } else {
      statbuf->st_mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
    }

    return 0;
  }
};

};  // namespace mlibc::vfs