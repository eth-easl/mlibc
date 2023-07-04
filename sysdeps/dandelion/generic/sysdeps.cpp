#include <mlibc-config.h>
#include <bits/ensure.h>
#include <abi-bits/fcntl.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include "mlibc/arch-defs.hpp"
#include "mlibc/posix-sysdeps.hpp"

#include "abi-bits/errno.h"
#include "abi-bits/fcntl.h"

#include <dandelion/runtime.h>
#include <filesystem.hpp>

#ifndef MLIBC_BUILDING_RTDL
extern "C" long __do_syscall_ret(unsigned long ret) {
	if(ret > -4096UL) {
		errno = -ret;
		return -1;
	}
	return ret;
}
#endif

extern "C" {

// required for linking with normal gcc
__attribute__((weak)) char __dso_handle;

};

namespace mlibc {

namespace vfs {

FileTable& get_file_table() {
	static frg::eternal<FileTable> list;
	return *list;
}

};

int sys_vm_map(void *hint, size_t size, int prot, int flags,
		int fd, off_t offset, void **window) {
	(void)hint, (void)prot, (void)flags, (void)fd, (void)offset;
	void* res = dandelion_alloc(size, page_size);
	if (res == NULL) {
		mlibc::infoLogger() << "mlibc: sys_vm_map: out of memory" << frg::endlog;
		return ENOMEM;
	}
	*window = res;
	return 0;
}

int sys_vm_unmap(void *pointer, size_t size) {
	(void)pointer, (void)size;
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
  dandelion_exit(INT_MIN);
  __builtin_unreachable();
}

int sys_tcb_set(void *pointer) {
#if defined(__x86_64__)
	dandelion_set_thread_pointer(pointer);
	// auto ret = do_syscall(SYS_arch_prctl, 0x1002 /* ARCH_SET_FS */, pointer);
	// if(int e = sc_error(ret); e)
	// 	return e;
#elif defined(__riscv)
	uintptr_t thread_data = reinterpret_cast<uintptr_t>(pointer) + sizeof(Tcb);
	dandelion_set_thread_pointer((void*)thread_data);
	// asm volatile ("mv tp, %0" :: "r"(thread_data));
#elif defined (__aarch64__)
	uintptr_t thread_data = reinterpret_cast<uintptr_t>(pointer) + sizeof(Tcb) - 0x10;
	dandelion_set_thread_pointer((void*)thread_data);
	// asm volatile ("msr tpidr_el0, %0" :: "r"(thread_data));
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
	(void)fd, (void)flags, (void)statbuf, (void)path;
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
	(void)buf, (void)size;
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
	(void)nfds, (void)readfds, (void)writefds, (void)exceptfds, (void)timeout, (void)sigmask, (void)num_events;
	return ENOSYS;
}

int sys_pipe(int *fds, int flags) {
	(void)fds, (void)flags;
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
	(void)fds, (void)count, (void)timeout, (void)num_events;
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
	// serialize all files to dandelion io structure
	vfs::get_file_table().finalize();

	dandelion_exit(status);
	__builtin_unreachable();
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
	(void)target_path, (void)link_path;
	return ENOSYS;
}

int sys_symlinkat(const char *target_path, int dirfd, const char *link_path) {
	(void)target_path, (void)dirfd, (void)link_path;
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
	(void)path, (void)buf, (void)bufsiz, (void)len;
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
	(void)flags;
	memset(buffer, 0, length);
	*bytes_written = length;
	return 0;
}

int sys_getentropy(void *buffer, size_t length) {
	ssize_t written;
	return sys_getrandom(buffer, length, 0, &written);
}

} // namespace mlibc
