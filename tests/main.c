#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

const char teststr[] = "Hello world";

int main() {
    mkdir("foo", 0777);
    int dirfd = open("foo", O_RDONLY);
    int fd1 = openat(dirfd, "bar", O_CREAT | O_RDWR, 0777);
    int fd2 = openat(dirfd, "baz", O_CREAT | O_RDWR, 0777);
    printf("dirfd: %d, fd1: %d, fd2: %d\n", dirfd, fd1, fd2);
    // write "Hello world" to fd1
    write(fd1, teststr, sizeof(teststr) - 1);
    close(fd1);
    close(fd2);
    close(dirfd);

    int fd3 = open("foo/bar", O_RDONLY);
    // print contents of fd3
    char buf[1024];
    int n = read(fd3, buf, sizeof(buf));
    buf[n] = '\0';
    printf("fd3: %s, n: %d\n", buf, n);
    close(fd3);

    int res = remove("foo/bar");
    if (res != 0) {
        perror("remove");
    }

    return 0;
}