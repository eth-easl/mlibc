#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>

const char teststr[] = "Hello world";

void print_dir_entries(DIR* dir) {
    printf("dir entries:\n");
    for (struct dirent* ent = readdir(dir); ent != NULL; ent = readdir(dir)) {
        printf("%s\n", ent->d_name);
    }
}

// create 1000 numbered files in the directory supplied by dirfd
void create_files(int dirfd) {
    for (int i = 0; i < 1000; i++) {
        char buf[32];
        sprintf(buf, "%d", i);
        int fd = openat(dirfd, buf, O_CREAT | O_RDWR, 0777);
        close(fd);
    }
}

int main() {
    mkdir("foo", 0777);
    int dirfd = open("foo", O_RDONLY);
    int fd1 = openat(dirfd, "bar", O_CREAT | O_RDWR, 0777);
    int fd2 = openat(dirfd, "baz", O_CREAT | O_RDWR, 0777);
    mkdirat(dirfd, "qux", 0777);
    printf("dirfd: %d, fd1: %d, fd2: %d\n", dirfd, fd1, fd2);
    // write "Hello world" to fd1
    write(fd1, teststr, sizeof(teststr) - 1);
    close(fd1);
    close(fd2);
    close(dirfd);

    int dir2fd = open("foo/qux", O_RDONLY);
    create_files(dir2fd);

    // print all entries in "foo"
    DIR* dir = opendir("foo");
    if (dir == NULL) {
        perror("open foo");
        return 1;
    } else {
        print_dir_entries(dir);
        rewinddir(dir);
        print_dir_entries(dir);
    }

    close(dir2fd);

    DIR* dir2 = opendir("foo/qux");
    if (dir2 == NULL) {
        perror("open foo/qux");
        return 1;
    } else {
        print_dir_entries(dir2);
        closedir(dir2);
    }


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

    res = rmdir("foo");
    if (res != 0) {
        perror("rmdir");
    }

    closedir(dir);
    return 0;
}