#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>

#define FILE_COUNT 1000

const char teststr[] = "Hello world";

void print_dir_entries(DIR* dir) {
    printf("dir entries:\n");
    for (struct dirent* ent = readdir(dir); ent != NULL; ent = readdir(dir)) {
        printf("%s\n", ent->d_name);
    }
}

void assert_dir_entry_count(DIR* dir, int n) {
    // checks that dir has n entries
    rewinddir(dir);
    int count = 0;
    for (struct dirent* ent = readdir(dir); ent != NULL; ent = readdir(dir)) {
        count++;
    }
    if (count != n) {
        printf("expected %d entries, got %d\n", n, count);
    }
}

// create 1000 numbered files in the directory supplied by dirfd
void create_files(int dirfd, int n) {
    for (int i = 0; i < n; i++) {
        char buf[32];
        sprintf(buf, "%d", i);
        int fd = openat(dirfd, buf, O_CREAT | O_RDWR, 0777);
        close(fd);
    }
}

// prints the contents of the file referred to by fd
void print_file(int fd) {
    char buf[1024];
    int n = read(fd, buf, sizeof(buf));
    buf[n] = '\0';
    printf("%s\n", buf);
}

void dump(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return;
    }
    printf("== Start of file %s ==\n", path);
    print_file(fd);
    printf("==   End of file %s ==\n", path);
    close(fd);
}

int main() {
    dump("input.txt");

    mkdir("output", 0);
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
    create_files(dir2fd, FILE_COUNT);

    // print all entries in "foo"
    DIR* dir = opendir("foo");
    if (dir == NULL) {
        perror("open foo");
        return 1;
    } else {
        assert_dir_entry_count(dir, 3);
    }

    close(dir2fd);

    DIR* dir2 = opendir("foo/qux");
    if (dir2 == NULL) {
        perror("open foo/qux");
        return 1;
    } else {
        assert_dir_entry_count(dir2, FILE_COUNT);
        closedir(dir2);
    }


    dump("foo/bar");

    // int res = remove("foo/bar");
    // res = remove("foo/baz");
    // if (res != 0) {
    //     perror("remove");
    // }

    // res = rmdir("foo");
    // if (res != 0) {
    //     perror("rmdir foo");
    //     return 1;
    // }

    int outdirfd = open("output", O_RDONLY);
    int outfd = openat(outdirfd, "out.txt", O_CREAT | O_RDWR, 0777);
    // write "Output for testing" to outfd
    write(outfd, "Output for testing", 18);

    mkdirat(outdirfd, "subdir", 0777);
    int out2fd = openat(outdirfd, "subdir/out2.txt", O_CREAT | O_RDWR, 0777);
    // write "different output in subfile" to out2fd
    write(out2fd, "different output in subfile", 27);
    
    close(outfd);
    close(out2fd);
    close(outdirfd);

    closedir(dir);

    int rootoutfd = open("root_output.txt", O_CREAT | O_RDWR, 0777);
    // write "root output file" to rootoutfd
    write(rootoutfd, "root output file", 16);
    close(rootoutfd);

    printf("success\n");
    return 0;
}