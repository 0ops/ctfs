#include <stdio.h>
#include <unistd.h>

void zero_hexdump(unsigned char *mem, int len) {
    int i = 0;
    int j = 0;
    int maxlines = len/0x10+1;
    int tmp;

    for (; i < maxlines; i+=0x1) {
        if (i == maxlines-1) {
            tmp = len%0x10;

        } else {
            tmp = 0x10;

        }
        for (; j < tmp; j+=0x1) {
            if (j == 7) {
                //printf("%02x        ", *(mem+j+i*0x10));
                printf("%02x ", *(mem+j+i*0x10));

            } else {
                printf("%02x ", *(mem+j+i*0x10));

            }

        }
        puts("");
        j = 0x0;

    }

    write(1, mem, len);
    puts("\n");

}
