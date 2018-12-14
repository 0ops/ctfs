#ifndef ZERO_UTILS_H
#define ZERO_UTILS_H

#include <stdint.h>
#include <stdlib.h>

#define BITS(byte, start, end) ((byte>>start)&((1<<(end-start))-1))
#define BITS_SET(byte, pos) (byte|(1<<pos))
#define BITS_CLR(byte, pos) (byte&(~(1<<pos)))
#define BITS_SET_VAL(byte, start, end, val) ((byte)&\
                                            (~(((1<<(end-start))-1)<<start))|\
                                            (val<<start))

#define PTRARRAY_LEN(array, len) while(((uint64_t *)array)[len])len++;

#define MIN(a, b) a<b?a:b
#define MAX(a, b) a>b?a:b

void zero_hexdump(unsigned char *mem, int len);
//#ifdef DEBUG
//#define LOG(...) printf(__VA_ARGS__)
//#else
//#define LOG(...)
//#endif

#endif
