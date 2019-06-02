/*************************************************************************
	> File Name: dec.c
	> Author: 
	> Mail: 
	> Created Time: Sun May 26 16:22:03 2019
 ************************************************************************/

#include <stdio.h>
#include <stdint.h>
void encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        printf("%d %d\n", v0, v1);
    }
    v[0]=v0; v[1]=v1;
}

void decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

int main()
{
    uint32_t k[4] = {0, 0, 0, 0};
    int i = 0;
    uint32_t c[2] = {2586051617, 2764128737};
    decipher(32, c, k);
    for(i=0; i<8; ++i)
        printf("%c", *((unsigned char*)(c)+i));
    c[0] = 1835204653;
    c[1] = 2601945884;
    decipher(32, c, k);
    for(i=0; i<8; ++i)
        printf("%c", *((unsigned char*)(c)+i));
    c[0] = 95579550;
    c[1] = 993221996;
    decipher(32, c, k);
    for(i=0; i<8; ++i)
        printf("%c", *((unsigned char*)(c)+i));
    c[0] = 1624609160;
    c[1] = 781843991;
    decipher(32, c, k);
    for(i=0; i<8; ++i)
        printf("%c", *((unsigned char*)(c)+i));
    printf("4bf4a}");
    puts("");
}
