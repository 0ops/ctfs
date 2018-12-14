#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/bn.h>
#include "enc_sock.h"

#ifdef DEBUG
#define LOG(...) printf(__VA_ARGS__)
#define LOG_ERROR(...) perror(__VA_ARGS__)
#else
#define LOG(...)
#define LOG_ERROR(...)
#endif

uc key[P_BITLEN/8] = {0};
uc s[258] = {0};

void zero_error(const char*s)
{
    LOG_ERROR(s);
    exit(1);
}

void init_rc4()
{
    int i;
    uc k[256];
    uc tmp, j = 0;
    for (i = 0; i < 256; ++i)
    {
        s[i] = i;
        k[i] = key[i%(P_BITLEN/8)];
    }
    for (i = 0; i < 256; ++i)
    {
        j += s[i] + k[i];
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}

void crypt(uc *data, size_t len)
{
    size_t k;
    uc t, tmp;
    for (k = 0; k < len; ++k)
    {
        s[256] += 1;
        s[257] += s[s[256]];
        tmp = s[s[256]];
        s[s[256]] = s[s[257]];
        s[s[257]] = tmp;
        t = s[s[256]] + s[s[257]];
        data[k] ^= s[t];
    }
}

void init_dh()
{
    BIGNUM *g, *x, *p;
    FILE *rand_fp;
    char recv_buf[P_BITLEN/4+1];
    char *hex_buf;

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    g = BN_CTX_get(ctx);
    BN_hex2bn(&p, P);
    BN_hex2bn(&g, G);
    BN_rand(x, P_BITLEN-1, 0, 0);
#ifdef DEBUG
    printf("x: "); BN_print_fp(stdout, x);puts("");
#endif
    BN_mod_exp(g, g, x, p, ctx);
#ifdef DEBUG
    printf("gx: "); BN_print_fp(stdout, g);puts("");
#endif
    hex_buf = BN_bn2hex(g);
    write(1, hex_buf, strlen(hex_buf));
    OPENSSL_free(hex_buf);
    bzero(recv_buf, P_BITLEN/4+1);
    read(0, recv_buf, P_BITLEN/4);
    if (!BN_hex2bn(&g, recv_buf))
    {
        LOG("BN_hex2bn failed.");
        exit(1);
    }
#ifdef DEBUG
    printf("gy: "); BN_print_fp(stdout, g);puts("");
#endif
    BN_mod_exp(g, g, x, p, ctx);
#ifdef DEBUG
    printf("key: "); BN_print_fp(stdout, g);puts("");
#endif
    BN_bn2bin(g, key);
    // printf("%llx\n", *(long long unsigned*)key);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void zero_send(void* buf, size_t len)
{
    uc tmp_buf[1024];
    ssize_t res;
    size_t buf_len;
    while (len)
    {
        if (len > 1024)
            buf_len = 1024;
        else
            buf_len = len;
        memcpy(tmp_buf, buf, buf_len);
        crypt(tmp_buf, buf_len);
        res = write(1, tmp_buf, buf_len);
        if (res < 0)
            zero_error("write");
        buf += res;
        len -= res;
    }
}

void zero_recv(void* buf, size_t len)
{
    ssize_t res;
    while (len)
    {
        res = read(0, buf, len);
        if (res <= 0)
            zero_error("read");
        crypt(buf, res);
#ifdef DEBUGGG
        int i;
        printf("len: %d; ", len);
        for (i = 0; i < res; ++i)
            printf("%02x", *(uc*)(buf+i));
#endif
        buf += res;
        len -= res;
    }
#ifdef DEBUGGG
    printf("\n");
#endif
}

