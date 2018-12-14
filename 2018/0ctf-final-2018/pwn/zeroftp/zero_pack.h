#ifndef ZERO_PACK_H
#define ZERO_PACK_H

#include <stdint.h>
#include <stdlib.h>

enum zero_basic_type {
    ZERO_BOOL = 1,
    ZERO_STRING = 2,
    ZERO_RAW = 3,
    ZERO_INT = 4,
    ZERO_LIST = 5
};

typedef uint8_t zero_info_t ;
typedef uint8_t zero_types_t ;

typedef struct zero_basic_t {
    uint8_t type;
    size_t len;
    void *ptr;
} zero_basic_t;

typedef int32_t result_t;

enum RETURN_RESULT {
    RET_SUCCESS = 0,
    RET_FAILED = -1,
} card;

#define ZERO_BASIC_TYPE(zero_basic) zero_basic->type
#define ZERO_BOOL_VAL(zero_basic) *((uint8_t *)zero_basic->ptr)
#define ZERO_INT_VAL(zero_basic) *((uint64_t *)(((char *)zero_basic->ptr)+1))
//#define ZERO_INT_VAL(zero_basic) *((uint64_t *)(((char *)zero_basic->ptr)+1))
#define ZERO_STRING_VAL(zero_basic) (char *)(zero_basic->ptr)

/*
 * functions
 */

int zero_unpack_bool(uint8_t *in, uint8_t **out_p, zero_basic_t **zero_basic);
int zero_unpack_string(uint8_t *in, uint8_t **out_p, zero_basic_t **zero_basic);
int zero_unpack_raw(uint8_t *in, uint8_t **out_p, zero_basic_t **zero_basic);
int zero_unpack_int(uint8_t *in, uint8_t **out_p, zero_basic_t **zero_basic);
//int zero_unpack_list(uint8_t *in, uint8_t **out_p, zero_basic_t **zero_basic);
//int zero_unpack(uint8_t *in, uint8_t **out_p, zero_basic_t **zero_basic);
int zero_pack(zero_basic_t *zero_basic, uint8_t *in, uint8_t **out_p);
void zero_bool_new(zero_basic_t **zero_basic_p, uint8_t val);
void zero_string_new(zero_basic_t **zero_basic_p, char *val);
void zero_raw_new(zero_basic_t **zero_basic_p, uint8_t *raw, size_t len);
void zero_int_new(zero_basic_t **zero_basic_p, uint64_t val, uint8_t endian);
void zero_list_new(zero_basic_t **zero_basic_p, zero_basic_t **list);
size_t zero_pack_len(zero_basic_t *zero_basic);
void zero_basic_free(zero_basic_t *zero_basic);

#ifdef DEBUG
void test_zero_pack();
void zero_basic_dump(zero_basic_t *, size_t);
#endif

#endif
