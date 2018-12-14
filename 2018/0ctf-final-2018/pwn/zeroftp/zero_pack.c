#include "zero_pack.h"
#include "zero_utils.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

//#define DEBUG

#ifdef DEBUG2
#define LOG(...) printf(__VA_ARGS__)
#else
#define LOG(...)
#endif

/*
 * bits[0:3] - types
 *
 * types:
 *  1. bool
 *      bits[3] - value 0 or 1
 *  2. string
 *      null terminated
 *  3. raw
 *      bits[3] - short raw (0) or long raw (1)
 *      if short raw
 *          bits[4:8] - length
 *      else if long raw
 *          bits[4:8] - length of length
 *  4. int
 *      bits[4] - endian
 *      bits[5:8] - length
 *  5. list
 *      bits[3:8] - length of length
 */

#define CHECK_MALLOC(ptr, err) { \
	do { \
		if ((ptr) == (err)) { \
			exit(-1); \
		} \
	} while (0); \
}

uint8_t *g_buf;
size_t g_buf_len;

int zero_unpack_bool(uint8_t *in, uint8_t **out_p, zero_basic_t **p_zero_basic) {
    uint8_t *payload = in;
    zero_info_t zero_info;
    uint8_t zero_basic_types;
    zero_basic_t *zero_basic = NULL;

    zero_info = payload[0];

    zero_basic_types = BITS(zero_info, 0, 3);

    if (zero_basic_types != 0x1) {
        return RET_FAILED;
    } else {
        zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
        CHECK_MALLOC(zero_basic, NULL);
        memset(zero_basic, 0, sizeof(zero_basic_t));
        zero_basic->type = 1;
        zero_basic->len = 1;
        zero_basic->ptr = malloc(1);
        *(uint8_t *)(zero_basic->ptr) = BITS(zero_info, 3, 4);

        *out_p = in+1;
        *p_zero_basic = zero_basic;

        LOG("unpack bool %d\n", *(uint8_t *)(zero_basic->ptr));

        return RET_SUCCESS;
    }

}

int zero_unpack_string(uint8_t *in, uint8_t **out_p, zero_basic_t **p_zero_basic) {
    uint8_t *payload = in;
    zero_info_t zero_info;
    uint8_t zero_basic_types;
    zero_basic_t *zero_basic = NULL;

    zero_info = payload[0];

    zero_basic_types = BITS(zero_info, 0, 3);

    if (zero_basic_types != 0x2) {
        return RET_FAILED;
    } else {
        zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
        CHECK_MALLOC(zero_basic, NULL);
        memset(zero_basic, 0, sizeof(zero_basic_t));
        zero_basic->type = 2;
        zero_basic->len = strlen(payload+1)+1;
        zero_basic->ptr = malloc(zero_basic->len);
        CHECK_MALLOC(zero_basic->ptr, NULL);
        memset((uint8_t *)zero_basic->ptr, 0, zero_basic->len);
        strcpy(zero_basic->ptr, payload+1);

        *out_p = in+1+zero_basic->len;
        *p_zero_basic = zero_basic;

        LOG("unpack string %s\n", (uint8_t *)(zero_basic->ptr));

        return RET_SUCCESS;
    }
}

int zero_unpack_raw(uint8_t *in, uint8_t **out_p, zero_basic_t **p_zero_basic) {
    uint8_t *payload = in;
    zero_info_t zero_info;
    uint8_t zero_basic_types;
    uint8_t zero_raw_type = 0;
    uint8_t zero_raw_len = 0;
    size_t zero_raw_long_len = 0;
    zero_basic_t *zero_basic = NULL;

    zero_info = payload[0];

    zero_basic_types = BITS(zero_info, 0, 3);

    if (zero_basic_types != 0x3) {
        return RET_FAILED;
    } else {
        zero_raw_type = BITS(zero_info, 3, 4);
        zero_raw_len = BITS(zero_info, 4, 8);

        if (!zero_raw_type) {
            /* short raw */
            zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
            CHECK_MALLOC(zero_basic, NULL);
            memset(zero_basic, 0, sizeof(zero_basic_t));
            zero_basic->type = 3;
            zero_basic->len = zero_raw_len;
            zero_basic->ptr = malloc(zero_raw_len);
            CHECK_MALLOC(zero_basic->ptr, NULL);
            memset((uint8_t *)zero_basic->ptr, 0, zero_raw_len);
            memcpy(zero_basic->ptr, payload+1, zero_raw_len);

            *out_p = in+1+zero_basic->len;
            *p_zero_basic = zero_basic;

            LOG("unpack short raw %s\n", (uint8_t *)(zero_basic->ptr));

            return RET_SUCCESS;
        } else {
            /* long raw */
            if (zero_raw_len >= 6) {
                return RET_FAILED;
            } else {
                uint64_t tmp = 1;
                for (int i = 0; i < zero_raw_len; i++, tmp*=0x100) {
                    zero_raw_long_len += payload[1+i]*tmp;
                }

                zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
                CHECK_MALLOC(zero_basic, NULL);
                memset(zero_basic, 0, sizeof(zero_basic_t));
                zero_basic->type = 3;
                zero_basic->len = zero_raw_long_len;
                zero_basic->ptr = malloc(zero_raw_long_len);
                CHECK_MALLOC(zero_basic->ptr, NULL);
                memset((uint8_t *)zero_basic->ptr, 0, zero_raw_long_len);
                memcpy(zero_basic->ptr, payload+1+zero_raw_len, zero_raw_long_len);

                *out_p = in+1+zero_basic->len+zero_raw_len;
                *p_zero_basic = zero_basic;

                LOG("unpack long raw %s length %lu\n", (uint8_t *)(zero_basic->ptr), zero_raw_long_len);

                return RET_SUCCESS;
            }
        }
    }

}

int zero_unpack_int(uint8_t *in, uint8_t **out_p, zero_basic_t **p_zero_basic) {
    uint8_t *payload = in;
    zero_info_t zero_info;
    uint8_t zero_basic_types;
    uint8_t zero_int_type = 0;
    uint8_t zero_int_len = 0;
    uint8_t zero_int_endian = 0;
    uint64_t zero_int_val = 0;
    zero_basic_t *zero_basic = NULL;

    zero_info = payload[0];

    zero_basic_types = BITS(zero_info, 0, 3);

    if (zero_basic_types != 0x4) {
        return RET_FAILED;
    } else {
        zero_int_type = BITS(zero_info, 3, 4);
        zero_int_len = BITS(zero_info, 5, 8)+1;
        zero_int_endian = BITS(zero_info, 4, 5);

        if (!zero_int_endian) {
            /* little endian */
            zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
            CHECK_MALLOC(zero_basic, NULL);
            memset(zero_basic, 0, sizeof(zero_basic_t));
            zero_basic->type = 4;
            zero_basic->len = zero_int_len;
            zero_basic->ptr = malloc(9);
            CHECK_MALLOC(zero_basic->ptr, NULL);

            uint64_t tmp = 1;
            for (int i = 0; i < zero_int_len; i++, tmp*=0x100) {
                zero_int_val += payload[1+i]*tmp;
            }
            *((uint64_t *)(((char *)zero_basic->ptr)+1)) = zero_int_val;
            *((char *)zero_basic->ptr) = zero_int_endian;

            *out_p = in+1+zero_basic->len;
            *p_zero_basic = zero_basic;

            LOG("unpack int little endian %lx\n", *((uint64_t *)(((char *)zero_basic->ptr)+1)));

            return RET_SUCCESS;
        } else {
            /* big endian */
            zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
            CHECK_MALLOC(zero_basic, NULL);
            memset(zero_basic, 0, sizeof(zero_basic_t));
            zero_basic->type = 4;
            zero_basic->len = zero_int_len;
            zero_basic->ptr = malloc(9);
            CHECK_MALLOC(zero_basic->ptr, NULL);

            uint64_t tmp = 1;
            for (int i = 0; i < zero_int_len; i++, tmp*=0x100) {
                zero_int_val += payload[1+zero_int_len-i-1]*tmp;
            }
            *((uint64_t *)(((char *)zero_basic->ptr)+1)) = zero_int_val;
            *((char *)zero_basic->ptr) = zero_int_endian;

            *out_p = in+1+zero_basic->len;
            *p_zero_basic = zero_basic;

            LOG("unpack int big endian %lx\n", *((uint64_t *)(((char *)zero_basic->ptr)+1)));

            return RET_SUCCESS;

        }
    }

}

//int zero_unpack_list(uint8_t *in, uint8_t **out_p, zero_basic_t **p_zero_basic) {
//    uint8_t *payload = in;
//    uint8_t *payload_in, *payload_out;
//    zero_info_t zero_info;
//    uint8_t zero_basic_types;
//    uint8_t zero_list_type = 0;
//    uint8_t zero_list_len = 0;
//    size_t zero_list_long_len = 0;
//    zero_basic_t *zero_basic = NULL;
//    zero_basic_t *zero_basic_tmp = NULL;
//
//    zero_info = payload[0];
//
//    zero_basic_types = BITS(zero_info, 0, 3);
//
//    if (zero_basic_types != 0x5) {
//        return RET_FAILED;
//    } else {
//        zero_list_type = BITS(zero_info, 3, 4);
//        zero_list_len = BITS(zero_info, 4, 8);
//
//        if (!zero_list_type) {
//            /* short list */
//            zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
//            CHECK_MALLOC(zero_basic, NULL);
//            memset(zero_basic, 0, sizeof(zero_basic_t));
//            zero_basic->type = 5;
//            zero_basic->len = zero_list_len;
//            zero_basic->ptr = malloc(sizeof(zero_basic_t *)*zero_list_len);
//            CHECK_MALLOC(zero_basic->ptr, NULL);
//            memset(zero_basic->ptr, 0, sizeof(zero_basic_t *)*zero_list_len);
//
//            payload_in = payload+1;
//            for (int i = 0; i < zero_list_len; i++) {
//                zero_unpack(payload_in, &payload_out, &zero_basic_tmp);
//                ((zero_basic_t **)zero_basic->ptr)[i] = zero_basic_tmp;
//                payload_in = payload_out;
//            }
//
//            *out_p = payload_out;
//            *p_zero_basic = zero_basic;
//
//            LOG("unpack short list %d\n", zero_list_len);
//
//            return RET_SUCCESS;
//        } else {
//            /* long list */
//            if (zero_list_len >= 6) {
//                return RET_FAILED;
//            } else {
//                uint64_t tmp = 1;
//                for (int i = 0; i < zero_list_len; i++, tmp*=0x100) {
//                    zero_list_long_len += payload[1+i]*tmp;
//                }
//
//                zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
//                CHECK_MALLOC(zero_basic, NULL);
//                memset(zero_basic, 0, sizeof(zero_basic_t));
//                zero_basic->type = 5;
//                zero_basic->len = zero_list_long_len;
//                zero_basic->ptr = malloc(sizeof(zero_basic_t *)*zero_list_long_len);
//                CHECK_MALLOC(zero_basic->ptr, NULL);
//                memset(zero_basic->ptr, 0, sizeof(zero_basic_t *)*zero_list_long_len);
//
//                payload_in = payload+1+zero_list_len;
//                for (int i = 0; i < zero_list_long_len; i++) {
//                    zero_unpack(payload_in, &payload_out, &zero_basic_tmp);
//                    ((zero_basic_t **)zero_basic->ptr)[i] = zero_basic_tmp;
//                    payload_in = payload_out;
//                }
//
//                *out_p = payload_out;
//                *p_zero_basic = zero_basic;
//
//                LOG("unpack long list %d\n", zero_list_long_len);
//
//                return RET_SUCCESS;
//            }
//        }
//    }
//}

static inline int zero_pack_bool(zero_basic_t *zero_basic, uint8_t *in, uint8_t **out_p) {
    uint8_t *payload = in;
    size_t payload_len = 0;
    uint8_t info = 0x0;
    uint8_t val = *(uint8_t *)zero_basic->ptr;

    payload_len += 1;
    info = BITS_SET_VAL(info, 0, 3, 1); // types
    info = BITS_SET_VAL(info, 3, 4, val); // bool
    *payload = info;
    *out_p = payload+payload_len;

} __attribute__((always_inline))

static inline int zero_pack_string(zero_basic_t *zero_basic, uint8_t *in, uint8_t **out_p) {
    uint8_t *payload = in;
    uint8_t info = 0x0;
    uint8_t *str = (uint8_t *)zero_basic->ptr;
    size_t str_len = 0;

    info = BITS_SET_VAL(info, 0, 3, 2); // types
    *payload = info;
    payload += 1;

    str_len = strlen(str);
    strcpy(payload, str);
    payload += str_len+1;
    *out_p = payload;

} __attribute__((always_inline))

static inline int zero_pack_raw(zero_basic_t *zero_basic, uint8_t *in, uint8_t **out_p) {
    uint8_t *payload = in;
    uint8_t info = 0x0;
    uint8_t *raw = (uint8_t *)zero_basic->ptr;
    size_t raw_len = zero_basic->len;
    size_t raw_len_len = 0;

    if (raw_len <= 15) {
        info = BITS_SET_VAL(info, 0, 3, 3); // types
        info = BITS_SET_VAL(info, 3, 4, 0); // short or long
        info = BITS_SET_VAL(info, 4, 8, raw_len); // len
        *payload = info;
        payload += 1;

        memcpy(payload, raw, raw_len);
        payload += raw_len;
        *out_p = payload;
    } else {
        info = BITS_SET_VAL(info, 0, 3, 3); // types
        info = BITS_SET_VAL(info, 3, 4, 1); // short or long

        payload += 1;
        for (int i = raw_len; i; i/=0x100) {
            *payload = i%0x100;
            payload += 1;
            raw_len_len += 1;
        }

        info = BITS_SET_VAL(info, 4, 8, raw_len_len); // len of len
        *(payload-raw_len_len-1) = info;
        memcpy(payload, raw, raw_len);
        payload += raw_len;
        *out_p = payload;
    }

} __attribute__((always_inline))

static inline int zero_pack_int(zero_basic_t *zero_basic, uint8_t *in, uint8_t **out_p) {

    uint8_t *payload = in;
    uint8_t info = 0x0;
    uint64_t int_val = *(uint64_t *)(((char *)zero_basic->ptr)+1);
    uint8_t int_endian = *((char *)zero_basic->ptr);
    uint8_t int_len = zero_basic->len;


    info = BITS_SET_VAL(info, 0, 3, 4); // types
    info = BITS_SET_VAL(info, 4, 5, int_endian); // endian
    info = BITS_SET_VAL(info, 5, 8, int_len-1);
    *payload = info;
    payload += 1;

    if (!int_endian) {
        /* little endian */
        uint64_t tmp = 1;
        for (int i = 0; i < int_len; i++, tmp*=0x100) {
            *(payload+i) = int_val/tmp;
        }
    } else {
        /* big endian */
        uint64_t tmp = 1;
        for (int i = 0; i < int_len; i++, tmp*=0x100) {
            *(payload+int_len-1-i) = int_val/tmp;
        }
    }
    payload += int_len;

    *out_p = payload;

} __attribute__((always_inline))

static inline int zero_pack_list(zero_basic_t *zero_basic, uint8_t *in, uint8_t **out_p) {
    uint8_t *payload = in;
    uint8_t *payload_in = in+1;
    uint8_t *payload_out = in;
    uint8_t info = 0x0;
    uint8_t *list = (uint8_t *)zero_basic->ptr;
    size_t list_len = zero_basic->len;
    size_t list_len_len = 0;

    if (list_len <= 15) {
        info = BITS_SET_VAL(info, 0, 3, 5); // types
        info = BITS_SET_VAL(info, 3, 4, 0); // short or long
        info = BITS_SET_VAL(info, 4, 8, list_len); // len
        *payload = info;
        payload += 1;

        payload_out = payload;
        for (int i = 0; i < list_len; i++) {
            zero_pack(((zero_basic_t **)zero_basic->ptr)[i], payload_in, &payload_out);
            payload_in = payload_out;
        }
        *out_p = payload_out;
    } else {
        info = BITS_SET_VAL(info, 0, 3, 5); // types
        info = BITS_SET_VAL(info, 3, 4, 1); // short or long

        payload += 1;
        for (int i = list_len; i; i/=0x100) {
            *payload = i%0x100;
            payload += 1;
            list_len_len += 1;
        }

        info = BITS_SET_VAL(info, 4, 8, list_len_len); // len of len
        *(payload-list_len_len-1) = info;

        payload_in = payload;
        payload_out = payload;
        for (int i = 0; i < list_len; i++) {
            zero_pack(((zero_basic_t **)zero_basic->ptr)[i], payload_in, &payload_out);
            payload_in = payload_out;
        }
        *out_p = payload_out;
    }

} __attribute__((always_inline))

//int zero_unpack(uint8_t *in, uint8_t **out_p, zero_basic_t **p_zero_basic) {
//    zero_info_t zero_info;
//    uint8_t zero_basic_types;
//    int result;
//    zero_info = in[0];
//    zero_basic_types = BITS(zero_info, 0, 3);
//
//    switch(zero_basic_types) {
//        case 1:
//            result = zero_unpack_bool(in, out_p, p_zero_basic);
//            return result;
//        case 2:
//            result = zero_unpack_string(in, out_p, p_zero_basic);
//            return result;
//            break;
//        case 3:
//            result = zero_unpack_raw(in, out_p, p_zero_basic);
//            return result;
//            break;
//        case 4:
//            result = zero_unpack_int(in, out_p, p_zero_basic);
//            return result;
//            break;
//        case 5:
//            result = zero_unpack_list(in, out_p, p_zero_basic);
//            return result;
//            break;
//        default:
//            return RET_FAILED;
//            break;
//    }
//}

size_t zero_pack_bool_len(zero_basic_t *zero_basic) {
    return 1;
}

size_t zero_pack_string_len(zero_basic_t *zero_basic) {
    return zero_basic->len+2;
}

size_t zero_pack_raw_len(zero_basic_t *zero_basic) {
    size_t raw_len = zero_basic->len;
    if (raw_len <= 15) {
        return raw_len+1;

    } else {
        size_t raw_len_len = 0;
        for (int i = raw_len; i; i/=0x100) {
            raw_len_len += 1;
        }
        return raw_len_len+raw_len+1;
    }
}

size_t zero_pack_int_len(zero_basic_t *zero_basic) {
    return zero_basic->len+1;
}

size_t zero_pack_list_len(zero_basic_t *zero_basic) {
    size_t len = 0;
    for (int i = 0; i < zero_basic->len; i++) {
        len += zero_pack_len(((zero_basic_t **)zero_basic->ptr)[i]);
    }
    return len+1;
}

size_t zero_pack_len(zero_basic_t *zero_basic) {
    uint8_t zero_basic_types;
    int result;
    zero_basic_types = zero_basic->type;

    switch(zero_basic_types) {
        case 1:
            result = zero_pack_bool_len(zero_basic);
            return result;
        case 2:
            result = zero_pack_string_len(zero_basic);
            return result;
        case 3:
            result = zero_pack_raw_len(zero_basic);
            return result;
        case 4:
            result = zero_pack_int_len(zero_basic);
            return result;
        case 5:
            result = zero_pack_list_len(zero_basic);
            return result;
        default:
            return RET_FAILED;
            break;
    }
}

int zero_pack(zero_basic_t *zero_basic, uint8_t *in, uint8_t **out_p) {
    uint8_t zero_basic_types;
    int result;
    zero_basic_types = zero_basic->type;

    switch(zero_basic_types) {
        case 1:
            result = zero_pack_bool(zero_basic, in, out_p);
            return result;
        case 2:
            result = zero_pack_string(zero_basic, in, out_p);
            return result;
        case 3:
            result = zero_pack_raw(zero_basic, in, out_p);
            return result;
        case 4:
            result = zero_pack_int(zero_basic, in, out_p);
            return result;
        case 5:
            result = zero_pack_list(zero_basic, in, out_p);
            return result;
        default:
            return RET_FAILED;
            break;
    }
}

void zero_basic_bool_free(zero_basic_t *zero_basic) {
    free(zero_basic->ptr);
    free(zero_basic);
}

void zero_basic_string_free(zero_basic_t *zero_basic) {
    free(zero_basic->ptr);
    free(zero_basic);
}

void zero_basic_raw_free(zero_basic_t *zero_basic) {
    free(zero_basic->ptr);
    free(zero_basic);
}

void zero_basic_int_free(zero_basic_t *zero_basic) {
    free(zero_basic->ptr);
    free(zero_basic);
}

void zero_basic_list_free(zero_basic_t *zero_basic) {
    size_t len = 0;
    for (int i = 0; i < zero_basic->len; i++) {
        zero_basic_free(((zero_basic_t **)zero_basic->ptr)[i]);
    }
    free(zero_basic->ptr);
    free(zero_basic);
}

void zero_basic_free(zero_basic_t *zero_basic) {
    uint8_t zero_basic_types;
    int result;
    zero_basic_types = zero_basic->type;

    switch(zero_basic_types) {
        case 1:
            zero_basic_bool_free(zero_basic);
            break;
        case 2:
            zero_basic_string_free(zero_basic);
            break;
        case 3:
            zero_basic_raw_free(zero_basic);
            break;
        case 4:
            zero_basic_int_free(zero_basic);
            break;
        case 5:
            zero_basic_list_free(zero_basic);
            break;
        default:
            break;
    }
}

void zero_bool_new(zero_basic_t **zero_basic_p, uint8_t val) {
    zero_basic_t *zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
    CHECK_MALLOC(zero_basic, NULL);
    memset(zero_basic, 0, sizeof(zero_basic_t));
    zero_basic->type = 1;
    zero_basic->len = 1;
    zero_basic->ptr = malloc(1);
    CHECK_MALLOC(zero_basic->ptr, NULL);
    *(uint8_t *)(zero_basic->ptr) = val;
    *zero_basic_p = zero_basic;
}

void zero_string_new(zero_basic_t **zero_basic_p, char *str) {
    zero_basic_t *zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
    CHECK_MALLOC(zero_basic, NULL);
    memset(zero_basic, 0, sizeof(zero_basic_t));
    zero_basic->type = 2;
    zero_basic->len = strlen(str)+1;
    zero_basic->ptr = malloc(zero_basic->len);
    CHECK_MALLOC(zero_basic->ptr, NULL);
    strcpy(zero_basic->ptr, str);
    *zero_basic_p = zero_basic;
}

void zero_raw_new(zero_basic_t **zero_basic_p, uint8_t *raw, size_t len) {
    zero_basic_t *zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
    CHECK_MALLOC(zero_basic, NULL);
    memset(zero_basic, 0, sizeof(zero_basic_t));
    zero_basic->type = 3;
    zero_basic->len = len;
    zero_basic->ptr = malloc(len);
    CHECK_MALLOC(zero_basic->ptr, NULL);
    memcpy(zero_basic->ptr, raw, len);
    *zero_basic_p = zero_basic;
}

void zero_int_new(zero_basic_t **zero_basic_p, uint64_t val, uint8_t endian) {
    uint8_t len = 0;
    uint64_t val_tmp = val;

    if (val == 0) {
        len = 1;
    } else {
        for (int i = val_tmp; val_tmp; val_tmp/=0x100) {
            len++;
        }
    }

    zero_basic_t *zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
    CHECK_MALLOC(zero_basic, NULL);
    memset(zero_basic, 0, sizeof(zero_basic_t));
    zero_basic->type = 4;
    zero_basic->len = len;
    zero_basic->ptr = malloc(9);
    CHECK_MALLOC(zero_basic->ptr, NULL);
    memset(zero_basic->ptr, '\0', 9);
    *((char *)zero_basic->ptr) = endian;
    *((uint64_t *)(((char *)zero_basic->ptr)+1)) = val;
    *zero_basic_p = zero_basic;
}

void zero_list_new(zero_basic_t **zero_basic_p, zero_basic_t **list) {
    zero_basic_t *tmp;
    size_t len = 0;

    PTRARRAY_LEN(list, len);

    //while (list[len]) {
    //    len++;
    //}

    //printf("%ld\n", len);

    zero_basic_t *zero_basic = (zero_basic_t *)malloc(sizeof(zero_basic_t));
    CHECK_MALLOC(zero_basic, NULL);
    memset(zero_basic, 0, sizeof(zero_basic_t));
    zero_basic->type = 5;
    zero_basic->len = len;
    zero_basic->ptr = malloc(len*8);
    CHECK_MALLOC(zero_basic->ptr, NULL);
    memcpy(zero_basic->ptr, list, len*8);
    *zero_basic_p = zero_basic;
}

#ifdef DEBUG

static void zero_bool_test() {
    zero_basic_t *tmp;
    zero_basic_t *zero_basic;

    zero_bool_new(&zero_basic, 1);

    uint8_t *in = malloc(0x300);
    uint8_t *out;
    zero_pack(zero_basic, in, &out);
    LOG("%lx\n", out-in);
    zero_unpack(in, &out, &tmp);
    //zero_unpack_bool(in, &out, &tmp);
    LOG("%lx\n\n", out-in);
}

static void zero_string_test() {
    zero_basic_t *tmp;
    zero_basic_t *zero_basic;

    zero_string_new(&zero_basic, "ABCDABCDABCDABCD");

    uint8_t *in = malloc(0x300);
    uint8_t *out;
    zero_pack(zero_basic, in, &out);
    LOG("%lx\n", out-in);
    zero_unpack(in, &out, &tmp);
    //zero_unpack_string(in, &out, &tmp);
    LOG("%lx\n\n", out-in);
}

static void zero_short_raw_test() {
    zero_basic_t *tmp;
    zero_basic_t *zero_basic;

    zero_raw_new(&zero_basic, "rrrrrrrrrrrrrrr", 0xf);

    uint8_t *in = malloc(0x300);
    uint8_t *out;
    zero_pack(zero_basic, in, &out);
    LOG("%lx\n", out-in);
    zero_unpack(in, &out, &tmp);
    //zero_unpack_raw(in, &out, &tmp);
    LOG("%lx\n\n", out-in);
}

static void zero_long_raw_test() {
    zero_basic_t *tmp;
    zero_basic_t *zero_basic;

    uint8_t buf[0x100];
    memset(buf, 'a', 0x100);

    zero_raw_new(&zero_basic, buf, 0x100);

    uint8_t *in = malloc(0x300);
    uint8_t *out;
    zero_pack(zero_basic, in, &out);
    LOG("%lx\n", out-in);
    zero_unpack(in, &out, &tmp);
    //zero_unpack_raw(in, &out, &tmp);
    LOG("%lx\n\n", out-in);

}

static void zero_int_little_test() {
    zero_basic_t *tmp;
    zero_basic_t *zero_basic;

    zero_int_new(&zero_basic, 0x4142434445464748, 0x0);

    uint8_t *in = malloc(0x300);
    uint8_t *out;
    zero_pack(zero_basic, in, &out);
    LOG("%lx\n", out-in);
    zero_unpack(in, &out, &tmp);
    //zero_unpack_int(in, &out, &tmp);
    LOG("%lx\n\n", out-in);
}

static void zero_int_big_test() {
    zero_basic_t *tmp;
    zero_basic_t *zero_basic;

    zero_int_new(&zero_basic, 0x4142434445464748, 0x1);

    uint8_t *in = malloc(0x300);
    uint8_t *out;
    zero_pack(zero_basic, in, &out);
    LOG("%lx\n", out-in);
    zero_unpack(in, &out, &tmp);
    //zero_unpack_int(in, &out, &tmp);
    LOG("%lx\n\n", out-in);
}

static void zero_list_test() {
    zero_basic_t *tmp = 0;

    zero_basic_t *zero_basic1;
    zero_raw_new(&zero_basic1, "rrrrrrrrrrrrrrr", 0xf);
    zero_basic_t *zero_basic2;
    zero_int_new(&zero_basic2, 0x4142434445464748, 0x1);

    zero_basic_t *zero_basic;
    zero_basic_t *zero_basic_list[3];
    zero_basic_list[0] = zero_basic1;
    zero_basic_list[1] = zero_basic2;
    zero_basic_list[2] = NULL;
    zero_list_new(&zero_basic, zero_basic_list);

    zero_basic_t *zero_basic3;
    zero_raw_new(&zero_basic3, "AAAAAAAAAAAAAAA", 0xf);
    zero_basic_t *zero_basic4;
    zero_int_new(&zero_basic4, 0x4242434445464748, 0x1);

    zero_basic_t *zero_basic5;
    zero_basic_t *zero_basic_list2[4];
    zero_basic_list2[0] = zero_basic3;
    zero_basic_list2[1] = zero_basic4;
    zero_basic_list2[2] = zero_basic;
    zero_basic_list2[3] = NULL;
    zero_list_new(&zero_basic5, zero_basic_list2);


    uint8_t *in = malloc(0x100);
    uint8_t *out;
    zero_pack(zero_basic5, in, &out);
    LOG("%lx\n", out-in);
    zero_unpack(in, &out, &tmp);
    LOG("%lx\n\n", out-in);
}

void test_zero_pack() {
    //g_buf_len = 0x1000;
    //g_buf = malloc(g_buf_len);

    zero_bool_test();
    zero_string_test();
    zero_short_raw_test();
    zero_long_raw_test();
    zero_int_little_test();
    zero_int_big_test();
    zero_list_test();
}

void zero_basic_dump(zero_basic_t *target, size_t size) {
    printf("type : %d\n", target->type);
    printf("len  : %d\n", target->len);
    zero_hexdump(target->ptr, size);
}

#endif
