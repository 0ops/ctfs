#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include "zero_pack.h"
#include "zero_proto.h"
#include "md5.h"
#include "string.h"
#include "zero_utils.h"
#include "crc32.h"
#include "zerofs.h"
#include <signal.h>

#ifdef DEBUG
#define LOG(...) printf(__VA_ARGS__)
#else
#define LOG(...)
#endif

#ifdef SERVER
#define ZERO_SEND(buf, size) zero_send(buf, size)
#define ZERO_RECV(buf, size) zero_recv(buf, size)
#else
#define ZERO_SEND(buf, size) write(1, buf, size)
#define ZERO_RECV(buf, size) read(0, buf, size)
#endif

#define CHECK_MALLOC(ptr, err) { \
	do { \
		if ((ptr) == (err)) { \
			exit(-1); \
		} \
	} while (0); \
}

static int is_regular_file(const char *path) {
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}


void zeroftp_send(uint8_t *packet, size_t data_len) {
    uint32_t crc32;
    packet[0] = ZERO_MAGIC;
    *((uint32_t *)&packet[ZERO_MAGIC_LEN]) = htonl(data_len);

    crc32 = crc32_compute(0, packet+ZERO_MAGIC_LEN+4, data_len);

    *((uint32_t *)&packet[ZERO_MAGIC_LEN+4+data_len]) = htonl(crc32);

    size_t packet_len = ZERO_MAGIC_LEN+4+data_len+4;

    ZERO_SEND(packet, packet_len);

#ifdef DEBUG
    zero_hexdump(packet, packet_len);
#endif
}

void zeroftp_result_bool(int result) {
    uint8_t *result_packet, *result_data_in, *result_data_out;
    size_t data_len, zero_pack_len_val;
    zero_basic_t *zeroftp_result;

    zero_bool_new(&zeroftp_result, result);

    zero_pack_len_val = zero_pack_len(zeroftp_result);
    result_packet = (uint8_t *)malloc(zero_pack_len_val+0x100);

    result_data_in = result_packet+5;
    zero_pack(zeroftp_result, result_data_in, &result_data_out);

    data_len = result_data_out-result_packet-5;

    zeroftp_send(result_packet, data_len);

    zero_basic_free(zeroftp_result);
    free(result_packet);

}

void zeroftp_result_int(uint64_t val) {
    uint8_t *result_packet, *result_data_in, *result_data_out;
    size_t data_len, zero_pack_len_val;
    zero_basic_t *zeroftp_result;

    zero_int_new(&zeroftp_result, val, 1);

    zero_pack_len_val = zero_pack_len(zeroftp_result);
    result_packet = (uint8_t *)malloc(zero_pack_len_val+0x100);

    result_data_in = result_packet+5;
    zero_pack(zeroftp_result, result_data_in, &result_data_out);

    data_len = result_data_out-result_packet-5;

    zeroftp_send(result_packet, data_len);

    zero_basic_free(zeroftp_result);
    free(result_packet);
}

void zeroftp_result_raw(uint8_t *raw, uint8_t raw_size) {
    uint8_t *result_packet, *result_data_in, *result_data_out;
    size_t data_len, zero_pack_len_val;
    zero_basic_t *zeroftp_result;

    zero_raw_new(&zeroftp_result, raw, raw_size);

    zero_pack_len_val = zero_pack_len(zeroftp_result);
    result_packet = (uint8_t *)malloc(zero_pack_len_val+0x100);

    result_data_in = result_packet+5;
    zero_pack(zeroftp_result, result_data_in, &result_data_out);
    data_len = result_data_out-result_packet-5;

    zeroftp_send(result_packet, data_len);

    zero_basic_free(zeroftp_result);
    free(result_packet);
}

void zeroftp_result_string(uint8_t *str) {
    uint8_t *result_packet, *result_data_in, *result_data_out;
    size_t data_len, zero_pack_len_val;
    zero_basic_t *zeroftp_result;

    zero_string_new(&zeroftp_result, str);

    zero_pack_len_val = zero_pack_len(zeroftp_result);
    result_packet = (uint8_t *)malloc(zero_pack_len_val+0x100);

    result_data_in = result_packet+5;
    zero_pack(zeroftp_result, result_data_in, &result_data_out);
    data_len = result_data_out-result_packet-5;

    zeroftp_send(result_packet, data_len);

    zero_basic_free(zeroftp_result);
    free(result_packet);
}

void zeroftp_result_list(zero_basic_t **list) {
    uint8_t *result_packet, *result_data_in, *result_data_out;
    size_t data_len, zero_pack_len_val;
    zero_basic_t *zeroftp_result;

    zero_list_new(&zeroftp_result, list);

    zero_pack_len_val = zero_pack_len(zeroftp_result);
    result_packet = (uint8_t *)malloc(zero_pack_len_val+0x100);

    result_data_in = result_packet+5;
    zero_pack(zeroftp_result, result_data_in, &result_data_out);
    data_len = result_data_out-result_packet-5;

    zeroftp_send(result_packet, data_len);

    zero_basic_free(zeroftp_result);
    free(result_packet);
}

int g_logined = 0;

void zeroftp_cmd_dispatcher(uint8_t *cmd, uint32_t cmd_len) {
    uint8_t *arg1;
    uint8_t *arg2;
    uint8_t *arg3;
    uint8_t *arg4;
    zero_basic_t *zeroftp_cmd;
    zero_basic_t *zeroftp_arg1, *zeroftp_arg2, *zeroftp_arg3;
    int unpack_res = 0;

    unpack_res = zero_unpack_int(cmd, &arg1, &zeroftp_cmd);
    if (unpack_res == -1) {
        goto LABEL_FAILED;
    }

    if (ZERO_BASIC_TYPE(zeroftp_cmd) == ZERO_INT) {
        switch(ZERO_INT_VAL(zeroftp_cmd)) {
            case ZEROFTP_LOGIN:
                // arg1 username arg2 user_password
                unpack_res = zero_unpack_string(arg1, &arg2, &zeroftp_arg1);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }
                unpack_res = zero_unpack_raw(arg2, &arg3, &zeroftp_arg2);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }

                char *username = ZERO_STRING_VAL(zeroftp_arg1);

                if (zeroftp_arg2->len != 16) {
                    zero_basic_free(zeroftp_arg1);
                    zero_basic_free(zeroftp_arg2);
                    goto LABEL_FAILED;
                }

                uint8_t *password = zeroftp_arg2->ptr;

                uint8_t username_md5[16];
                md5((uint8_t*)username, strlen(username), username_md5);

                if(memcmp(password, username_md5, 16)) {
                    LOG("login failed\n");
                    //zeroftp_result_bool(0);
                    //return;
                    zero_basic_free(zeroftp_arg1);
                    zero_basic_free(zeroftp_arg2);
                    goto LABEL_FAILED;
                } else {
#ifndef ZEROFS
                    LOG("login success\n");
#else
                    zerofs_initfs(username);
#endif
                    g_logined = 1;
                    zeroftp_result_bool(1);
                }
                zero_basic_free(zeroftp_arg1);
                zero_basic_free(zeroftp_arg2);
                break;
            case ZEROFTP_LS:
                if (!g_logined) {
                    //zeroftp_result_bool(0);
                    //return;
                    goto LABEL_FAILED;
                }
                // arg1 pathname
                unpack_res = zero_unpack_string(arg1, &arg2, &zeroftp_arg1);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }
                char *ls_pathname = ZERO_STRING_VAL(zeroftp_arg1);
#ifndef ZEROFS
                char *ls_list[3] = {"AAAA", "BBBB", NULL};
                //char *ls_list[3] = {NULL};
#else
                char **ls_list = NULL;
                ls_list = zerofs_list(ls_pathname);
#endif

                size_t zero_string_list_len = 0;
                PTRARRAY_LEN(ls_list, zero_string_list_len);
                zero_basic_t **zero_string_list = (zero_basic_t **)malloc(sizeof(zero_basic_t *)*(zero_string_list_len+1));
                CHECK_MALLOC(zero_string_list, NULL);

                size_t ls_i = 0;
                zero_basic_t *zero_string_tmp;
                char *ls_tmp = ls_list[0];
                while (ls_tmp) {
                    zero_string_new(&zero_string_tmp, ls_tmp);
                    zero_string_list[ls_i] = zero_string_tmp;
                    ls_i++;
                    ls_tmp = ls_list[ls_i];
                }
                zero_string_list[ls_i] = NULL;

                zeroftp_result_list(zero_string_list);
                free(zero_string_list);
                zero_basic_free(zeroftp_arg1);
                break;
            case ZEROFTP_CD:
                if (!g_logined) {
                    goto LABEL_FAILED;
                }
                // arg1 pathname
                unpack_res = zero_unpack_string(arg1, &arg2, &zeroftp_arg1);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }
                char *cd_pathname = ZERO_STRING_VAL(zeroftp_arg1);
#ifndef ZEROFS
                int cd_result = 0;
#else
                int cd_result = zerofs_chdir(cd_pathname);
#endif

                if (cd_result == 0) {
                    zeroftp_result_bool(1);
                } else {
                    goto LABEL_FAILED;
                }
                zero_basic_free(zeroftp_arg1);
                break;
            case ZEROFTP_MKDIR:
                if (!g_logined) {
                    goto LABEL_FAILED;
                }
                // arg1 pathname
                unpack_res = zero_unpack_string(arg1, &arg2, &zeroftp_arg1);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }
                char *mkdir_pathname = ZERO_STRING_VAL(zeroftp_arg1);
                size_t mkdir_pathname_len = strlen(mkdir_pathname);

                //for (int i = 0; i < mkdir_pathname_len; i++) {
                //    char victim = mkdir_pathname[i];
                //    if (!isalpha(victim) && !isdigit(victim) && victim != '_') {
                //        goto LABEL_FAILED;
                //    }
                //}

#ifndef ZEROFS
                int mkdir_result = 0;
#else
                int mkdir_result = zerofs_mkdir(mkdir_pathname, O_RDWR);
#endif

                if (mkdir_result == 0) {
                    zeroftp_result_bool(1);
                } else {
                    goto LABEL_FAILED;
                }
                zero_basic_free(zeroftp_arg1);
                break;
            case ZEROFTP_RMDIR:
                if (!g_logined) {
                    goto LABEL_FAILED;
                }
                // arg1 pathname
                unpack_res = zero_unpack_string(arg1, &arg2, &zeroftp_arg1);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }
                char *rmdir_pathname = ZERO_STRING_VAL(zeroftp_arg1);
#ifndef ZEROFS
                int rmdir_result = 0;
#else
                int rmdir_result = zerofs_rmdir(rmdir_pathname);
#endif

                if (rmdir_result == 0) {
                    zeroftp_result_bool(1);
                } else {
                    goto LABEL_FAILED;
                }
                zero_basic_free(zeroftp_arg1);
                break;
            case ZEROFTP_RDFILE:
                if (!g_logined) {
                    goto LABEL_FAILED;
                }
                // arg1 pathname
                unpack_res = zero_unpack_string(arg1, &arg2, &zeroftp_arg1);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }
                char *rd_pathname = ZERO_STRING_VAL(zeroftp_arg1);

#ifndef ZEROFS
                size_t rd_filesize = strlen(rd_pathname);
                uint8_t *rd_buf = (uint8_t *)malloc(rd_filesize+0x10);
                CHECK_MALLOC(rd_buf, NULL);

                memcpy(rd_buf, rd_pathname, rd_filesize);
#else
                int rd_fd = zerofs_open(rd_pathname, O_RDONLY);
                if (rd_fd < 0) {
                    zero_basic_free(zeroftp_arg1);
                    goto LABEL_FAILED;
                }
                size_t rd_filesize = zerofs_lseek(rd_fd, 0, SEEK_END);
                if (rd_filesize == -1) {
                    zero_basic_free(zeroftp_arg1);
                    goto LABEL_FAILED;
                }
                rd_filesize = MIN(rd_filesize, 0x800);

                zerofs_lseek(rd_fd, 0, SEEK_SET);
                uint8_t *rd_buf = (uint8_t *)malloc(rd_filesize+0x10);
                CHECK_MALLOC(rd_buf, NULL);

                int rd_result = zerofs_read(rd_fd, rd_buf, rd_filesize);
#endif

#ifdef PWN
#else
                zerofs_close(rd_fd);
#endif
                zeroftp_result_raw(rd_buf, rd_filesize);

                free(rd_buf);
                zero_basic_free(zeroftp_arg1);
                break;
            case ZEROFTP_WRFILE:
                if (!g_logined) {
                    goto LABEL_FAILED;
                }
                // arg1 pathname
                // arg2 file_content
                unpack_res = zero_unpack_string(arg1, &arg2, &zeroftp_arg1);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }
                unpack_res = zero_unpack_raw(arg2, &arg3, &zeroftp_arg2);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }

                char *wr_pathname = ZERO_STRING_VAL(zeroftp_arg1);
                char *wr_file_content = zeroftp_arg2->ptr;
                size_t wr_file_content_size = zeroftp_arg2->len;

                //for (int i = 0; i < strlen(wr_pathname); i++) {
                //    char victim = wr_pathname[i];
                //    if (!isalpha(victim) && !isdigit(victim)) {
                //        goto LABEL_FAILED;
                //    }
                //}

#ifndef ZEROFS
                size_t wr_result = wr_file_content_size;
#else
                int wr_fd = zerofs_open(wr_pathname, O_WRONLY);
                if (wr_fd < 0) {
                    zero_basic_free(zeroftp_arg1);
                    zero_basic_free(zeroftp_arg2);
                    goto LABEL_FAILED;
                }
                size_t wr_result;
                wr_result = zerofs_write(wr_fd, wr_file_content, wr_file_content_size);

#endif

                zerofs_close(wr_fd);
                zeroftp_result_int(wr_result);
                zero_basic_free(zeroftp_arg1);
                zero_basic_free(zeroftp_arg2);
                break;
            case ZEROFTP_RMFILE:
                if (!g_logined) {
                    goto LABEL_FAILED;
                }
                // arg1 pathname
                unpack_res = zero_unpack_string(arg1, &arg2, &zeroftp_arg1);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }
                char *rmfile_pathname = ZERO_STRING_VAL(zeroftp_arg1);
#ifndef ZEROFS
                int rmfile_result = 0;
#else
                int rmfile_result = zerofs_unlink(rmfile_pathname);
#endif

                if (rmfile_result == 0) {
                    zeroftp_result_bool(1);
                } else {
                    goto LABEL_FAILED;
                }
                zero_basic_free(zeroftp_arg1);
                break;
            case ZEROFTP_FILEINFO:
                if (!g_logined) {
                    goto LABEL_FAILED;
                }
                // arg1 pathname
                // arg2 elem
                unpack_res = zero_unpack_string(arg1, &arg2, &zeroftp_arg1);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }

                char *fileinfo_pathname = ZERO_STRING_VAL(zeroftp_arg1);
                value_t fileinfo_type;
                fileinfo_type = (zerofs_elemget(fileinfo_pathname, FTYPE));

                if (fileinfo_type.num == -1) {
                    goto LABEL_FAILED;
                }
                value_t fileinfo_value_name;
                value_t fileinfo_value_type;
                value_t fileinfo_value_perm;
                value_t fileinfo_value_size;
                value_t fileinfo_value_ctime;
                value_t fileinfo_value_mtime;
                zero_basic_t **fileinfo_list;
                zero_basic_t *zero_fileinfo_tmp;

                if (fileinfo_type.num == NORMAL_FILE) {
                    unpack_res = zero_unpack_bool(arg2, &arg3, &zeroftp_arg2);
                    if (unpack_res == -1) {
                        goto LABEL_FAILED;
                    }
                    if (ZERO_BOOL_VAL(zeroftp_arg2)) {
                        unpack_res = zero_unpack_int(arg3, &arg4, &zeroftp_arg3);
                        if (unpack_res == -1) {
                            goto LABEL_FAILED;
                        }
                        uint64_t fileinfo_elem = ZERO_INT_VAL(zeroftp_arg3);
                        value_t fileinfo_value;
                        uint64_t fileinfo_num;
                        char *fileinfo_ptr;

                        switch(fileinfo_elem) {
                            case FNAME:
#ifndef ZEROFS
                                fileinfo_value.ptr = "filefilefile";
#else
                                fileinfo_value = (zerofs_elemget(fileinfo_pathname, FNAME));
                                size_t fileinfo_value_len = strlen(fileinfo_value.ptr);
                                if (fileinfo_value_len > 0x800) {
                                    fileinfo_value_len = 0x800;
                                    fileinfo_value.ptr[0x800] = 0;
                                }
#endif
                                zeroftp_result_string(fileinfo_value.ptr);
                                break;
                            case FTYPE:
                            case FPERM:
                            case FSIZE:
                            case FCTIME:
                            case FMTIME:
#ifndef ZEROFS
                                fileinfo_value.num = 0xdeadbeef;
#else
                                fileinfo_value = zerofs_elemget(fileinfo_pathname, fileinfo_elem);
#endif
                                zeroftp_result_int(fileinfo_value.num);
                                break;
                            default:
                                goto LABEL_FAILED;
                        }

                        zero_basic_free(zeroftp_arg1);
                        zero_basic_free(zeroftp_arg2);
                        zero_basic_free(zeroftp_arg3);
                    } else {
                        fileinfo_value_name  = (zerofs_elemget(fileinfo_pathname, FNAME));
                        fileinfo_value_type  = (zerofs_elemget(fileinfo_pathname, FTYPE));
                        fileinfo_value_perm  = (zerofs_elemget(fileinfo_pathname, FPERM));
                        fileinfo_value_size  = (zerofs_elemget(fileinfo_pathname, FSIZE));
                        fileinfo_value_ctime = (zerofs_elemget(fileinfo_pathname, FCTIME));
                        fileinfo_value_mtime = (zerofs_elemget(fileinfo_pathname, FMTIME));

                        fileinfo_list = (zero_basic_t **)malloc(sizeof(zero_basic_t *)*(7));
                        CHECK_MALLOC(fileinfo_list, NULL);

                        zero_string_new(&zero_string_tmp, fileinfo_value_name.ptr);
                        fileinfo_list[0] = zero_string_tmp;
                        zero_int_new(&zero_string_tmp, fileinfo_value_type.num, 1);
                        fileinfo_list[1] = zero_string_tmp;
                        zero_int_new(&zero_string_tmp, fileinfo_value_perm.num, 1);
                        fileinfo_list[2] = zero_string_tmp;
                        zero_int_new(&zero_string_tmp, fileinfo_value_size.num, 1);
                        fileinfo_list[3] = zero_string_tmp;
                        zero_int_new(&zero_string_tmp, fileinfo_value_ctime.num, 1);
                        fileinfo_list[4] = zero_string_tmp;
                        zero_int_new(&zero_string_tmp, fileinfo_value_mtime.num, 1);
                        fileinfo_list[5] = zero_string_tmp;
                        fileinfo_list[6] = NULL;

                        zeroftp_result_list(fileinfo_list);

                        free(fileinfo_list);
                        zero_basic_free(zeroftp_arg1);
                        zero_basic_free(zeroftp_arg2);
                        break;

                    }
                } else {
                    char **fileinfo_file_list = NULL;
                    fileinfo_file_list = zerofs_list(fileinfo_pathname);

                    size_t fileinfo_file_list_len = 0;
                    PTRARRAY_LEN(fileinfo_file_list, fileinfo_file_list_len);
                    zero_basic_t **zero_fileinfo_file_list = (zero_basic_t **)malloc(sizeof(zero_basic_t *)*(fileinfo_file_list_len+1));
                    CHECK_MALLOC(zero_fileinfo_file_list, NULL);

                    for (int i = 0; i < fileinfo_file_list_len; i++) {
                        fileinfo_value_name  = (zerofs_elemget(fileinfo_file_list[i], FNAME));
                        fileinfo_value_type  = (zerofs_elemget(fileinfo_file_list[i], FTYPE));
                        fileinfo_value_perm  = (zerofs_elemget(fileinfo_file_list[i], FPERM));
                        fileinfo_value_size  = (zerofs_elemget(fileinfo_file_list[i], FSIZE));
                        fileinfo_value_ctime = (zerofs_elemget(fileinfo_file_list[i], FCTIME));
                        fileinfo_value_mtime = (zerofs_elemget(fileinfo_file_list[i], FMTIME));

                        fileinfo_list = (zero_basic_t **)malloc(sizeof(zero_basic_t *)*(7));
                        CHECK_MALLOC(fileinfo_list, NULL);

                        zero_string_new(&zero_string_tmp, fileinfo_value_name.ptr);
                        fileinfo_list[0] = zero_string_tmp;
                        zero_int_new(&zero_string_tmp, fileinfo_value_type.num, 1);
                        fileinfo_list[1] = zero_string_tmp;
                        zero_int_new(&zero_string_tmp, fileinfo_value_perm.num, 1);
                        fileinfo_list[2] = zero_string_tmp;
                        zero_int_new(&zero_string_tmp, fileinfo_value_size.num, 1);
                        fileinfo_list[3] = zero_string_tmp;
                        zero_int_new(&zero_string_tmp, fileinfo_value_ctime.num, 1);
                        fileinfo_list[4] = zero_string_tmp;
                        zero_int_new(&zero_string_tmp, fileinfo_value_mtime.num, 1);
                        fileinfo_list[5] = zero_string_tmp;
                        fileinfo_list[6] = NULL;

                        zero_list_new(zero_fileinfo_file_list+i, fileinfo_list);
                    }
                    zero_fileinfo_file_list[fileinfo_file_list_len] = 0;

                    zeroftp_result_list(zero_fileinfo_file_list);
                    zero_basic_free(zeroftp_arg1);
                }

                break;
            case ZEROFTP_SETFILEINFO:
                if (!g_logined) {
                    goto LABEL_FAILED;
                }
                // arg1 pathname
                // arg2 elem
                // arg3 value
                unpack_res = zero_unpack_string(arg1, &arg2, &zeroftp_arg1);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }
                unpack_res = zero_unpack_int(arg2, &arg3, &zeroftp_arg2);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }
                char *setfileinfo_pathname = ZERO_STRING_VAL(zeroftp_arg1);
                uint64_t setfileinfo_elem = ZERO_INT_VAL(zeroftp_arg2);
                value_t setfileinfo_value;


                switch(setfileinfo_elem) {
                    case FNAME:
                        unpack_res = zero_unpack_string(arg3, &arg4, &zeroftp_arg3);
                        if (unpack_res == -1) {
                            goto LABEL_FAILED;
                        }
                        setfileinfo_value.ptr = ZERO_STRING_VAL(zeroftp_arg3);
#ifndef ZEROFS
#else
                        zerofs_elemset(setfileinfo_pathname, FNAME, setfileinfo_value);
#endif
                        zeroftp_result_bool(1);
                        break;
                    //case FTYPE:
                    case FPERM:
                    //case FSIZE:
                    case FCTIME:
                    case FMTIME:
                        unpack_res = zero_unpack_int(arg3, &arg4, &zeroftp_arg3);
                        if (unpack_res == -1) {
                            goto LABEL_FAILED;
                        }
                        setfileinfo_value.num = ZERO_INT_VAL(zeroftp_arg3);
#ifndef ZEROFS
#else
                        zerofs_elemset(setfileinfo_pathname, setfileinfo_elem, setfileinfo_value);
#endif
                        zeroftp_result_bool(1);
                        break;
                    default:
                        goto LABEL_FAILED;
                }
                zero_basic_free(zeroftp_arg1);
                zero_basic_free(zeroftp_arg2);
                zero_basic_free(zeroftp_arg3);
                break;
            case ZEROFTP_BACKDOOR:
                if (!g_logined) {
                    goto LABEL_FAILED;
                }
                // arg1 backdoor_filename
                unpack_res = zero_unpack_string(arg1, &arg2, &zeroftp_arg1);
                if (unpack_res == -1) {
                    goto LABEL_FAILED;
                }
                char *backdoor_pathname = ZERO_STRING_VAL(zeroftp_arg1);
                size_t backdoor_pathname_len = strlen(backdoor_pathname);

                /* check */
                if(!is_regular_file(backdoor_pathname)) {
                    goto LABEL_FAILED;
                }
                if (!isalpha(backdoor_pathname[0]) && !isdigit(backdoor_pathname[0])) {
                    goto LABEL_FAILED;
                }
                if (backdoor_pathname_len > 1) {
                    for (int i = 1; i < backdoor_pathname_len; i++) {
                        char victim = backdoor_pathname[i];
                        if (!isalpha(victim) && !isdigit(victim) && victim != '_' && victim != '/') {
                            goto LABEL_FAILED;
                        }
                    }
                }

                int backdoor_fd = open(backdoor_pathname, O_RDONLY);


                size_t backdoor_filesize = lseek(backdoor_fd, 0, SEEK_END);
                if (backdoor_filesize == -1) {
                    goto LABEL_FAILED;
                }
                backdoor_filesize = MIN(backdoor_filesize, 0x800);
                lseek(backdoor_fd, 0, SEEK_SET);

                uint8_t *backdoor_filecontent = (uint8_t *)malloc(backdoor_filesize+0x10);
                CHECK_MALLOC(backdoor_filecontent, NULL);
                read(backdoor_fd, backdoor_filecontent, backdoor_filesize);

                /* write to vfs */
                int backdoor_vfs_fd = zerofs_open(backdoor_pathname, O_WRONLY);
                if (backdoor_vfs_fd < 0) {
                    goto LABEL_FAILED;
                }
                zerofs_write(backdoor_vfs_fd, backdoor_filecontent, backdoor_filesize);
                zerofs_close(backdoor_vfs_fd);

                zeroftp_result_bool(1);
                free(backdoor_filecontent);
                zero_basic_free(zeroftp_arg1);
                //zeroftp_result_raw(backdoor_filecontent, backdoor_filesize);
                break;
            case ZEROFTP_QUIT:
                exit(-1);
                break;
            default:
LABEL_FAILED:
                zeroftp_result_bool(0);
                zero_basic_free(zeroftp_cmd);
                //exit(-1);
                return;
        }
    } else {
        exit(-1);
    }
    zero_basic_free(zeroftp_cmd);


}

#ifdef TEST_ZEROFTP_SAMPLE
void zeroftp_main(uint8_t *packet) {
    uint32_t data_len;
    uint32_t data_crc32;
    uint32_t crc32;
    uint8_t *data;

    if(packet[0] != ZERO_MAGIC) {
        exit(-1);
    }

    data_len = ntohl(*((uint32_t *)&packet[ZERO_MAGIC_LEN]));

        data = &packet[ZERO_MAGIC_LEN+4];

    data_crc32 = ntohl(*((uint32_t *)&packet[ZERO_MAGIC_LEN+4+data_len]));

    crc32 = crc32_compute(0, packet+ZERO_MAGIC_LEN+4, data_len);

    if (crc32 != data_crc32) {
        zeroftp_result_bool(0);
        exit(-1);
    }

    zeroftp_cmd_dispatcher(data, data_len);
}
#else
void zeroftp_main() {
    uint32_t data_len;
    uint32_t data_crc32;
    uint32_t crc32;
    uint8_t *data;
    uint8_t magic;
    uint32_t rd;

    rd = ZERO_RECV(&magic, 1);
    if (magic != ZERO_MAGIC) {
        zeroftp_result_bool(0);
        exit(-1);
    }

    ZERO_RECV(&data_len, 4);
    data_len = ntohl(data_len);

    if (data_len >= 0x8000) {
        exit(-1);
    }

    data = (uint8_t *)malloc(data_len+0x10);
    memset(data, '0', data_len+0x8);
    CHECK_MALLOC(data, NULL);

    ZERO_RECV(data, data_len);

    ZERO_RECV(&data_crc32, 4);
    data_crc32 = ntohl(data_crc32);

    crc32 = crc32_compute(0, data, data_len);

    if (crc32 != data_crc32) {
        zeroftp_result_bool(0);
        exit(-1);
    }

    zeroftp_cmd_dispatcher(data, data_len);

    free(data);
}

void zeroftp_loop() {
    while (1) {
        zeroftp_main();
    }
}

#endif




#ifdef TEST_ZEROFTP_SAMPLE
uint8_t *zeroftp_build_sample_login() {
    zero_basic_t *zero_cmd;
    zero_basic_t *zero_username;
    zero_basic_t *zero_password;
    zero_int_new(&zero_cmd, ZEROFTP_LOGIN, 1);
    zero_string_new(&zero_username, "admin");
    zero_raw_new(&zero_password, "\x21\x23\x2f\x29\x7a\x57\xa5\xa7\x43\x89\x4a\x0e\x4a\x80\x1f\xc3", 0x10);

    uint8_t *buf = malloc(0x1000);
    memset(buf, '\x0', 0x1000);
    uint8_t *buf_tmp1, *buf_tmp2;
    buf_tmp1 = buf+5;
    zero_pack(zero_cmd, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_username, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_password, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;

    buf[0] = '\xdd';
    size_t data_len = buf_tmp2-buf-4-ZERO_MAGIC_LEN;
    *((uint32_t *)&buf[ZERO_MAGIC_LEN]) = htonl(data_len);

    uint32_t crc32;
    crc32 = crc32_compute(0, buf+ZERO_MAGIC_LEN+4, data_len);
    *((uint32_t *)&buf[ZERO_MAGIC_LEN+4+data_len]) = htonl(crc32);

    //write(1, buf, buf_tmp2+4-buf);

    return buf;
}

uint8_t *zeroftp_build_sample_ls(char *pathname) {
    zero_basic_t *zero_cmd;
    zero_basic_t *zero_pathname;
    zero_int_new(&zero_cmd, ZEROFTP_LS, 1);
    zero_string_new(&zero_pathname, pathname);

    uint8_t *buf = malloc(0x1000);
    memset(buf, '\x0', 0x1000);
    uint8_t *buf_tmp1, *buf_tmp2;
    buf_tmp1 = buf+5;
    zero_pack(zero_cmd, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_pathname, buf_tmp1, &buf_tmp2);

    buf[0] = '\xdd';
    size_t data_len = buf_tmp2-buf-4-ZERO_MAGIC_LEN;
    *((uint32_t *)&buf[ZERO_MAGIC_LEN]) = htonl(data_len);

    uint32_t crc32;
    crc32 = crc32_compute(0, buf+ZERO_MAGIC_LEN+4, data_len);
    *((uint32_t *)&buf[ZERO_MAGIC_LEN+4+data_len]) = htonl(crc32);

    //write(1, buf, buf_tmp2+4-buf);

    return buf;
}

uint8_t *zeroftp_build_sample_rdfile(char *pathname) {
    zero_basic_t *zero_cmd;
    zero_basic_t *zero_pathname;
    zero_int_new(&zero_cmd, ZEROFTP_RDFILE, 1);
    zero_string_new(&zero_pathname, pathname);

    uint8_t *buf = malloc(0x1000);
    memset(buf, '\x0', 0x1000);
    uint8_t *buf_tmp1, *buf_tmp2;
    buf_tmp1 = buf+5;
    zero_pack(zero_cmd, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_pathname, buf_tmp1, &buf_tmp2);

    buf[0] = '\xdd';
    size_t data_len = buf_tmp2-buf-4-ZERO_MAGIC_LEN;
    *((uint32_t *)&buf[ZERO_MAGIC_LEN]) = htonl(data_len);

    uint32_t crc32;
    crc32 = crc32_compute(0, buf+ZERO_MAGIC_LEN+4, data_len);
    *((uint32_t *)&buf[ZERO_MAGIC_LEN+4+data_len]) = htonl(crc32);

    //write(1, buf, buf_tmp2+4-buf);

    return buf;
}

uint8_t *zeroftp_build_sample_wrfile(char *pathname, char *file_content, size_t len) {
    zero_basic_t *zero_cmd;
    zero_basic_t *zero_pathname;
    zero_basic_t *zero_filecontent;
    zero_int_new(&zero_cmd, ZEROFTP_WRFILE, 1);
    zero_string_new(&zero_pathname, pathname);
    zero_raw_new(&zero_filecontent, file_content, len);

    uint8_t *buf = malloc(0x1000);
    memset(buf, '\x0', 0x1000);
    uint8_t *buf_tmp1, *buf_tmp2;
    buf_tmp1 = buf+5;
    zero_pack(zero_cmd, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_pathname, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_filecontent, buf_tmp1, &buf_tmp2);

    buf[0] = '\xdd';
    size_t data_len = buf_tmp2-buf-4-ZERO_MAGIC_LEN;
    *((uint32_t *)&buf[ZERO_MAGIC_LEN]) = htonl(data_len);

    uint32_t crc32;
    crc32 = crc32_compute(0, buf+ZERO_MAGIC_LEN+4, data_len);
    *((uint32_t *)&buf[ZERO_MAGIC_LEN+4+data_len]) = htonl(crc32);

    //zero_hexdump(buf, buf_tmp2+4-buf);
    //write(1, buf, buf_tmp2+4-buf);

    return buf;
}

uint8_t *zeroftp_build_sample_fileinfo1(char *pathname) {
    zero_basic_t *zero_cmd;
    zero_basic_t *zero_pathname;
    zero_basic_t *zero_elem_enable;
    zero_basic_t *zero_elem;
    zero_int_new(&zero_cmd, ZEROFTP_FILEINFO, 1);
    zero_string_new(&zero_pathname, pathname);
    zero_bool_new(&zero_elem_enable, 1);
    zero_int_new(&zero_elem, FNAME, 1);

    uint8_t *buf = malloc(0x1000);
    memset(buf, '\x0', 0x1000);
    uint8_t *buf_tmp1, *buf_tmp2;
    buf_tmp1 = buf+5;
    zero_pack(zero_cmd, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_pathname, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_elem_enable, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_elem, buf_tmp1, &buf_tmp2);

    buf[0] = '\xdd';
    size_t data_len = buf_tmp2-buf-4-ZERO_MAGIC_LEN;
    *((uint32_t *)&buf[ZERO_MAGIC_LEN]) = htonl(data_len);

    uint32_t crc32;
    crc32 = crc32_compute(0, buf+ZERO_MAGIC_LEN+4, data_len);
    *((uint32_t *)&buf[ZERO_MAGIC_LEN+4+data_len]) = htonl(crc32);

    //write(1, buf, buf_tmp2+4-buf);

    return buf;
}

uint8_t *zeroftp_build_sample_fileinfo2(char *pathname) {
    zero_basic_t *zero_cmd;
    zero_basic_t *zero_pathname;
    zero_basic_t *zero_elem_enable;
    zero_basic_t *zero_elem;
    zero_int_new(&zero_cmd, ZEROFTP_FILEINFO, 1);
    zero_string_new(&zero_pathname, pathname);
    zero_bool_new(&zero_elem_enable, 0);
    zero_int_new(&zero_elem, FNAME, 1);

    uint8_t *buf = malloc(0x1000);
    memset(buf, '\x0', 0x1000);
    uint8_t *buf_tmp1, *buf_tmp2;
    buf_tmp1 = buf+5;
    zero_pack(zero_cmd, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_pathname, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_elem_enable, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_elem, buf_tmp1, &buf_tmp2);

    buf[0] = '\xdd';
    size_t data_len = buf_tmp2-buf-4-ZERO_MAGIC_LEN;
    *((uint32_t *)&buf[ZERO_MAGIC_LEN]) = htonl(data_len);

    uint32_t crc32;
    crc32 = crc32_compute(0, buf+ZERO_MAGIC_LEN+4, data_len);
    *((uint32_t *)&buf[ZERO_MAGIC_LEN+4+data_len]) = htonl(crc32);

    //write(1, buf, buf_tmp2+4-buf);

    return buf;
}

uint8_t *zeroftp_build_sample_fileinfo3(char *pathname) {
    zero_basic_t *zero_cmd;
    zero_basic_t *zero_pathname;
    zero_basic_t *zero_elem_enable;
    zero_basic_t *zero_elem;
    zero_int_new(&zero_cmd, ZEROFTP_FILEINFO, 1);
    zero_string_new(&zero_pathname, pathname);
    zero_bool_new(&zero_elem_enable, 1);
    zero_int_new(&zero_elem, FNAME, 1);

    uint8_t *buf = malloc(0x1000);
    memset(buf, '\x0', 0x1000);
    uint8_t *buf_tmp1, *buf_tmp2;
    buf_tmp1 = buf+5;
    zero_pack(zero_cmd, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_pathname, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_elem_enable, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_elem, buf_tmp1, &buf_tmp2);

    buf[0] = '\xdd';
    size_t data_len = buf_tmp2-buf-4-ZERO_MAGIC_LEN;
    *((uint32_t *)&buf[ZERO_MAGIC_LEN]) = htonl(data_len);

    uint32_t crc32;
    crc32 = crc32_compute(0, buf+ZERO_MAGIC_LEN+4, data_len);
    *((uint32_t *)&buf[ZERO_MAGIC_LEN+4+data_len]) = htonl(crc32);

    //write(1, buf, buf_tmp2+4-buf);

    return buf;
}
uint8_t *zeroftp_build_sample_setfileinfo() {
    zero_basic_t *zero_cmd;
    zero_basic_t *zero_pathname;
    zero_basic_t *zero_elem;
    zero_basic_t *zero_value_ptr;
    zero_basic_t *zero_value_num;
    zero_int_new(&zero_cmd, ZEROFTP_SETFILEINFO, 1);
    zero_string_new(&zero_pathname, "./flag");
    zero_int_new(&zero_elem, FNAME, 1);
    zero_string_new(&zero_value_ptr, "flag2");

    uint8_t *buf = malloc(0x1000);
    memset(buf, '\x0', 0x1000);
    uint8_t *buf_tmp1, *buf_tmp2;
    buf_tmp1 = buf+5;
    zero_pack(zero_cmd, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_pathname, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_elem, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_value_ptr, buf_tmp1, &buf_tmp2);

    buf[0] = '\xdd';
    size_t data_len = buf_tmp2-buf-4-ZERO_MAGIC_LEN;
    *((uint32_t *)&buf[ZERO_MAGIC_LEN]) = htonl(data_len);

    uint32_t crc32;
    crc32 = crc32_compute(0, buf+ZERO_MAGIC_LEN+4, data_len);
    *((uint32_t *)&buf[ZERO_MAGIC_LEN+4+data_len]) = htonl(crc32);

    //write(1, buf, buf_tmp2+4-buf);

    return buf;
}

uint8_t *zeroftp_build_sample_backdoor() {
    zero_basic_t *zero_cmd;
    zero_basic_t *zero_pathname;
    zero_int_new(&zero_cmd, ZEROFTP_BACKDOOR, 1);
    zero_string_new(&zero_pathname, "flag");

    uint8_t *buf = malloc(0x1000);
    memset(buf, '\x0', 0x1000);
    uint8_t *buf_tmp1, *buf_tmp2;
    buf_tmp1 = buf+5;
    zero_pack(zero_cmd, buf_tmp1, &buf_tmp2);
    buf_tmp1 = buf_tmp2;
    zero_pack(zero_pathname, buf_tmp1, &buf_tmp2);

    buf[0] = '\xdd';
    size_t data_len = buf_tmp2-buf-4-ZERO_MAGIC_LEN;
    *((uint32_t *)&buf[ZERO_MAGIC_LEN]) = htonl(data_len);

    uint32_t crc32;
    crc32 = crc32_compute(0, buf+ZERO_MAGIC_LEN+4, data_len);
    *((uint32_t *)&buf[ZERO_MAGIC_LEN+4+data_len]) = htonl(crc32);

    //write(1, buf, buf_tmp2+4-buf);

    return buf;
}


void zeroftp_test() {
    LOG("[*] LOGIN TEST\n");
    char *buf = zeroftp_build_sample_login();
    zeroftp_main(buf);

    LOG("[*] WRITE FILE TEST\n");
    buf = zeroftp_build_sample_wrfile("flag1", "AAAAAAAA", 8);
    zeroftp_main(buf);

    buf = zeroftp_build_sample_wrfile("flag2", "BBBBBBBB", 8);
    zeroftp_main(buf);

    LOG("[*] LS TEST\n");
    buf = zeroftp_build_sample_ls("/");
    zeroftp_main(buf);

    LOG("[*] READ FILE TEST\n");
    buf = zeroftp_build_sample_rdfile("/flag1");
    zeroftp_main(buf);

    LOG("[*] FILEINFO TEST 1\n");
    buf = zeroftp_build_sample_fileinfo1("./flag");
    zeroftp_main(buf);

    LOG("[*] FILEINFO TEST 2\n");
    buf = zeroftp_build_sample_fileinfo2("./flag");
    zeroftp_main(buf);

    LOG("[*] FILEINFO TEST 3\n");
    buf = zeroftp_build_sample_fileinfo3(".");
    zeroftp_main(buf);

    //LOG("[*] SETFILEINFO TEST\n");
    //buf = zeroftp_build_sample_setfileinfo();
    //zeroftp_main(buf);

    //LOG("[*] FILEINFO TEST\n");
    //buf = zeroftp_build_sample_fileinfo("./flag2");
    //zeroftp_main(buf);

    //LOG("[*] BACKDOOR TEST\n");
    //buf = zeroftp_build_sample_backdoor();
    //zeroftp_main(buf);

}
#endif

void sigalrm_fn(int sig)
{
        printf("%s", "\n[!] bye!");
        exit(-1);
}

void initial() {
        signal(SIGALRM, sigalrm_fn);
        //alarm(0x10000);
        alarm(0x3c);

        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
}

int main(int argc, char const* argv[])
{

#ifdef SERVER
    init_dh();
    init_rc4();
#endif
    //zeroftp_main("AAAA");
#ifdef TEST_ZEROFTP_SAMPLE
    zeroftp_test();
#else
    initial();
    zeroftp_loop();
#endif

    return 0;
}
