/*************************************************************************
	> File Name: zerofs.h
	> Author:
	> Mail:
	> Created Time: Thu May  3 16:44:48 2018
 ************************************************************************/

#ifndef _ZEROFS_H
#define _ZEROFS_H

#include <time.h>
#include <unistd.h>

#define INODES_NUM 0x100
#define BLOCKS_NUM 0x100
#define BLOCK_SIZE 0x1000
#define FD_MAX 0x10


/*
 * Enumerations
 */

typedef enum {
    DIRECTORY,
    NORMAL_FILE,
} file_t;

typedef enum {
    PWRITE = 0x1,
    PREAD = 0x2,
    PEXECUTE = 0x4,
} perm_t;

typedef enum {
    FNAME,
    FTYPE,
    FPERM,
    FSIZE,
    FCTIME,
    FMTIME,
    FLINK,
} elem_t;

/*
 * Unions
 */

typedef union {
    char *ptr;
    long int num;
} value_t;

/*
 * Structures
 */

typedef struct inode_t {
    union inodeInfo {
        struct inode_t *next;
        long int blockId;
    } info;
    long int size;
    long int inumber;
    long int linkNr;
} inode_t;

typedef struct {
    char data[BLOCK_SIZE];
    long int nextId;
} block_t;


typedef struct {
    long int bitmap[BLOCKS_NUM / 0x40];
    inode_t inodes[INODES_NUM];
    inode_t *freeList;
    block_t blocks[BLOCKS_NUM];
} zerofs_disk;

typedef struct fnode_t {
    union {
        struct fnode_t *child;
        long int inumber;
    } info;
    perm_t perm;
    file_t type;
    time_t createTime;
    time_t modifyTime;
    long int userId;
    struct fnode_t *parent;
    struct fnode_t *brother;
    char *name;
} fnode_t;

typedef struct IOFile {
    long int cur;
    fnode_t *fnode;
    int flags;
} IOFile;

typedef struct {
    long int userId;
    char *username;
    zerofs_disk *disk;
    fnode_t *root;
    fnode_t *pwd;
    IOFile *io_files[FD_MAX];
} zerofs_state;


/*
 * Functions
 */

ssize_t zerofs_initfs(const char *username); // DONE
ssize_t zerofs_read(int fd, void *buf, size_t count); // DONE
ssize_t zerofs_write(int fd, const void *buf, size_t count);
int zerofs_open(const char *pathname, int flags); // DONE BUG
int zerofs_close(int fd); // DONE
int zerofs_unlink(const char *pathname); // DONE
int zerofs_link(const char *oldpath, const char *newpath);
int zerofs_chdir(const char *pathname); // DONE
int zerofs_rmdir(const char *pathname); // DONE BUG
int zerofs_mkdir(const char *pathname, int flags); // DONE
off_t zerofs_lseek(int fd, off_t offset, int whence); // DONE
int zerofs_truncate(const char *path, off_t length); // DONE

value_t zerofs_elemget(const char *pathname, elem_t elem); // DONE
int zerofs_elemset(const char *pathname, elem_t elem, value_t value); // DONE BUG
char **zerofs_list(const char *pathname); // DONE
char *zerofs_pwd(void);

#endif

