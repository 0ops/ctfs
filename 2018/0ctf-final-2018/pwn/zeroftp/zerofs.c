/*************************************************************************
	> File Name: zerofs.c
	> Author:
	> Mail:
	> Created Time: Thu May  3 17:27:52 2018
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zerofs.h"

/*
 * MACRO
 */

#ifdef DEBUG

#define LOG(format, args...) { \
	do { \
		dprintf(2, format"\n", ##args); \
	} while (0); \
}

#define DEBUG_CHECK(code) { \
	do { \
		code \
	} while(0); \
}

#else

#define LOG(format, args...) {}

#define DEBUG_CHECK(code) {}

#endif

#define INSERT_FNODE(fnode, dnode) { \
	do { \
		((fnode)->brother) = ((dnode)->info.child); \
		((fnode)->parent) = (dnode); \
		((dnode)->info.child) = fnode; \
   	} while (0); \
}

#define CHECK_MALLOC(ptr, err) { \
	do { \
		if ((ptr) == (err)) { \
			exit(-1); \
		} \
	} while (0); \
}


zerofs_state *state;

/*
 * Static Functions
 */

static int _create_block(void) {
	long int i, j;
	long int one = 1;
	for (i = 0; i < (BLOCKS_NUM / 0x40); i++) {
		if (state->disk->bitmap[i] == (long int) -1) {
			continue;
		}
		for (j = 0; j < 0x40; j++) {
			if (!((one << j) & state->disk->bitmap[i])) {
				LOG("[_create_block] find empty block");
				state->disk->bitmap[i] |= (one << j);
				return (i * 0x40 + j);
			}
		}
	}
	LOG("[_create_block] no enough block");
	exit(-1);
}

static int _free_block(int blockId) {
	long int i = blockId / 0x40;
	long int j = blockId % 0x40;
	long int one = 1;
	if (!(state->disk->bitmap[i] & (one << j))) {
		LOG("[_free_block] blockId (%d) not inuse", blockId);
		return -1;
	}
	state->disk->bitmap[i] ^= (one << j);
	state->disk->blocks[blockId].nextId = -1;
	LOG("[_free_block] blockId (%d) freed", blockId);
	return 0;
}

static long int _memory_truncate(long int blockId, off_t length, long int size) {
	long int blockId_;
	long int size_;
	if (!length) {
		if (blockId == -1) {
			return -1;
		}
		blockId_ = state->disk->blocks[blockId].nextId;
		_free_block(blockId);
		return _memory_truncate(blockId_, length, size - BLOCK_SIZE);
	}
	if (blockId == -1) {
		blockId = _create_block();
	}
	if (length <= BLOCK_SIZE) {
		if (length <= size) {
			blockId_ = state->disk->blocks[blockId].nextId;
			state->disk->blocks[blockId].nextId = _memory_truncate(blockId_, 0, size - BLOCK_SIZE);
			return blockId;
		} else {
			memset(&(state->disk->blocks[blockId].data[size]), 0, length - size);
			return blockId;
		}
	} else {
		if (size < 0) {
			size_ = 0;
		} else {
			size_ = size;
		}
		if (size < BLOCK_SIZE) {
			memset(&(state->disk->blocks[blockId].data[size_]), 0, BLOCK_SIZE - size_);
		}
		blockId_ = state->disk->blocks[blockId].nextId;
		state->disk->blocks[blockId].nextId = _memory_truncate(blockId_, length - BLOCK_SIZE, size - BLOCK_SIZE);
		return blockId;
	}
}

static ssize_t _memory_write(long int blockId, const void *buf, long int st, long int en) {
	long int blockId_ = state->disk->blocks[blockId].nextId;
	if (st >= BLOCK_SIZE) {
		if (blockId_ == -1) {
			blockId_ = state->disk->blocks[blockId].nextId = _create_block();
		}
		return _memory_write(blockId_, buf, st - BLOCK_SIZE, en - BLOCK_SIZE);
	}
	if (en > BLOCK_SIZE) {
		memcpy(&(state->disk->blocks[blockId].data[st]), buf, BLOCK_SIZE - st);
		buf = (char *)buf + BLOCK_SIZE - st;
		if (blockId_ == -1) {
			blockId_ = state->disk->blocks[blockId].nextId = _create_block();
		}
		return _memory_write(blockId_, buf, 0, en - BLOCK_SIZE) + BLOCK_SIZE - st;
	}
	memcpy(&(state->disk->blocks[blockId].data[st]), buf, en - st);
	return en - st;
}

static ssize_t _memory_read(long int blockId, void *buf, long int st, long int en) {
	if (blockId == -1) {
		LOG("[_memory_read] invalid blockId (%ld)", blockId);
		return -1;
	}
	long int blockId_ = state->disk->blocks[blockId].nextId;
	if (st >= BLOCK_SIZE) {
		return _memory_read(blockId_, buf, st - BLOCK_SIZE, en - BLOCK_SIZE);
	}
	if (en > BLOCK_SIZE) {
		memcpy(buf, &(state->disk->blocks[blockId].data[st]), BLOCK_SIZE - st);
		buf = (char *)buf + BLOCK_SIZE - st;
		return _memory_read(blockId_, buf, 0, en - BLOCK_SIZE) + BLOCK_SIZE - st;
	}
	memcpy(buf, &(state->disk->blocks[blockId].data[st]), en - st);
	return en - st;
}

static int _create_inode(void) {
	if (!state->disk->freeList) {
		LOG("[_create_inode] no enough inodes");
		exit(-1);
	}
	inode_t *inode = state->disk->freeList;
	state->disk->freeList = inode->info.next;
	inode->info.blockId = -1;
	inode->linkNr = 1;
	inode->size = 0;
	return inode->inumber;
}

static int _free_inode(long int inumber) {
	long int blockId = state->disk->inodes[inumber].info.blockId;
	long int res;

	inode_t *inode = &(state->disk->inodes[inumber]);
	if (inode->linkNr) {
		LOG("[_free_inode] inode is still inuse (%ld)", inumber);
		return -1;
	}

	while (blockId != -1) {
		res = blockId;
		blockId = state->disk->blocks[blockId].nextId;
		_free_block(res);
	}
	LOG("[_free_inode] blocks clear");
	inode->size = 0;

	inode->info.next = state->disk->freeList;
	state->disk->freeList = inode;
	return 0;
}

static char *_fullpath(fnode_t *fnode) {
	if (fnode->parent == fnode) {
		return strdup("/");
	}
	char *pas = _fullpath(fnode->parent);
	if (fnode->type == NORMAL_FILE) {
		char *res = malloc(strlen(pas) + strlen(fnode->name));
		strcpy(res, pas);
		strcat(res, fnode->name);
		free(pas);
		return res;
	} else {
		char *res = malloc(strlen(pas) + strlen(fnode->name) + 1);
		strcpy(res, pas);
		strcat(res, fnode->name);
		strcat(res, "/");
		free(pas);
		return res;
	}
}

static inline void _unlink_fnode(fnode_t *fnode) {
	fnode_t *dnode = fnode->parent;
	if (fnode == dnode) {
		LOG("[_unlink_fnode] try to unlink root");
		return;
	}
	if (dnode->info.child == fnode) {
		dnode->info.child = fnode->brother;
		return;
	}
	for (fnode_t *cur = dnode->info.child; cur != NULL; cur = cur->brother) {
		if (cur->brother == fnode) {
			cur->brother = fnode->brother;
			return;
		}
	}
	DEBUG_CHECK(exit(-1););
	return;
}

static char *_filename(const char *pathname) {
	const char *cur = &(pathname[strlen(pathname)-1]);
	while ((*cur != '/') && (cur != pathname - 1)) {
		cur--;
	}
	cur++;
	if (*cur == '\x00') {
		return NULL;
	} else {
		return strdup(cur);
	}
}

static fnode_t *_resolve_path(const char *pathname, int padir) {
	fnode_t *cur;
	char *tmp;
	if (pathname[0] == '/') {
		cur = state->root;
		if (pathname[1] == '\x00') {
			return cur;
		}
		tmp = strdup(pathname);
	} else {
		cur = state->pwd;
		tmp = malloc(strlen(pathname) + 3);
		CHECK_MALLOC(tmp, NULL);
		memset(tmp, 0, strlen(pathname) + 3);
		tmp[0] = '.';
		tmp[1] = '/';
		strcat(tmp + 2, pathname);
	}
	if (pathname[strlen(pathname)-1] == '/') {
		tmp[strlen(tmp)-1] = '\x00';
	}
	char c;
	if (padir) {
		do {
			c = tmp[strlen(tmp)-1];
			tmp[strlen(tmp)-1] = '\x00';
		} while (c != '/');
	}
	char *token = strtok(tmp, "/");
	while (token) {
		LOG("[_resolve_path] get token (%s)", token);
		if (strcmp(token, ".") == 0) {
			goto next;
		}
		if (strcmp(token, "..") == 0) {
			cur = cur->parent;
			goto next;
		}
		cur = cur->info.child;
		if (cur == NULL) {
			LOG("[_resolve_path] No subdir/subfile");
			free(tmp);
			return NULL;
		}
		while (strcmp(token, cur->name)) {
			cur = cur->brother;
			if (!cur) {
				LOG("[_resolve_path] No subdir/subfile with name (%s)", token);
				free(tmp);
				return NULL;
			}
		}
next:
		token = strtok(NULL, "/");
	}
	LOG("[_resolve_path] Find node (%s) for %s", cur->name, pathname);
	free(tmp);
	return cur;
}

static IOFile *_create_IOFile(fnode_t *fnode, int flags) {
	IOFile *io_file = (IOFile *) malloc(sizeof(IOFile));
	CHECK_MALLOC(io_file, NULL);

	io_file->fnode = fnode;
	io_file->cur = 0;
	io_file->flags = flags;

	return io_file;
}

static void _init_disk(zerofs_disk *disk) {
	for (int i = 0; i < (INODES_NUM - 1); i++) {
		disk->inodes[i].info.next = &(disk->inodes[i+1]);
		disk->inodes[i].inumber = i;
		disk->inodes[i].size = 0;
	}
	disk->inodes[INODES_NUM - 1].info.next = NULL;
	disk->inodes[INODES_NUM - 1].inumber = (INODES_NUM - 1);
	disk->inodes[INODES_NUM - 1].size = 0;
	disk->freeList = &(disk->inodes[0]);

	DEBUG_CHECK(
		int j = 0;
		for (inode_t *ptr = disk->freeList; ptr != NULL; ptr = ptr->info.next) {
			if ((ptr->inumber != j) || (ptr->size)) {
				exit(-1);
			}
			j++;
		}
		if (j == INODES_NUM) {
			LOG("[_init_disk] inodes.next ok");
		}
		else
			exit(-1);
	);

	for (int i = 0; i < BLOCKS_NUM; i++) {
		disk->blocks[i].nextId = -1;
	}
}

static int _insert_IOFile(IOFile *io_file) {
	int fd = 0;
	// XXX: BUG of unlimited fd
#ifdef PWN
	while (state->io_files[fd]) {
		fd++;
	}
	state->io_files[fd] = io_file;
	return fd;
#else
	for (fd = 0; fd < FD_MAX; fd++) {
		if (!state->io_files[fd]) {
			state->io_files[fd] = io_file;
			return fd;
		}
	}
	return -1;
#endif
}

static fnode_t *_create_fnode(file_t type, const char *name, perm_t perm, long int inumber) {
	fnode_t *node = (fnode_t*) malloc(sizeof(fnode_t));
	CHECK_MALLOC(node, 0);

	node->type = type;
	node->name = strdup(name);
	node->perm = perm;

	node->modifyTime = node->createTime = time(NULL);

	node->parent = node;
	node->brother = NULL;

	if (type == NORMAL_FILE) {
		if (inumber == -1) {
			node->info.inumber = _create_inode();
		} else {
			node->info.inumber = inumber;
			state->disk->inodes[inumber].linkNr++;
		}
	} else {
		node->info.child = NULL;
	}

	LOG("[_create_fnode] create fileNode ok (%s)", node->name);
	return node;
}

/*
 * API Functions
 */

ssize_t zerofs_initfs(const char *username) {
	LOG("[zerofs_initfs] zerofs_initfs starts");

	state = (zerofs_state*) malloc(sizeof(zerofs_state));
	CHECK_MALLOC(state, NULL);
	LOG("[zerofs_initfs] state ok (%#lx)", (unsigned long) state);

	state->userId = 0xdd; // ONLY XDD COULD HANDLE THIS FILESYSTEM
	LOG("[zerofs_initfs] userId ok (%#lx)", state->userId);

	state->username = strdup(username);
	LOG("[zerofs_initfs] username ok (%s)", state->username);

	state->disk = mmap(NULL, sizeof(zerofs_disk), PROT_READ|PROT_WRITE,  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	CHECK_MALLOC(state->disk, MAP_FAILED);
	LOG("[zerofs_initfs] disk mmap ok (%#lx)", (unsigned long) state->disk);

	memset(state->disk, 0, sizeof(zerofs_disk));
	LOG("[zerofs_initfs] disk memset ok");

	_init_disk(state->disk);
	LOG("[zerofs_initfs] disk init ok");

	state->pwd = state->root = _create_fnode(DIRECTORY, "/", PWRITE|PREAD, -1);
	LOG("[zerofs_initfs] pwd and root ok (%#lx)", (unsigned long) state->root);

	memset(state->io_files, 0, sizeof(state->io_files));
	LOG("[zerofs_initfs] io_files ok");
	DEBUG_CHECK(
		for (int i = 0; i < FD_MAX; i++)
			if (state->io_files[i]) {
				LOG("[zerofs_initfs] error on io_files's memset");
				exit(-1);
			}
	);

	return 0;
}

int zerofs_open(const char *pathname, int flags){
	fnode_t *fnode = _resolve_path(pathname, 0);
	if (!fnode) {
		LOG("[zerofs_open] no such a file (%s)", pathname);
		if (flags == O_RDONLY) {
			LOG("[zerofs_open] read a non-existed file (%s)", pathname);
			return -1;
		}
		fnode_t *dnode = _resolve_path(pathname, 1);
		if (!dnode) {
			LOG("[zerofs_open] no such file or directory (%s)", pathname);
			return -1;
		}
		if ((dnode->perm & PWRITE) == 0) {
			LOG("[zerofs_open] cannot create anything in a non-write dir (%s)", dnode->name);
			return -1;
		}

		char *filename = _filename(pathname);
		if (!filename) {
			LOG("[zerofs_open] no filename (%s)", pathname);
			return -1;
		}
		fnode = _create_fnode(NORMAL_FILE, filename, PWRITE|PREAD, -1);
		free(filename);
		INSERT_FNODE(fnode, dnode);
	} else {
		if (fnode->type == DIRECTORY) {
			LOG("[zerofs_open] try to open a directory (%s)", fnode->name);
			return -1;
		}
		if ((flags == O_RDONLY) && (!(fnode->perm & PREAD))) {
			LOG("[zerofs_open] access delay (%s)", fnode->name);
			return -1;
		}
		if ((flags == O_WRONLY) && (!(fnode->perm & PWRITE))) {
			LOG("[zerofs_open] access delay (%s)", fnode->name);
			return -1;
		}
		if ((flags == O_RDWR) && ((fnode->perm & (PWRITE|PREAD)) != (PWRITE|PREAD))) {
			LOG("[zerofs_open] access delay (%s)", fnode->name);
			return -1;
		}
	}
	IOFile *io_file = _create_IOFile(fnode, flags);
	return _insert_IOFile(io_file);
}

int zerofs_close(int fd) {
	if (!state->io_files[fd]) {
		LOG("[zerofs_close] unused fd (%d)", fd);
		return -1;
	}
	// if ((fd < 0) || (fd >= FD_MAX)) {
	// 	LOG("[zerofs_close] invalid fd (%d)", fd);
	// 	return -1;
	// }
	free(state->io_files[fd]);
	state->io_files[fd] = 0;
	return 0;
}

int zerofs_chdir(const char *pathname) {
	fnode_t *fnode = _resolve_path(pathname, 0);
	if (!fnode) {
		LOG("[zerofs_chdir] no such directory (%s)", pathname);
		return -1;
	}
	if (fnode->type != DIRECTORY) {
		LOG("[zerofs_chdir] pathname is not a directory (%s)", pathname);
		return -1;
	}
	state->pwd = fnode;
	LOG("[zerofs_chdir] pwd is \"%s\" now", state->pwd->name);
	return 0;
}

int zerofs_mkdir(const char *pathname, int flags) {
	fnode_t *dnode = _resolve_path(pathname, 1);
	if (!dnode) {
		LOG("[zerofs_mkdir] no such directory (%s)", pathname);
		return -1;
	}
	if (dnode->type != DIRECTORY) {
		LOG("[zerofs_mkdir] no such directory (%s)", pathname);
		return -1;
	}
	if (!(dnode->perm & PWRITE)) {
		LOG("[zerofs_mkdir] directory cannot be written (%s)", dnode->name);
		return -1;
	}
	if (_resolve_path(pathname, 0)) {
		LOG("[zerofs_mkdir] directory already exists (%s)", pathname);
		return -1;
	}
	perm_t perm;
	switch (flags) {
		case O_RDONLY: perm = PREAD; break;
		case O_WRONLY: perm = PWRITE; break;
		case O_RDWR: perm = PWRITE|PREAD; break;
		default: LOG("[zerofs_mkdir] invalid flags (%d)", flags); return -1;
	}
	char *filename = _filename(pathname);
	fnode_t *fnode = _create_fnode(DIRECTORY, filename, perm, -1);
	free(filename);
	LOG("[zerofs_mkdir] new fnode (%p)", fnode);
	INSERT_FNODE(fnode, dnode);
	return 0;
}

int zerofs_rmdir(const char *pathname) {
	fnode_t *fnode = _resolve_path(pathname, 0);
	if (!fnode) {
		LOG("[zerofs_rmdir] no such directory (%s)", pathname);
		return -1;
	}
	if (fnode->info.child) {
		LOG("[zerofs_rmdir] directory is not empty (%s)", pathname);
		return -1;
	}
	if (fnode->type != DIRECTORY) {
		LOG("[zerofs_rmdir] no such directory (%s)", pathname);
		return -1;
	}
	// XXX: BUG for target directory is pwd
//#ifdef PWN
	// NOTHING TO DO
//#else
	if (fnode == state->pwd) {
		LOG("[zerofs_rmdir] cannot remove pwd (%s)", pathname);
		return -1;
	}
//#endif
	LOG("[zerofs_rmdir] remove directory (%s)", fnode->name);
	_unlink_fnode(fnode);
	free(fnode);
	return 0;
}

off_t zerofs_lseek(int fd, off_t offset, int whence) {
	// if ((fd < 0) || (fd >= FD_MAX)) {
	// 	LOG("[zerofs_lseek] invalid fd (%d)", fd);
	// 	return -1;
	// }
	if (!state->io_files[fd]) {
		LOG("[zerofs_lseek] no such fd (%d)", fd);
		return -1;
	}
	IOFile *io_file = state->io_files[fd];
	long int offset_;
	long int file_size = state->disk->inodes[io_file->fnode->info.inumber].size;
	switch (whence) {
		case SEEK_SET: offset_ = offset; break;
		case SEEK_CUR: offset_ = offset + io_file->cur; break;
		case SEEK_END: offset_ = offset + file_size; break;
		default: return -1;
	}
	if ((offset_ < 0) || (offset_ > file_size)) {
		LOG("[zerofs_lseek] invalid offset (%ld)", offset);
		return -1;
	}
	io_file->cur = offset_;
	return io_file->cur;
}

char **zerofs_list(const char *pathname) {
	fnode_t *fnode = _resolve_path(pathname, 0);
	char **res;
	if (!fnode) {
		LOG("[zerofs_list] no such file or directory (%s)", pathname);
fail:
		res = malloc(sizeof(char *));
		CHECK_MALLOC(res, 0);
		*res = NULL;
		return res;
	}
	if (fnode->type == DIRECTORY) {
		LOG("[zerofs_list] find directory (%s)", fnode->name);
		if (!(fnode->perm & PREAD)) {
			LOG("[zerofs_list] access delay (%s)", fnode->name);
			goto fail;
		}
		int num = 0;
		for (fnode_t *cur = fnode->info.child; cur != NULL; cur = cur->brother) {
			num++;
		}
		LOG("[zerofs_list] find %d children", num);
		res = malloc(sizeof(char *) * (num + 1));
		CHECK_MALLOC(res, 0);
		num = 0;
		for (fnode_t *cur = fnode->info.child; cur != NULL; cur = cur->brother) {
			res[num] = _fullpath(cur);
			num++;
		}
		res[num] = NULL;
		return res;
	}
	if (fnode->type == NORMAL_FILE) {
		LOG("[zerofs_list] find normal file (%s)", fnode->name);
		if (!(fnode->parent->perm & PREAD)) {
			LOG("[zerofs_list] access delay (%s)", fnode->parent->name);
			goto fail;
		}
		res = malloc(sizeof(char *) * 2);
		res[0] = _fullpath(fnode);
		res[1] = NULL;
		return res;
	}
	goto fail;
}

int zerofs_elemset(const char *pathname, elem_t elem, value_t value) {
	fnode_t *fnode = _resolve_path(pathname, 0);
	if (!fnode) {
		LOG("[zerofs_elemset] no such file or directory (%s)", pathname);
		return -1;
	}
	switch (elem) {
		case FNAME:
			if (!strcmp(value.ptr, ".") || !strcmp(value.ptr, "..") || strchr(value.ptr, '/')) {
				LOG("[zerofs_elemset] invalid new name (%s)", value.ptr);
				return -1;
			}
			// if (fnode->parent == fnode) {
			// 	LOG("[zerofs_elemset] try to rename root");
			// 	return -1;
			// }
			LOG("[zerofs_elemset] checking same name (%s)", value.ptr);
			for (fnode_t *cur = fnode->parent->info.child; cur != NULL; cur = cur->brother) {
				LOG("[zerofs_elemset] cur name (%s)", cur->name);
				if (!strcmp(value.ptr, cur->name)) {
					LOG("[zerofs_elemset] same name in directory (%s)", value.ptr);
					return -1;
				}
			}
			LOG("[zerofs_elemset] valid name (%s)", value.ptr);
			// free(fnode->name);
			// fnode->name = strdup(value.ptr);
			if (strlen(value.ptr)<=strlen(fnode->name))
				strncpy(fnode->name, value.ptr, strlen(fnode->name));
			else {
				free(fnode->name);
				fnode->name = strdup(value.ptr);
			}
			break;
		case FTYPE:
			LOG("[zerofs_elemset] cannot set type");
			return -1;
			// fnode->type = value.num;
			// break;
		case FPERM:
			fnode->perm = value.num;
			break;
		case FSIZE:
			LOG("[zerofs_elemset] cannot set size");
			return -1;
		case FLINK:
			LOG("[zerofs_elemset] cannot set link number");
			return -1;
		case FCTIME:
			fnode->createTime = value.num;
			break;
		case FMTIME:
			fnode->modifyTime = value.num;
			break;
		default:
			LOG("[zerofs_elemset] invalid type");
			return -1;
	}
	LOG("[zerofs_elemset] set value (%#lx)", value.num);
	return 0;
}

value_t zerofs_elemget(const char *pathname, elem_t elem) {
	fnode_t *fnode = _resolve_path(pathname, 0);
	value_t value;
	if (!fnode) {
		LOG("[zerofs_elemget] no such file or directory (%s)", pathname);
		value.num = -1;
		return value;
	}
	switch (elem) {
		case FNAME:
			value.ptr = strdup(fnode->name);
			break;
		case FTYPE:
			value.num = fnode->type;
			break;
		case FPERM:
			value.num = fnode->perm;
			break;
		case FSIZE:
			if (fnode->type == DIRECTORY) {
				value.num = 320;
			} else {
				value.num = state->disk->inodes[fnode->info.inumber].size;
			}
			break;
		case FLINK:
			if (fnode->type == DIRECTORY) {
				value.num = 1;
			} else {
				value.num = state->disk->inodes[fnode->info.inumber].linkNr;
			}
			break;
		case FCTIME:
			value.num = fnode->createTime;
			break;
		case FMTIME:
			value.num = fnode->modifyTime;
			break;
		default:
			value.num = -1;
	}
	LOG("[zerofs_elemget] get value (%#lx)", value.num);
	return value;
}

int zerofs_link(const char *oldpath, const char *newpath) {
	fnode_t *old_fnode = _resolve_path(oldpath, 0);
	if (!old_fnode) {
		LOG("[zerofs_link] no such file (%s)", oldpath);
		return -1;
	}
	if (old_fnode->type == DIRECTORY) {
		LOG("[zerofs_link] %s is a directory", old_fnode->name);
		return -1;
	}

	if (_resolve_path(newpath, 0)) {
		LOG("[zerofs_link] file already exists (%s)", newpath);
		return -1;
	}
	fnode_t *new_dnode = _resolve_path(newpath, 1);
	if (!new_dnode) {
		LOG("[zerofs_link] no sucu directory (%s)", newpath);
		return -1;
	}
	if (new_dnode->type == NORMAL_FILE) {
		LOG("[zerofs_link] %s is a normal file", new_dnode->name);
		return -1;
	}
	if (!(new_dnode->perm & PWRITE)) {
		LOG("[zerofs_link] access delay (%s)", new_dnode->name);
		return -1;
	}
	char *filename = _filename(newpath);
	fnode_t *new_fnode = _create_fnode(NORMAL_FILE, filename, old_fnode->perm, old_fnode->info.inumber);
	free(filename);
	INSERT_FNODE(new_fnode, new_dnode);
	return 0;
}

int zerofs_unlink(const char *pathname) {
	fnode_t *fnode = _resolve_path(pathname, 0);
	if (!fnode) {
		LOG("[zerofs_unlink] no such file or directory (%s)", pathname);
		return -1;
	}
	if (fnode->type == DIRECTORY) {
		LOG("[zerofs_unlink] cannot unlink a directory");
		return -1;
	}
	for (int fd = 0; fd < FD_MAX; fd++) {
		if ((state->io_files[fd]) && (state->io_files[fd]->fnode == fnode)) {
			int res = zerofs_close(fd);
			LOG("[zerofs_unlink] close fd (%d) with return value (%d)", fd, res);
		}
	}
	LOG("[zerofs_unlink] clear all fds");
	if (!(--state->disk->inodes[fnode->info.inumber].linkNr)) {
		_free_inode(fnode->info.inumber);
	}

	free(fnode->name);
	_unlink_fnode(fnode);
	free(fnode);
	fnode = 0;
	return 0;
}

char *zerofs_pwd(void) {
	return _fullpath(state->pwd);
}

ssize_t zerofs_read(int fd, void *buf, size_t count) {
	// if ((fd >= FD_MAX) || (!state->io_files[fd]) || (fd < 0)) {
	// 	LOG("[zerofs_read] invalid fd (%d)", fd);
	// 	return -1;
	// }
	IOFile *io_file = state->io_files[fd];
	long int file_size = state->disk->inodes[io_file->fnode->info.inumber].size;
	long int start = io_file->cur;
	long int end = io_file->cur + count;
	if (end > file_size) {
		end = file_size;
	}
	if (start >= end) {
		LOG("[zerofs_read] nothing to read");
		return 0;
	}
	long int inumber = io_file->fnode->info.inumber;
	long int blockId = state->disk->inodes[inumber].info.blockId;
	ssize_t ret = _memory_read(blockId, buf, start, end);
	if (ret != -1) {
		io_file->cur = end;
	}
	return ret;
}

int zerofs_truncate(const char *pathname, off_t length) {
	if (length < 0) {
		LOG("[zerofs_truncate] invalid offset (%d)", length);
	}
	fnode_t *fnode = _resolve_path(pathname, 0);
	if (!fnode) {
		LOG("[zerofs_truncate] no such file or directory (%s)", pathname);
		return -1;
	}
	if (fnode->type == DIRECTORY) {
		LOG("[zerofs_truncate] try to truncate a directory (%s)", pathname);
		return -1;
	}
	long int blockId = state->disk->inodes[fnode->info.inumber].info.blockId;
	long int old_size = state->disk->inodes[fnode->info.inumber].size;
	state->disk->inodes[fnode->info.inumber].info.blockId = _memory_truncate(blockId, length, old_size);
	state->disk->inodes[fnode->info.inumber].size = length;
	for (int i = 0; i < FD_MAX; i++) {
		if ((state->io_files[i]) && (state->io_files[i]->fnode == fnode) && (state->io_files[i]->cur > length)) {
			state->io_files[i]->cur = length;
		}
	}
	return 0;
}

ssize_t zerofs_write(int fd, const void *buf, size_t count) {
	// if ((fd >= FD_MAX) || (!state->io_files[fd]) || (fd < 0)) {
	// 	LOG("[zerofs_write] invalid fd (%d)", fd);
	// 	return -1;
	// }
	IOFile *io_file = state->io_files[fd];
	long int start = io_file->cur;
	long int end = io_file->cur + count;
	long int file_size = state->disk->inodes[io_file->fnode->info.inumber].size;

	if (end > file_size) {
		state->disk->inodes[io_file->fnode->info.inumber].size = end;
	}

	if (start >= end) {
		LOG("[zerofs_write] nothing to write");
		return 0;
	}

	io_file->fnode->modifyTime = time(NULL);

	long int inumber = io_file->fnode->info.inumber;
	long int blockId = state->disk->inodes[inumber].info.blockId;
	if (blockId == -1) {
		blockId = state->disk->inodes[inumber].info.blockId = _create_block();
	}
	ssize_t ret = _memory_write(blockId, buf, start, end);
	if (ret != -1) {
		io_file->cur = end;
	}
	return ret;
}

#ifdef DEBUG

#ifndef SHELL

int main() {
	printf("Hello World!\n");
	zerofs_initfs("izhuer");
	int fd = zerofs_open("izhuer", O_WRONLY);
	printf("fd: %d\n", fd);
	zerofs_close(fd);
	zerofs_close(fd);
	zerofs_chdir("izhuer");
	zerofs_chdir("/");
	zerofs_mkdir("izhuer", O_RDONLY);
	zerofs_mkdir("./izhuer", O_RDWR);
	zerofs_mkdir("/izhuer", O_RDWR);
	zerofs_mkdir("xuexue", O_RDWR);
	zerofs_chdir("./../../xuexue");
	zerofs_mkdir("test_rd", O_RDONLY);
	zerofs_mkdir("test_wr", O_WRONLY);
	zerofs_mkdir("test_rdwr", O_RDWR);
	zerofs_chdir("test_rd");
	zerofs_mkdir("test", O_RDONLY);
	zerofs_chdir("..");
	zerofs_rmdir("test_rdwr");
	zerofs_chdir("test_rdwr");
	zerofs_chdir("/xuexue/");
	char **res;
	res = zerofs_list(".../../../../");
	while (*res) {
		printf("%s\n", *res);
		res++;
	}
	zerofs_elemget(".", FCTIME);
	value_t value;
	value.num = 0;
	zerofs_elemset(".", FCTIME, value);
	zerofs_elemget(".", FCTIME);
	value.ptr = strdup("../test");
	zerofs_elemset(".", FNAME, value);
	res = zerofs_list("/");
	while (*res) {
		printf("%s\n", *res);
		res++;
	}
	res = zerofs_list(".");
	while (*res) {
		printf("%s\n", *res);
		res++;
	}
	value.ptr = strdup("izhuer");
	zerofs_elemset(".", FNAME, value);
	value.ptr = strdup("izhuer2");
	zerofs_elemset(".", FNAME, value);
	puts(zerofs_pwd());
	for (int i = 0; i < 0x50; i ++)
		printf("%d\n", _create_block());
	_free_block(0x1);
	printf("%d\n", _create_block());
	_free_block(0x48);
	printf("%d\n", _create_block());
	res = zerofs_list("/");
	while (*res) {
		printf("%s\n", *res);
		res++;
	}
	zerofs_unlink("/izhuer");
	res = zerofs_list("/");
	while (*res) {
		printf("%s\n", *res);
		res++;
	}
	fd = zerofs_open("/izhuer3", O_RDWR);
	char *buf = strdup("zzdawang");
	printf("TEST: buf: \"%s\"\n", buf);
	zerofs_write(fd, buf, 0x8);
	zerofs_close(fd);
	*((long int *)buf) = 0;
	printf("TEST: buf: \"%s\"\n", buf);
	fd = zerofs_open("/izhuer3", O_RDWR);
	zerofs_read(fd, buf, 0x8);
	zerofs_close(fd);
	printf("TEST: buf: \"%s\"\n", buf);
	zerofs_chdir("/");
	zerofs_link("/izhuer3", "izhuer4");
	res = zerofs_list(".");
	while (*res) {
		printf("%s\n", *res);
		res++;
	}
	int fd1, fd2;
	fd1 = zerofs_open("/izhuer3", O_RDWR);
	zerofs_read(fd1, buf, 0x8);
	printf("TEST: buf: \"%s\"\n", buf);
	zerofs_truncate("izhuer4", 0x10000);
	fd2 = zerofs_open("izhuer4", O_RDWR);
	zerofs_write(fd2, "aixuexue", 0x8);
	zerofs_read(fd1, buf, 0x8);
	printf("TEST: buf: \"%s\"\n", buf);
	zerofs_lseek(fd1, 0, SEEK_SET);
	zerofs_read(fd1, buf, 0x8);
	printf("TEST: buf: \"%s\"\n", buf);

	zerofs_close(fd1);
	zerofs_close(fd2);
}

#endif

#endif
