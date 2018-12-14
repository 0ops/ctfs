#!/usr/bin/env python
# coding=utf-8

from pwn import u32, p32, crc, log, md5sum, pack, unpack, remote, process,context
from random import randint
from Crypto.Cipher import ARC4

context.log_level = 'debug'
# context.log_level = 'critical'
a = None
r = None
DEBUG = 0
DEBUG2 = 1

def init_sock(ip, port):
    global r
    # r = remote(ip, port, timeout=1)
    r = process('./zeroftp')

def init_enc():
    global r, a
    p = 0xab1b141539b31ec6468724ad0c42d177e72f17649cfc4677ca415cfeacd792e3a32c9e4f3f9c5fc0bb95fa651b4edbbe484929d8c9991bf2b00019b4e53d26bf321c6a5b4b9efe010300a696a812869f87f4d4d1ac074b505137ac0c2e0567395d7dde02f517a7cfff8021049ba5733b974e87b459b054199c6ae600414539b7
    g = 15

    if DEBUG:
        log.info(r.recvline())
        log.info(r.recvline())
    gx = int(r.recv(1024), 16)
    if DEBUG:
        print 'gx', hex(gx)
    y = randint(2, p-1)
    if DEBUG:
        print 'y', hex(y)
    gy = pow(g, y, p)
    if DEBUG:
        print 'gy', hex(gy)
    r.send("{:0256x}".format(gy))
    if DEBUG:
        log.info(r.recvline())
        log.info(r.recvline())
    key = format(pow(gx, y, p), '0256x').decode('hex')
    if DEBUG:
        print 'key', key.encode('hex')
    a = ARC4.new(key)

def send(m):
    global a, r
    m = a.encrypt(m)
    r.send(m)
    if DEBUG2:
        log.info(r.recvline())

def recv(length):
    global a, r
    res = ''
    while length:
        try:
            m = r.recv(length)
        except EOFError:
            break
        m = a.encrypt(m)
        res += m
        length -= len(m)
    return res

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
        payload += payload
    else:
        len_len = len(bin(len(data))[2:])//8 + 1
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
    int_len = len(bin(data)[2:])//8 + 1
    payload = pack(data, 8*int_len, endian=endian)
    info = 0
    info = BITS_SET_VAL(info, 0, 3, 4)
    info = BITS_SET_VAL(info, 4, 5, int(endian == 'big'))
    info = BITS_SET_VAL(info, 5, 8, int_len-1);
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
        return data, payload[1+zero_int_len]

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
        list_len_len = len(bin(len(list_len))[2:])//8 + 1
        list_len = pack(len(list_len), 8*list_len_len, endian='little')
        info = BITS_SET_VAL(info, 3, 4, 1)
        info = BITS_SET_VAL(info, 4, 8, list_len_len)
        payload = chr(info)
        for i in xrange(list_len):
            payload += data[i]
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
            #log.debug('aaaaaaaaa {}'.format(ret))
    else:
        if zero_list_len >= 6:
            return 0
        else:
            list_len = unpack(payload[1:1+zero_list_len], 8*zero_list_len, endian='little')
            payload = payload[1+zero_list_len:]
            for i in xrange(list_len):
                payload = zero_unpack(payload)
    return ret

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
    magic = recv(1)
    assert magic == '\xdd'
    data_length = u32(recv(4), endian='big')
    #log.info('data_length {}'.format(data_length))
    data = recv(data_length)
    #log.info('data {}'.format(hexdump(data)))
    data_crc32 = u32(recv(4), endian='big')
    assert crc.crc_32(data) == data_crc32
    #log.info(data.encode('hex'))
    return zero_unpack(data)

def zero_send(data):
    magic = '\xdd'
    data_len = p32(len(data), endian='big')
    data_crc32 = p32(crc.crc_32(data), endian='big')
    payload  = magic + data_len + data + data_crc32
    send(payload)

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
    ret = zero_recv()
    return ret

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
    return 

def zeroftp_rmdir(directory):
    payload  = zero_pack_int(0x5, endian='big')
    payload += zero_pack_string(directory)
    zero_send(payload)
    ret = zero_recv()
    return ret 
    return 

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

def zeroftp_rmfile():
    payload  = zero_pack_int(0x8, endian='big')
    return 

def zeroftp_fileinfo(pathname, fileinfo_elem):
    payload  = zero_pack_int(0x9, endian='big')
    payload += zero_pack_string(pathname)
    payload += zero_pack_int(fileinfo_elem, endian='big')
    zero_send(payload)
    ret = zero_recv()
    return ret 

def zeroftp_setfileinfo(pathname, fileinfo_elem, arg3):
    payload  = zero_pack_int(0xa, endian='big')
    payload += zero_pack_string(pathname)
    payload += zero_pack_int(fileinfo_elem, endian='big')
    payload += zero_pack_string(pathname)
    if fileinfo_elem == 0:
        payload += zero_pack_string(arg3)
    else:
        payload += zero_pack_int(arg3, endian='big')

    zero_send(payload)
    ret = zero_recv()
    return ret 

def zeroftp_backdoor():
    payload  = zero_pack_int(0xb, endian='big')
    payload += zero_pack_string('flag')
    #payload += zero_pack_raw('b1111111111111gtang')
    zero_send(payload)
    ret = zero_recv()
    return ret

def zeroftp_exit():
    return 

def test():
    zeroftp_login('admin', 'admin')
    zeroftp_wrfile('./flag','hackedhackedhacked')
    zeroftp_wrfile('./test1','hackedhackedhacked')
    zeroftp_wrfile('./test2','hackedhackedhacked')
    directory = zeroftp_ls('/')
    log.info('directory {}'.format(directory))
    content = zeroftp_rdfile('./flag')
    log.info('file {} content {}'.format('./flag', content))
    zeroftp_fileinfo('./flag', 0)
    zeroftp_setfileinfo('test1', 0, 'test2')
    zeroftp_setfileinfo('test1', 1, 1)
    zeroftp_mkdir('./zzz')
    zeroftp_cd('./zzz')
    zeroftp_wrfile('./123','hackedhackedhacked')
    zeroftp_wrfile('./456','hackedhackedhacked')
    zeroftp_wrfile('./abc','hackedhackedhacked')
    content = zeroftp_rdfile('./456')
    log.info('file {} content {}'.format('./456', content))
    zeroftp_cd('/')
    directory = zeroftp_ls('/')
    log.info('directory {}'.format('./flag', directory))
    zeroftp_rmdir('/')
    directory = zeroftp_ls('/')
    log.info('directory {}'.format(directory))

