# Fast & Furious
Heap UAF in kernel, use ptmx to cause info leak and pc control, no smap means allowing you do ROP in kernel.

However kvm64 is enable and kpti become part of /proc/cpuinfo feature, one cannot use iretq to directly return to user space, here provide 2 way to read /flag using ROP:
    1. `commit_creds(prepare_kernel_cred(0)) -> chmod /flag 666 -> sleep` while start another process read the /flag (referred as solve.c)
    2. `commit_creds(prepare_kernel_cred(0)) -> file=flip_open("/flag",0,0) -> kernel_read(file,&offset,128,buf) -> pop pop pop pop ...` set buf to kernel stack(fakestack) and let the content of /flag pop to registers then trigger kernel panic (such as ret to addr 0), it will print the last saved value in each registers, which is the content of /flag
