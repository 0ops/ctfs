from secret import flag, mask1, mask2
import string
import random
import sys
import os
import signal
import hashlib
from Crypto.Cipher import AES

menu = """
CHOOSE 1 OPTION
1. Encrypt message
2. Decrypt message
3. Get encrypted flag
4. Exit\n
"""

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
bs = 16

def to_string(num, max_len = 128):
    tmp = bin(num).lstrip('0b')[-max_len:].rjust(max_len, '0')
    return "".join(chr(int(tmp[i:i+8], 2)) for i in range(0, max_len, 8))

def pad(s):
	padnum = bs - len(s) % bs
	return s + padnum * chr(padnum)

def unpad(s):
	return s[:-ord(s[-1])]

def gen_key(mask):
	tmp1 = random.random()
	tmp2 = random.random()
	key = int(tmp1 * 2**128) | int(tmp2 * 2**75) | (mask & 0x3fffff)
	key = to_string(key)
	return key

def encrypt_msg(msg, key1, key2):
	iv = to_string(random.getrandbits(128))
	aes1 = AES.new(key1, AES.MODE_CBC, iv)
	aes2 = AES.new(key2, AES.MODE_CBC, iv)
	enc = aes1.encrypt(aes2.encrypt(pad(msg)))
	return (iv + enc).encode("hex")

def proof_of_work():
    """
    This function has very special purpose 
    :)) Simply to screw you up
    """
    prefix = to_string(random.getrandbits(64), 64)
    print 'prefix = {}'.format(prefix.encode('hex'))
    challenge = raw_input('> ')
    tmp = hashlib.sha256(prefix + challenge).hexdigest()
    if tmp.startswith('00000'):
        return True
    else:
        return False

key1 = gen_key(mask1)
key2 = gen_key(mask2)

signal.alarm(300)

if not proof_of_work():
	exit(0)

for _ in range(256):
	print menu
	try:
		choice = int(raw_input("> "))
	except:
		print "wrong option"
		exit(-1)
	if choice == 1:
		msg = raw_input("give me a string: ")
		print encrypt_msg(msg, key1, key2)
	elif choice == 2:
		print "Not implement yet..."
	elif choice == 3:
		print encrypt_msg(flag, key1, key2)
	elif choice == 4:
		exit(-1)
	else:
		print "wrong option"
		exit(-1)