from Crypto.Util.number import bytes_to_long, getPrime
from random import randint
from gmpy2 import powmod
import sys

p = getPrime(1024)
q = getPrime(1024)
N = p*q
Phi = (p-1)*(q-1)

with open("flag", 'r') as fr:
	flag = bytes_to_long(fr.read().strip())

def get_enc_key(BitLen, Phi):
    e = getPrime(BitLen)
    if Phi % e == 0:
        return get_enc_key(BitLen, Phi)
    else:
        return e

def sprint(message):
	print(message)
	sys.stdout.flush()

def communicate():
	sprint("This is a message distribute system. Please tell me your name: ")
	user = raw_input()
	bakcdoor(user)
	e = get_enc_key(randint(13, 13 + (len(user) % 4)), Phi)
	ct = powmod(flag, e, N)
	sprint("Hi %s, your N is: %d\nAnd your exponent is: %d\nLast but not least, your secret is: %d" % (user, N, e, ct))
	sprint("You will know the secret after I give you P,Q.\nSee you next time!")

if __name__ == "__main__":
	communicate()

