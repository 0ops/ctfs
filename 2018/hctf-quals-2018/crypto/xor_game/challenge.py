from Crypto.Util.strxor import strxor
import base64
import random


def enc(data, key):
    key = (key * (len(data) / len(key) + 1))[:len(data)]
    return strxor(data, key)


poem = open('poem.txt', 'r').read()
flag = "hctf{xxxxxxxxxxx}"

with open('cipher.txt', 'w') as f:
    f.write(base64.b64encode(enc(poem, flag[5:-1])))
    f.close()

