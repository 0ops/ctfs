#!/usr/bin/env python3

from challenge import CodeBasedEncryptionScheme

from BitVector import BitVector
from random import SystemRandom
from os import urandom



if __name__ == "__main__":
    cipher = CodeBasedEncryptionScheme(BitVector(size=48, intVal=222740723777208))
    random = SystemRandom()
    flag = b''
    for i in range(31):
        with open("data/flag_{:02d}".format(i), "rb") as f:
            flag += cipher.decrypt(f.read())
    print(flag)
