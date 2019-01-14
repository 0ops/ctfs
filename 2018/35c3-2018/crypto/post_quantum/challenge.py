#!/usr/bin/python3

from BitVector import BitVector
from random import SystemRandom

inverse_error_probability = 3

def matrix_vector_multiply(columns, vector):
    cols = len(columns)
    assert(cols == len(vector))
    rows = len(columns[0])
    result = BitVector(size=rows)
    for i, bit in zip(range(cols), vector):
        assert(len(columns[i]) == rows)
        if bit == 1:
            result = result ^ columns[i]
    return result

def bitvector_to_bytes(bitvector):
    return bitvector.int_val().to_bytes(len(bitvector) // 8, 'big')

def bitvector_from_bytes(bytes):
    return BitVector(size=len(bytes) * 8, intVal = int.from_bytes(bytes, 'big'))

class CodeBasedEncryptionScheme(object):

    @classmethod
    def new(cls, bitlength=48):
        key = cls.keygen(bitlength)
        return cls(key)

    def __init__(self, key):
        self.key = key
        self.key_length = len(self.key)
        self.random = SystemRandom()

    @classmethod
    def keygen(cls, bitlength):
        key = SystemRandom().getrandbits(bitlength)
        key = BitVector(size=bitlength, intVal = key)
        return key

    def add_encoding(self, message):
        message = int.from_bytes(message, 'big')
        message = BitVector(size=self.key_length // 3, intVal=message)
        out = BitVector(size=self.key_length)
        for i, b in enumerate(message):
            out[i*3 + 0] = b
            out[i*3 + 1] = b
            out[i*3 + 2] = b
        return out


    def decode(self, message):
        out = BitVector(size=self.key_length // 3)
        for i in range(self.key_length // 3):
            if message[i * 3] == message[i * 3 + 1]:
                decoded_bit = message[i * 3]
            elif message[i * 3] == message[i * 3 + 2]:
                decoded_bit = message[i * 3]
            elif message[i * 3 + 1] == message [i * 3 + 2]:
                decoded_bit = message[i * 3 + 1]
            else:
                assert(False)
            out[i] = decoded_bit
        return bitvector_to_bytes(out)

    def encrypt(self, message):

        message = self.add_encoding(message)

        columns = [
            BitVector(
                size=self.key_length,
                intVal=self.random.getrandbits(self.key_length)
            )
            for _ in range(self.key_length)
        ]

        # compute the noiseless mask
        y = matrix_vector_multiply(columns, self.key)

        # mask the message
        y ^= message

        # add noise: make a third of all equations false
        for i in range(self.key_length // 3):
            noise_index = self.random.randrange(inverse_error_probability)
            y[i * 3 + noise_index] ^= 1

        columns = [bitvector_to_bytes(c) for c in columns]
        columns = b"".join(columns)

        return columns + bitvector_to_bytes(y)

    def decrypt(self, ciphertext):

        y = ciphertext[-self.key_length // 8:]
        columns = ciphertext[:-self.key_length // 8]
        columns = [
            bitvector_from_bytes(columns[i:i+self.key_length // 8])
            for i in range(0, len(columns), self.key_length // 8)
        ]
        y = bitvector_from_bytes(y)

        y ^= matrix_vector_multiply(columns, self.key)
        result = self.decode(y)
        return result


