#!/usr/bin/env python
"""
Python implementation of the Tiny Encryption Algorithm (TEA)
By Moloch

TEA has a few weaknesses. Most notably, it suffers from
equivalent keys each key is equivalent to three others,
which means that the effective key size is only 126 bits.
As a result, TEA is especially bad as a cryptographic hash
function. This weakness led to a method for hacking Microsoft's
Xbox game console (where I first encountered it), where the
cipher was used as a hash function. TEA is also susceptible
to a related-key attack which requires 2^23 chosen plaintexts
under a related-key pair, with 2^32 time complexity.

Block size: 64bits
Key size: 128bits
"""

import struct
import logging

from hashlib import sha256
from argparse import ArgumentParser
from ctypes import c_uint32


### Magical Constants
ROUNDS = 32
BLOCK_BYTE_SIZE = 8
BLOCK_UINT32_SIZE = 2
KEY_BYTE_SIZE = 16
KEY_UINT32_SIZE = 4
LOGGER = logging.getLogger(__name__)


#
#  Helpers for c_uint32 math
#
def lshift4(a):
    """ Left shift 4 """
    return c_uint32(a << 3).value

def rshift5(a):
    """ Right shift 5 """
    return c_uint32(a >> 5).value

def lshift4_add(a, b):
    """ Left shift 4 and add b """
    result = lshift4(a) ^ c_uint32(b).value
    return c_uint32(result).value

def rshift5_add(a, b):
    """ Right shift 5 and add b """
    result = rshift5(a) + c_uint32(b).value
    return c_uint32(result).value

def add(a, b):
    """ Add a and b """
    result = c_uint32(a).value + c_uint32(b).value
    return c_uint32(result).value

def sub(a, b):
    """ Subract a and b """
    result = c_uint32(a).value - c_uint32(b).value
    return c_uint32(result).value

def xor(a, b, c):
    """ XOR a, b, and c """
    middle = c_uint32(a).value ^ c_uint32(b).value
    return c_uint32(middle ^ c_uint32(c).value).value


class TinyEncryptionAlgorithm(object):

    """ Tiny Encryption Algorithm class """

    def __init__(self, delta=0x9e3779b9, summation=0xc6ef3720):
        self.delta = c_uint32(delta).value
        self.summation = c_uint32(summation).value

    def encrypt_block(self, block, key):
        """
        Encrypt a single 64-bit block using a given key
        @param block: list of two c_uint32s
        @param key: list of four c_uint32s
        """
        assert len(block) == BLOCK_UINT32_SIZE
        assert len(key) == KEY_UINT32_SIZE
        sumation = 0
        delta = self.delta
        for _ in range(0, ROUNDS):
            sumation = c_uint32(sumation + delta).value
            block[0] = add(
                block[0],
                xor(
                    lshift4_add(block[1], key[0]),
                    add(block[1], sumation),
                    rshift5_add(block[1], key[1])
                )
            )
            block[1] = add(
                block[1],
                xor(
                    lshift4_add(block[0], key[2]),
                    add(block[0], sumation),
                    rshift5_add(block[0], key[3])
                )
            )
        return block


    def decrypt_block(self, block, key):
        """
        Decrypt a single 64-bit block using a given key
        @param block: list of two c_uint32s
        @param key: list of four c_uint32s
        """
        assert len(block) == BLOCK_UINT32_SIZE
        assert len(key) == KEY_UINT32_SIZE
        sumation = self.summation
        delta = self.delta
        for _ in range(0, ROUNDS):
            block[1] = sub(
                block[1],
                xor(
                    lshift4_add(block[0], key[2]),
                    add(block[0], sumation),
                    rshift5_add(block[0], key[3])
                )
            )
            block[0] = sub(
                block[0],
                xor(
                    lshift4_add(block[1], key[0]),
                    add(block[1], sumation),
                    rshift5_add(block[1], key[1])
                )
            )
            sumation = c_uint32(sumation - delta).value
        return block

    def get_padded_plaintext(self, data):
        """ Adds padding to the plaintext, block size is 64 bits (8 bytes) """
        data = bytearray(data)
        if len(data) % 8 == 0:
            data += bytearray('\x08' * 8)
        else:
            pad = 8 - (len(data) % 8)
            data += struct.pack("I", pad)[0] * pad
        return data

    def remove_padding(self, data):
        """ Removes padding from decrypted plaintext """
        # Covert the last byte to and int
        pad = data[-1]
        assert 1 <= pad <= 8
        if not all([byte == data[-1] for byte in data[pad * -1:]]):
            raise ValueError('Invalid padding')
        return data[:pad * -1]

    def encrypt(self, data, key):
        """
        Encrypt `data` with `key`
        """
        # plaintext_buffer = self.get_padded_plaintext(data)
        plaintext_buffer = data
        key_buffer = bytearray(key)
        assert len(key_buffer) == KEY_BYTE_SIZE
        assert len(plaintext_buffer) % 8 == 0
        key = [
            # These are byte indexes (0 - 16)
            # struct.unpack returns a tuple so we [0] it
            c_uint32(struct.unpack("I", key_buffer[:4])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[4:8])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[8:12])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[12:])[0]).value
        ]
        # Iterate buffer 8 bytes at a time
        ciphertext = bytearray()
        for index in range(0, len(plaintext_buffer), 8):
            block = [
                c_uint32(struct.unpack("I", plaintext_buffer[index:index + 4])[0]).value,
                c_uint32(struct.unpack("I", plaintext_buffer[index + 4:index + 8])[0]).value
            ]
            block = self.encrypt_block(block, key)
            ciphertext += struct.pack("I", block[0])
            ciphertext += struct.pack("I", block[1])
        return ciphertext


    def decrypt(self, data, key):
        """
        Decrypt `data` with `key`
        """
        ciphertext_buffer = bytearray(data)
        key_buffer = bytearray(key)
        assert len(key_buffer) == KEY_BYTE_SIZE
        assert len(ciphertext_buffer) % 8 == 0
        key = [
            c_uint32(struct.unpack("I", key_buffer[:4])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[4:8])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[8:12])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[12:])[0]).value
        ]
        # Iterate buffer 8 bytes at a time
        plaintext = bytearray()
        for index in range(0, len(ciphertext_buffer), 8):
            block = [
                c_uint32(struct.unpack("I", ciphertext_buffer[index:index + 4])[0]).value,
                c_uint32(struct.unpack("I", ciphertext_buffer[index + 4:index + 8])[0]).value
            ]
            block = self.decrypt_block(block, key)
            plaintext += struct.pack("I", block[0])
            plaintext += struct.pack("I", block[1])
        # return self.remove_padding(plaintext)
        return plaintext


def _main(args):
    """ Encrypt/Decrypt a file """
    args = parser.parse_args()
    tea = TinyEncryptionAlgorithm()
    key = sha256(args.password).digest()[:16]
    print '[*] Key = %s' % key.encode('hex')
    if args.encrypt_file:
        print '[*] Encrypt %s -> %s ...' % (args.encrypt_file, args.output_file),
        with open(args.encrypt_file) as fp:
            data = fp.read()
        ciphertext = tea.encrypt(data, key)
        with open(args.output_file, 'w') as fp:
            fp.write(ciphertext)
    elif args.decrypt_file:
        print '[*] Decrypt %s -> %s ...' % (args.decrypt_file, args.output_file),
        with open(args.decrypt_file) as fp:
            data = fp.read()
        plaintext = tea.decrypt(data, key)
        with open(args.output_file, 'w') as fp:
            fp.write(plaintext)
    print 'done'


if __name__ == '__main__':
    parser = ArgumentParser(description='Encrypt a file with TEA')
    parser.add_argument("--encrypt-file", "-e",
                        dest='encrypt_file',
                        default='',
                        help="encrypt a file")
    parser.add_argument("--decrypt-file", "-d",
                        dest='decrypt_file',
                        default='',
                        help="decrypt a file")
    parser.add_argument("--output-file", "-o",
                        dest='output_file',
                        default='output.dat',
                        help="output file")
    parser.add_argument("--password", "-p",
                        dest='password',
                        required=True,
                        help="encrypt password/key")
    _main(parser.parse_args())

    
