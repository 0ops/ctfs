__author__ = "polaris"

from gmpy2 import gcd

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = egcd(b % a, a)
        return (g, y - (b // a) * x, x)

def modinv(b, n):
    g, x, _ = egcd(b, n)
    print g
    if g == 1:
        return x % n

def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0]*multiplier) % modulus
    return modulus, multiplier, increment

def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * modinv(states[1] - states[0], modulus) % modulus
    return crack_unknown_increment(states, modulus, multiplier)

def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)

from pwn import *


while True:
    p = remote("95.213.235.103",8801)
    p.recvline()
    p.recvline()
    data = []
    for i in range(10):
        data.append(int(p.recvline().strip()))
    try:
        (modulus, multiplier, increment) = crack_unknown_modulus(data[0:6])
        nnn = ((data[9]*multiplier+increment)%modulus)
        p.sendline(str(nnn))
        p.interactive()
    except:
        p.close()
