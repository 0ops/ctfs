#!/usr/bin/env python
__author__ = "polaris"

import numpy as np
from pwn import *
import matplotlib.pyplot as plt

#context.log_level = "debug"
def get_number(x, freq,rge):
    y = np.sin(2*np.pi*x*freq)*rge
    return y


p = remote("150.109.119.46",6775)
p.recvuntil("hint:")
p.sendline("y")
p.recvuntil("input your token:")
p.sendline("H2RHMpUvWhtgAutnpZ6Tyd6CzdOX2TJc")



for i in range(8):
    print i
    data = eval(p.recvuntil("]"))



    x = np.linspace(0,1,1500)
    y=np.fft.fft(data)
    yf=abs(y)
    yf1=abs(y)/len(x)
    yf2 = yf1[range(int(len(x)/2))]
    xf = np.arange(len(y))
    xf1 = xf
    xf2 = xf[range(int(len(x)/2))]
    tmp = list(yf2)
    res = []
    for i in range(len(tmp)):
        if tmp[i]>3:
            res.append(str(i))

    assert(len(res)==4)

    p.sendline(" ".join(res))
p.interactive()