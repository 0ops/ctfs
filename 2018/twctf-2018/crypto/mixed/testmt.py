from mt19937predictor import MT19937Predictor
import random

random.getrandbits(24)
pre = MT19937Predictor()
a = random.getrandbits(800*32)
pre.setrandbits(a,800*32)
print(random.getrandbits(32*10))
print(pre.getrandbits(32*10))
print(random.random())
print(pre.random())