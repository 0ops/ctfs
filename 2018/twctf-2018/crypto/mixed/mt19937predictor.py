#! python3

N = 624
M = 397
MATRIX_A   = 0x9908b0df
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7fffffff

class MT19937Predictor():    
    def __init__(self):
        self.mt = [0 for i in range(N)]
        self.mti = 0
    
    def __tempering(self, y):
        y ^= (y >> 11)
        y ^= (y <<  7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= (y >> 18)
        return y

    def __untempering(self, y):
        y ^= (y >> 18)
        y ^= (y << 15) & 0xefc60000
        y ^= ((y <<  7) & 0x9d2c5680) ^ ((y << 14) & 0x94284000) ^ ((y << 21) & 0x14200000) ^ ((y << 28) & 0x10000000)
        y ^= (y >> 11) ^ (y >> 22)
        return y

    def __twister(self, k):
        mag01 = [0x0, MATRIX_A]
        y = (self.mt[k] & UPPER_MASK) | (self.mt[(k + 1) % N] & LOWER_MASK)
        self.mt[k] = self.mt[(k + M) % N] ^ (y >> 1) ^ mag01[y & 0x1]
        
    def getrandbits(self, bits):
        if not (bits > 0):
            raise ValueError('number of bits must be greater than zero')
        if bits <= 32:
            return self.getrand32bits() >> (32 - bits)
        else:
            acc = bytearray()
            while bits > 0:
                r = self.getrand32bits()
                if bits < 32:
                    r >>= 32 - bits
                acc += r.to_bytes(4, byteorder='little')
                bits -= 32
            return int.from_bytes(acc, byteorder='little')
    
    def getrand32bits(self):
        self.__twister(self.mti)
        y = self.mt[self.mti]
        self.mti = (self.mti + 1) % N
        return self.__tempering(y)
     
    def setrand32bits(self, y):
        assert 0 <= y < 2 ** 32
        self.mt[self.mti] = self.__untempering(y)
        self.mti = (self.mti + 1) % N

    def setrandbits(self, y, bits):
        if not (bits % 32 == 0):
            raise ValueError('number of bits must be a multiple of 32')
        if not (0 <= y < 2 ** bits):
            raise ValueError('invalid state')
        if bits == 32:
            self.setrand32bits(y)
        else:
            while bits > 0:
                self.setrand32bits(y & 0xffffffff)
                y >>= 32
                bits -= 32

    def random(self):
        a = self.getrand32bits() >> 5
        b = self.getrand32bits() >> 6
        return ((a * 67108864.0 + b) * (1.0 / 9007199254740992.0))

    """
    def seed(self):
        raise NotImplementedError
    """
    
    def setstate(self, mt, mti):
        self.mt = mt
        self.mti = mti

    def getstate(self):
        return self.mt, self.mti
        