from hashlib import sha1
from Crypto import Random
from flag import FLAG


class PrivateSigningKey:

    def __init__(self):
        self.gen = 0x44120dc98545c6d3d81bfc7898983e7b7f6ac8e08d3943af0be7f5d52264abb3775a905e003151ed0631376165b65c8ef72d0b6880da7e4b5e7b833377bb50fde65846426a5bfdc182673b6b2504ebfe0d6bca36338b3a3be334689c1afb17869baeb2b0380351b61555df31f0cda3445bba4023be72a494588d640a9da7bd16L
        self.q = 0x926c99d24bd4d5b47adb75bd9933de8be5932f4bL
        self.p = 0x80000000000001cda6f403d8a752a4e7976173ebfcd2acf69a29f4bada1ca3178b56131c2c1f00cf7875a2e7c497b10fea66b26436e40b7b73952081319e26603810a558f871d6d256fddbec5933b77fa7d1d0d75267dcae1f24ea7cc57b3a30f8ea09310772440f016c13e08b56b1196a687d6a5e5de864068f3fd936a361c5L
        self.key = int(FLAG.encode("hex"), 16)

    def sign(self, m):

        def bytes_to_long(b):
            return long(b.encode("hex"), 16)

        h = bytes_to_long(sha1(m).digest())
        u = bytes_to_long(Random.new().read(20))
        assert(bytes_to_long(m) % (self.q - 1) != 0)

        k = pow(self.gen, u * bytes_to_long(m), self.q)
        r = pow(self.gen, k, self.p) % self.q
        s = pow(k, self.q - 2, self.q) * (h + self.key * r) % self.q
        assert(s != 0)

        return r, s
