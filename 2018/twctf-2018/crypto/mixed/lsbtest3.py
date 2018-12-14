#!/usr/bin/python3

def parity_oracle(n, query):
    """input: n: the modulus of the RSA
    query: query is a function which inputs an int i, returns if the m*(2^i)%n is odd
    return: int m
    """
    i = 0
    x = 0
    while n >> i:
        res = query(i+1)
        if res:
            x = 2 * x + 1
        else:
            x = 2 * x
        i += 1
    return (x+1) * n // 2 ** i

if __name__ == "__main__":
    from Crypto.PublicKey import RSA
    from Crypto.Util import number
    key = RSA.generate(2048)
    n = key.n
    m = number.getRandomRange(0, n)
    print(m)
    m2 = parity_oracle(n, lambda x: (pow(2, x, n) * m % n) & 1)
    print(m2)
    print(m2 == m)