#!/usr/bin/env sage
# coding=utf-8

import pickle

r = Zmod(2)
equations = []
result = []

def bitvector_from_bytes(bs):
    tmp = Integer(bs.encode('hex'), 16).bits()
    tmp += [0] * (len(bs)*8-len(tmp))
    tmp.reverse()
    return vector(r, tmp)

def parse_ctext(ctext):
    # transposition
    c = bitvector_from_bytes(ctext[-6:])
    m = matrix([bitvector_from_bytes(ctext[i:i+6]) for i in xrange(0, len(ctext)-6, 6)])
    return m, c

def get_equations(s):
    global equations
    global result
    m, p, c = s
    mc = m.columns()
    for i in xrange(0, len(mc), 3):
        equations.append(mc[i]+mc[i+1]+mc[i+2])
        result.append(c[i]+c[i+1]+c[i+2]-p[i]-p[i+1]-p[i+2]+1)

if __name__ == '__main__':
    '''
    data = []
    print 'start'
    for i in xrange(1536):
        if i % 10 == 0:
            print i
        with open('data/ciphertext_{:03d}'.format(i)) as f:
            test1 = f.read()
        m, c = parse_ctext(test1)
        with open('data/plaintext_{:03d}'.format(i)) as f:
            test2 = f.read()
        p = bitvector_from_bytes(test2)
        p = vector(sum([[i,i,i] for i in p], []))
        data.append((m, p, c))
    print 'data finish'
    with open('mpc_data', 'wb') as f:
        pickle.dump(data, f)
    '''
    with open('mpc_data', 'rb') as f:
        data = pickle.load(f)
    for i in xrange(0, 1536):
        get_equations(data[i])
        equations_matrix = matrix(equations)
        rank = equations_matrix.rank()
        print i, rank
        if rank >= 48:
            result_vector = vector(r, result)
            key = equations_matrix.solve_right(result_vector)
            key_val = int(''.join(map(str, key)), 2)
            print key_val
            break
