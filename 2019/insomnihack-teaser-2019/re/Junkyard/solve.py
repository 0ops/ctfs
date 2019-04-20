#!/usr/bin/env python
# coding=utf-8

from subprocess import check_output, CalledProcessError
from string import letters, digits
from itertools import product

cans = digits + letters
username = '73FF9B24EF8DE48C346D93FADCEE01151B0A1644BC81'

def check(s):
    try:
        res = check_output(['./junkyard-new', username, s])
    except CalledProcessError as e:
        res = e.output
    if not res:
        return '', 'error'
    tmp = res.split('\n')
    res, flag = tmp[1], tmp[2:]
    return res, flag

if __name__ == '__main__':
    for i,j in product(cans, repeat=2):
        if j is '0':
            print i
        password = i + '0'*41 + j
        res, flag = check(password)
        if not res.startswith('Maybe') and 'error' not in flag:
            print res
            print flag
            break
