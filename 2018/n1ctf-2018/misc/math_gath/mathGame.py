#!/usr/bin/env python
# coding=utf-8

from pwn import *
from math import sqrt
from itertools import count, islice

import primefac
import hashlib
import re
import sys, os

DEBUG = False
STEP = 5000
fuck = min
author = "izhuer"

def isPrime(n):
    return n > 1 and all(n%i for i in islice(count(2), int(sqrt(n)-1)))

def get_column(data, idx):
    res = []
    for i in xrange(7):
        res.append(data[i][idx])
    return res


def check(data, f):
    # make sure every number is unique
    help = []
    nums = []

    for i in xrange(6):
        for j in xrange(7):
            for k in xrange(7):
                if data[i][j][k] in help and (j not in [0, 6] and k not in [0, 6]):
                    print 'FAIL!!! with %d' % data[i][j][k]
                    exit()
                if data[i][j][k] not in help:
                    help.append(data[i][j][k])
                if f(data[i][j][k]):
                    if data[i][j][k] not in nums:
                        nums.append(data[i][j][k])
    assert len(nums) == 7, 'FAIL!!! with {}'.format(nums)
    print 'SUCCESS in ASSUMPTION! (EVERY NUMBER IS UNIQUE)'
    print '%d numbers' % len(help)


def find_points(data, f):
    check(data, f)

    # make vectors to help analysis
    vecs = {}
    for i in xrange(6):
        face = data[i]
        vecs[(face[0][0], face[0][6])] = face[0][:]
        vecs[(face[0][6], face[0][0])] = face[0][::-1]
        vecs[(face[6][0], face[6][6])] = face[6][:]
        vecs[(face[6][6], face[6][0])] = face[6][::-1]
        vecs[(face[0][0], face[6][0])] = get_column(face, 0)
        vecs[(face[6][0], face[0][0])] = get_column(face, 0)[::-1]
        vecs[(face[0][6], face[6][6])] = get_column(face, 6)
        vecs[(face[6][6], face[0][6])] = get_column(face, 6)[::-1]

    points_to = {}
    for (i, j) in vecs:
        if i not in points_to:
            points_to[i] = [j]
        elif j not in points_to[i]:
            points_to[i].append(j)

    for i in points_to:
        assert len(points_to[i]) == 3, "{} with {}".format(i, points_to[i])

    # Find 8 vertexs
    cubes = {}
    re_cubes = {}
    appeared = []
    # A
    for i in [0, 6]:
        for j in [0, 6]:
            re_cubes[data[0][i][j]] = (j, 6 - i, 0)
            cubes[(j, 6 - i, 0)] = data[0][i][j]
            appeared.append(data[0][i][j])
    for i in [0, 6]:
        for j in [0, 6]:
            nums = filter(lambda x: x not in appeared, points_to[data[0][i][j]])
            assert len(nums) == 1
            re_cubes[nums[0]] = (j, 6 - i, 6)
            cubes[(j, 6 - i, 6)] = nums[0]
    log.info("FINISH VERTEX STAGE")

    # Find 12 edges
    for i in [0, 6]:
        for j in [0, 6]:
            for k in [0, 6]:
                p = cubes[(i, j, k)]
                pi = cubes[((6 - i), j, k)]
                pj = cubes[(i, (6 - j), k)]
                pk = cubes[(i, j, (6 - k))]
                # pi
                vec = vecs[(p, pi)] if i == 0 else vecs[(pi, p)]
                for l in xrange(7):
                    if cubes.has_key((l, j, k)):
                        tmp = cubes[(l, j, k)]
                        assert tmp == vec[l], "%d with %d" % (tmp, vec[l])
                    else:
                        cubes[(l, j, k)] = vec[l]
                        re_cubes[vec[l]] = (l, j, k)
                # pj
                vec = vecs[(p, pj)] if j == 0 else vecs[(pj, p)]
                for l in xrange(7):
                    if cubes.has_key((i, l, k)):
                        tmp = cubes[(i, l, k)]
                        assert tmp == vec[l], "%d wjth %d" % (tmp, vec[l])
                    else:
                        cubes[(i, l, k)] = vec[l]
                        re_cubes[vec[l]] = (i, l, k)
                # pk
                vec = vecs[(p, pk)] if k == 0 else vecs[(pk, p)]
                for l in xrange(7):
                    if cubes.has_key((i, j, l)):
                        tmp = cubes[(i, j, l)]
                        assert tmp == vec[l], "%d wjth %d" % (tmp, vec[l])
                    else:
                        cubes[(i, j, l)] = vec[l]
                        re_cubes[vec[l]] = (i, j, l)
    log.info('FINISH EDGES')

    # for i in [0, 6]:
    #     for j in [0, 6]:
    #         print [cubes[i, j, k] for k in xrange(7)]
    #         print [cubes[j, k, i] for k in xrange(7)]
    #         print [cubes[k, i, j] for k in xrange(7)]


    points = []
    for k in xrange(6):
        for i in xrange(7):
            for j in xrange(7):
                if not f(data[k][i][j]):
                    continue
                if re_cubes.has_key(data[k][i][j]):
                    if re_cubes[data[k][i][j]] not in points:
                        out = re_cubes[data[k][i][j]]
                        print data[k][i][j], out
                        points.append(re_cubes[data[k][i][j]])
                    continue
                pa = re_cubes[data[k][0][j]]
                pb = re_cubes[data[k][6][j]]
                pp = float(i) / float(6 - i)
                out = [0, 0, 0]
                for l in xrange(3):
                    out[l] = (pa[l] + pb[l] * pp) / (1 + pp)
                    assert abs(out[l] - int(out[l])) < 0.0001, "Wrong %10f" % out[l]
                if (out[0], out[1], out[2]) not in points:
                    out = map(lambda x: int(x), out)
                    print data[k][i][j], out
                    points.append((out[0], out[1], out[2]))
    assert len(points) == 7, "{}".format(points)
    log.info("FIND ALL TARGETS")
    return points


def get_lines(points):
    lines = []
    for i in xrange(len(points)):
        for j in xrange(i + 1, len(points)):
            p1 = points[i]
            p2 = points[j]
            line = {}
            line['vec'] = (p2[0] - p1[0], p2[1] - p1[1], p2[2] - p1[2])
            line['p1'] = map(lambda x: x + 0.5, p1)
            line['p2'] = map(lambda x: x + 0.5, p2)
            lines.append(line)
    return lines

def get3(p1, p2, a, i):
    k = float(a - p1[i]) / float(p2[i] - p1[i])
    x = k * float(p2[0] - p1[0]) + p1[0]
    y = k * float(p2[1] - p1[1]) + p1[1]
    z = k * float(p2[2] - p1[2]) + p1[2]
    return (int(x), int(y), int(z))

def resolve(vec, l):
    if vec[0] != 0:
        points = map(lambda x: get3(l['p1'], l['p2'], float(x) / STEP, 0), xrange(-10, 7 * STEP + 10))
    elif vec[1] != 0:
        points = map(lambda y: get3(l['p1'], l['p2'], float(y) / STEP, 1), xrange(-10, 7 * STEP + 10))
    else:
        assert vec[2] != 0
        points = map(lambda z: get3(l['p1'], l['p2'], float(z) / STEP, 2), xrange(-10, 7 * STEP + 10))

    return list(set(points))

def find_point(lines):
    res = None
    for i in xrange(len(lines)):
        for j in xrange(i + 1, len(lines)):
            l1 = lines[i]
            l2 = lines[j]
            vec1 = l1['vec']
            vec2 = l2['vec']
            if vec1[0] * vec2[0] + vec1[1] * vec2[1] + vec1[2] * vec2[2] == 0 and len([p for p in [l1['p1'], l1['p2']] if p in [l2['p1'], l2['p2']]]) == 0:
                points1 = resolve(vec1, l1)
                points2 = resolve(vec2, l2)
                victim = [v for v in points1 if v in points2]
                if len(victim) >= 1:
                    if 6 not in victim[0] and 0 not in victim[0]:
                        print victim
                        assert res is None or res == fuck(victim)
                        res = fuck(victim)
    return res


def handle(f, debug = DEBUG):
    odata = []

    if debug:
        indata = file('debug.txt').read()
    else:
        semicolon = "Please enter the coordinates of the answer:\n"
        indata = r.recvuntil(semicolon)
        # f_ = file('debug.txt', 'w')
        # f_.write(indata)
        # f_.close()
    prog = re.compile('\|\d*\|\d*\|\d*\|\d*\|\d*\|\d*\|\d*\|')
    lines = prog.findall(indata)
    for i in xrange(6):
        surface = []
        for j in xrange(7):
            line = lines[i * 7 + j].strip('|')
            surface.append(map(lambda x: int(x), line.split('|')))
        odata.append(surface)

    points = find_points(odata, f)
    lines = get_lines(points)
    point = find_point(lines)
    log.info("FIND {}".format(point))
    return point


if __name__ == '__main__':
    while True:
        try:
            if not DEBUG:
                r = remote('47.98.54.1', 11011)
                line = r.recvline()
                while '== True' not in line:
                    line = r.recvline()

                data = line.split('"')
                prefix = data[1].strip()
                log.info('Prefix is %s' % prefix)
                sha256_prefix = data[3]
                log.info('Sha256 prefix is %s' % sha256_prefix)

                for i in xrange(0x1000000):
                    test = prefix + hex(i)[2:]
                    if hashlib.sha256(test).hexdigest().startswith(sha256_prefix):
                        break

                log.info('Get %s with %s' % (test, hashlib.sha256(test).hexdigest()))
                r.recv()
                r.sendline(hex(i)[2:])


                context.log_level = 'debug'

            ## Part One
            log.info('GOURN 1')
            STEP = 10000
            fuck = max
            point = handle(lambda x: x % 2 == 0)
            if not DEBUG:
                r.sendline('%d' % point[0])
                r.sendline('%d' % point[1])
                r.sendline('%d' % point[2])
            print "ROUND 1 DONE"

            # Part Two
            STEP = 15000
            fuck = min
            log.info('GOURN 2')
            point = handle(lambda x: x % 2 == 1)
            if not DEBUG:
                r.sendline('%d' % point[0])
                r.sendline('%d' % point[1])
                r.sendline('%d' % point[2])
            print "ROUND 2 DONE"

            # Part Three
            STEP = 10000
            fuck = min
            log.info('GOURN 3')
            point = handle(lambda x: isPrime(x))
            if not DEBUG:
                r.sendline('%d' % point[0])
                r.sendline('%d' % point[1])
                r.sendline('%d' % point[2])
            print "ROUND 3 DONE"

            # Part Four
            log.info('GOURN 4')
            point = handle(lambda x: not isPrime(x))
            if not DEBUG:
                r.sendline('%d' % point[0])
                r.sendline('%d' % point[1])
                r.sendline('%d' % point[2])
            print "ROUND 4 DONE"

            # Part Four
            log.info('GOURN 5')
            point = handle(lambda x: len(primefac.factorint(x)) == 3)
            # point = handle(lambda x: reduce(lambda a,b: a+b, primefac.factorint(x).values()) == 3)
            if not DEBUG:
                r.sendline('%d' % point[0])
                r.sendline('%d' % point[1])
                r.sendline('%d' % point[2])
            print "ROUND 5 DONE"

            r.interactive()
        except Exception, e:
            print 'FUCK!!! {}'.format(e)
            r.close()
        else:
            r.interactive()
