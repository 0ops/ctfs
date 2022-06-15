from hashlib import sha256

#################################################################################
# https://github.com/michaelhly/solana-py/blob/master/src/solana/publickey.py
#
# The MIT License (MIT)

# Copyright (C) 2020 Michael Huang

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from typing import Any, List, Optional, Tuple, Union

class OnCurveException(Exception):
    """Raise when generated address is on the curve."""
class KeyError(Exception):
    """Couldn't fine nonce"""

def create_program_address(seeds: List[bytes], program_id: bytes) -> bytes:
    """Derive a program address from seeds and a program ID.
    Returns:
        The derived program address.
    """
    buffer = b"".join(seeds + [bytes(program_id), b"ProgramDerivedAddress"])
    hashbytes: bytes = sha256(buffer).digest()
    if not is_on_curve(hashbytes):
        return hashbytes
    raise OnCurveException("Invalid seeds, address must fall off the curve")

def find_program_address(seeds: List[bytes], program_id: bytes) -> Tuple[bytes, int]:
    """Find a valid program address.
    Valid program addresses must fall off the ed25519 curve.  This function
    iterates a nonce until it finds one that when combined with the seeds
    results in a valid program address.
    Returns:
        The program address and nonce used.
    """
    nonce = 255
    while nonce != 0:
        try:
            buffer = seeds + [nonce.to_bytes(1, byteorder="little")]
            address = create_program_address(buffer, program_id)
        except OnCurveException:
            nonce -= 1
            continue
        return address, nonce
    raise KeyError("Unable to find a viable program address nonce")

#################################################################################

"""Curve25519/ed25519 helpers.

Sourced from https://github.com/warner/python-pure25519/blob/master/pure25519/basic.py
"""
# "python-pure25519" Copyright (c) 2015 Brian Warner and other contributors

# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

Q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, Q - 2, Q)


d = -121665 * _inv(121666)
I = pow(2, (Q - 1) // 4, Q)  # noqa: E741


def _xrecover(y):
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q != 0:
        x = (x * I) % Q
    if x % 2 != 0:
        x = Q - x
    return x


def _isoncurve(P):
    x = P[0]
    y = P[1]
    return (-x * x + y * y - 1 - d * x * x * y * y) % Q == 0


class NotOnCurve(Exception):
    """Raised when point fall off the curve."""


def _decodepoint(unclamped: int):
    clamp = (1 << 255) - 1
    y = unclamped & clamp  # clear MSB
    x = _xrecover(y)
    if bool(x & 1) != bool(unclamped & (1 << 255)):
        x = Q - x
    P = [x, y]
    if not _isoncurve(P):
        raise NotOnCurve("decoding point that is not on curve")
    return P


def is_on_curve(s: bytes) -> bool:
    """Verify the bytes s is a valid point on curve or not."""
    unclamped = int.from_bytes(s, byteorder="little")
    try:
        _ = _decodepoint(unclamped)
    except NotOnCurve:
        return False
    else:
        return True