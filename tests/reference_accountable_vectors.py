#!/usr/bin/env python3
# Copyright (c) 2026 Judica, Inc.
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Independent, variable-time public reference vectors; never use for signing."""

import hashlib
import json


P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3 * x * x) * pow(2 * y, -1, P) if a == b
             else (v - y) * pow(u - x, -1, P)) % P
    rx = (slope * slope - x - u) % P
    return rx, (slope * (x - rx) - y) % P


def mul(scalar, point=G):
    out = None
    while scalar:
        if scalar & 1:
            out = add(out, point)
        point = add(point, point)
        scalar >>= 1
    return out


def scalar_bytes(value):
    return value.to_bytes(32, "big")


def point_bytes(point):
    x, y = point
    return bytes([2 + (y & 1)]) + scalar_bytes(x)


def tagged_hash(tag, data):
    digest = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(digest + digest + data).digest()


def length_prefixed(data):
    return len(data).to_bytes(8, "big") + data


def vectors():
    q = 3
    key = mul(q)
    if key[1] & 1:
        q = N - q
        key = mul(q)
    r = 6
    host = bytes(range(32))
    slot = b"domain=7;epoch=13;slot=2"
    context = scalar_bytes(key[0]) + host + length_prefixed(slot)
    out = {
        "signing_key": scalar_bytes(key[0]).hex(),
        "host_commitment": host.hex(),
        "slot": slot.decode("ascii"),
        "nonce_input": tagged_hash("Purify/Accountable/Nonce/v1", context).hex(),
        "normalized_test_secret": scalar_bytes(q).hex(),
        "raw_test_nonce": scalar_bytes(r).hex(),
        "nonce_point": point_bytes(mul(r)).hex(),
        "statements": [],
    }
    for body in (b"accept:root-a", b"accept:root-b"):
        challenge = int.from_bytes(tagged_hash(
            "Purify/Accountable/Challenge/v1", context + length_prefixed(body)), "big") % N
        assert challenge != 0
        sigma = (r + challenge * q) % N
        assert add(mul(sigma), mul(N - challenge, key)) == mul(r)
        out["statements"].append({
            "body": body.decode("ascii"),
            "challenge": scalar_bytes(challenge).hex(),
            "sigma": scalar_bytes(sigma).hex(),
        })
    a, b = out["statements"]
    recovered = ((int(a["sigma"], 16) - int(b["sigma"], 16))
                 * pow(int(a["challenge"], 16) - int(b["challenge"], 16), -1, N)) % N
    assert recovered == q and mul(recovered) == key
    return out


if __name__ == "__main__":
    print(json.dumps(vectors(), indent=2))
