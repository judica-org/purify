#!/usr/bin/env python3
# Copyright (c) 2026 Judica, Inc.
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Independent public BIP327 key-aggregation vectors; never use for signing."""

import json

from reference_accountable_vectors import N, add, mul, point_bytes, scalar_bytes, tagged_hash


def roster_vector(scalars):
    points = [mul(secret) for secret in scalars]
    keys = [point_bytes(point) for point in points]
    digest = tagged_hash("KeyAgg list", b"".join(keys))
    coefficients = [
        1 if i == 1 else int.from_bytes(tagged_hash(
            "KeyAgg coefficient", digest + key), "big") % N
        for i, key in enumerate(keys)
    ]
    assert all(coefficients)
    aggregate = None
    for coefficient, point in zip(coefficients, points):
        aggregate = add(aggregate, mul(coefficient, point))
    negated = bool(aggregate[1] & 1)
    if negated:
        coefficients = [(N - coefficient) % N for coefficient in coefficients]
    normalized_secret = sum(a * secret for a, secret in zip(coefficients, scalars)) % N
    assert point_bytes(mul(normalized_secret)) == b"\x02" + scalar_bytes(aggregate[0])
    return {
        "member_keys": [key.hex() for key in keys],
        "key_list_hash": digest.hex(),
        "effective_coefficients": [scalar_bytes(value).hex() for value in coefficients],
        "aggregate_was_negated": negated,
        "signing_key": scalar_bytes(aggregate[0]).hex(),
        "normalized_test_secret": scalar_bytes(normalized_secret).hex(),
    }


if __name__ == "__main__":
    print(json.dumps([roster_vector(keys) for keys in ([3], [3, 6], [3, 6, 8])], indent=2))
