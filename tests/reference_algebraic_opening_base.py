#!/usr/bin/env python3
"""Independent reference for the candidate opening-generator pair."""

import hashlib
from pathlib import Path


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
NEG_C = 0xF5D2D456CAF80E20DCC88F3D586869D339E092EA25EB132B8272D850E32A03DD
D = 0x851695D49A83F8EF919BB86153CBCB16630FB68AED0A766A3EC693D68E6AFA40
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PAIR_TAG = b"Purify/BPPP/OpeningGeneratorPairV2"
PUBLIC_TAG = b"Purify/BPPP/PublicHashToPointV1"


def inverse_or_zero(value):
    return 0 if value == 0 else pow(value, P - 2, P)


def map_to_curve(value):
    value_squared = value * value % P
    wd = (value_squared + 8) % P
    x3d = -3 * value_squared % P
    joint_inverse = inverse_or_zero(wd * x3d % P)
    x1 = (D + NEG_C * value_squared * x3d * joint_inverse) % P
    candidates = (
        x1,
        -(x1 + 1) % P,
        (1 + wd * wd * wd * joint_inverse) % P,
    )
    for x in candidates:
        square = (x * x * x + 7) % P
        y = pow(square, (P + 1) // 4, P)
        if y * y % P == square:
            return x, -y % P if value & 1 else y
    raise AssertionError("SvdW map did not select a curve point")


def add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    if left[0] == right[0]:
        if (left[1] + right[1]) % P == 0:
            return None
        slope = 3 * left[0] * left[0] * pow(2 * left[1], P - 2, P)
    else:
        slope = (right[1] - left[1]) * pow(right[0] - left[0], P - 2, P)
    slope %= P
    x = (slope * slope - left[0] - right[0]) % P
    y = (slope * (left[0] - x) - left[1]) % P
    return x, y


def multiply(point, scalar):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        scalar >>= 1
    return result


def tagged_hash(tag, message):
    tag_hash = hashlib.sha256(tag).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def public_hash_to_point(message):
    key = tagged_hash(PUBLIC_TAG, message)
    points = []
    for prefix in (b"1st generation: ", b"2nd generation: "):
        value = int.from_bytes(hashlib.sha256(prefix + key).digest(), "big")
        assert value < P
        points.append(map_to_curve(value))
    return add(*points)


def opening_pair(basis_digest, role):
    points = []
    for index in range(2):
        message = basis_digest + role.to_bytes(8, "little") + bytes([index])
        seed = tagged_hash(PAIR_TAG, message)
        points.append(public_hash_to_point(seed))
    assert points[0] is not None and points[1] is not None
    assert points[0] != points[1]
    return points


def compressed(point):
    if point is None:
        return bytes(33)
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def check_vectors():
    path = (
        Path(__file__).parents[1]
        / "rust"
        / "receipt-cycle"
        / "tests"
        / "vectors"
        / "opening_base_pair.txt"
    )
    checked = 0
    for line in path.read_text(encoding="ascii").splitlines():
        if not line.startswith("vector "):
            continue
        words = line.split()
        assert len(words) == 9
        _, digest, role, scalar, first, second, expected_point, expected_y, marker = words
        assert marker == "ok"
        pair = opening_pair(bytes.fromhex(digest), int(role))
        assert compressed(pair[0]).hex() == first
        assert compressed(pair[1]).hex() == second
        scalar = int(scalar, 16)
        assert 0 < scalar < ORDER
        point = add(pair[0], multiply(pair[1], scalar))
        assert point is not None
        assert compressed(point).hex() == expected_point
        assert point[1].to_bytes(32, "big").hex() == expected_y
        checked += 1
    assert checked == 3


if __name__ == "__main__":
    check_vectors()
    print("algebraic opening-base vectors: ok")
