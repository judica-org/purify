#!/usr/bin/env python3
# Copyright (c) 2026 Judica, Inc.
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Independent public norm/IPA reference. Fixed test data; never use for secrets."""

import hashlib
import hmac
import json
from math import prod


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
    scalar %= N
    out = None
    while scalar:
        if scalar & 1:
            out = add(out, point)
        point = add(point, point)
        scalar >>= 1
    return out


def msm(points, scalars):
    assert len(points) == len(scalars)
    out = None
    for point, scalar in zip(points, scalars):
        out = add(out, mul(scalar, point))
    return out


def sb(value):
    return value.to_bytes(32, "big")


def size(value):
    return value.to_bytes(8, "little")


def pb(point):
    return bytes(33) if point is None else bytes([2 + (point[1] & 1)]) + sb(point[0])


def parse_point(encoded):
    assert len(encoded) == 33
    if encoded == bytes(33):
        return None
    assert encoded[0] in (2, 3)
    x = int.from_bytes(encoded[1:], "big")
    assert x < P
    y = pow((x**3 + 7) % P, (P + 1) // 4, P)
    assert y * y % P == (x**3 + 7) % P
    if (y & 1) != (encoded[0] & 1):
        y = P - y
    return x, y


def tagged_hash(tag, data):
    prefix = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(prefix + prefix + data).digest()


def challenge(tag, seed):
    for counter in range(256):
        candidate = int.from_bytes(tagged_hash(tag, seed + size(counter)), "big")
        if 0 < candidate < N:
            return candidate
    raise AssertionError("public test challenge exhausted")


def map_to_curve(t):
    # Independent affine form of the vendored Shallue--van de Woestijne map.
    c = -0xF5D2D456CAF80E20DCC88F3D586869D339E092EA25EB132B8272D850E32A03DD % P
    d = (c - 1) * pow(2, -1, P) % P
    w = c * t * pow(8 + t * t, -1, P) % P
    x1 = (d - t * w) % P
    candidates = (x1, -(x1 + 1) % P, (1 + pow(w * w, P - 2, P)) % P)
    for x in candidates:
        square = (x**3 + 7) % P
        y = pow(square, (P + 1) // 4, P)
        if y * y % P == square:
            return x, (-y if t & 1 else y) % P
    raise AssertionError("generator map has no curve point")


def generator_from_seed(seed):
    points = []
    for prefix in (b"1st generation: ", b"2nd generation: "):
        t = int.from_bytes(hashlib.sha256(prefix + seed).digest(), "big")
        assert t < P
        points.append(map_to_curve(t))
    return add(*points)


def generator_stream(count):
    def mac(key, value):
        return hmac.new(key, value, hashlib.sha256).digest()
    seed = sb(G[0]) + sb(G[1])
    key, value = bytes(32), bytes([1]) * 32
    for marker in (b"\0", b"\1"):
        key = mac(key, value + marker + seed)
        value = mac(key, value)
    result = []
    for index in range(count):
        if index:
            key = mac(key, value + b"\0")
            value = mac(key, value)
        value = mac(key, value)
        result.append(generator_from_seed(value))
    return result


def expand(term):
    scale, offset, factors = term
    coefficients = [scale]
    for factor in factors:
        coefficients += [coefficient * factor % N for coefficient in coefficients]
    return [0] * offset + coefficients


def coefficients(terms, dimension):
    out = [0] * dimension
    for term in terms:
        for i, coefficient in enumerate(expand(term)):
            out[i] = (out[i] + coefficient) % N
    return out


def evaluate(terms, x):
    result = 0
    for scale, offset, factors in terms:
        value = scale * pow(x, offset, N) % N
        for j, factor in enumerate(factors):
            value = value * (1 + factor * pow(x, 1 << j, N)) % N
        result = (result + value) % N
    return result


def norm_terms(g, h, rho, gammas, n, ell):
    return [(n * pow(rho, g - 1, N) % N, 0,
             [gamma * pow(pow(rho, 1 << j, N), -1, N) % N
              for j, gamma in enumerate(gammas)]),
            (ell, g, gammas[:h.bit_length() - 1])]


def dot(a, b):
    return sum(x * y for x, y in zip(a, b)) % N


def scalar_checks():
    for g, h in ((1, 1), (4, 2), (8, 8)):
        gammas = list(range(5, 5 + g.bit_length() - 1))
        terms = norm_terms(g, h, 3, gammas, 11, 17)
        actual = coefficients(terms, 2 * g)
        # Directly fold symbolic basis coordinates; no polynomial expansion.
        left = [[int(i == j) for i in range(2 * g)] for j in range(g)]
        right = [[int(i == g + j) for i in range(2 * g)] for j in range(h)]
        rho = 3
        for gamma in gammas:
            left = [[(rho * a + gamma * b) % N for a, b in zip(left[i], left[i + 1])]
                    for i in range(0, len(left), 2)]
            if len(right) > 1:
                right = [[(a + gamma * b) % N for a, b in zip(right[i], right[i + 1])]
                         for i in range(0, len(right), 2)]
            rho = rho * rho % N
        assert actual == [(11 * a + 17 * b) % N for a, b in zip(left[0], right[0])]
        for x in (7, 23):
            assert evaluate(terms, x) == sum(a * pow(x, i, N) for i, a in enumerate(actual)) % N

        # Scalar surrogates isolate shifted-c cancellation from curve arithmetic.
        c, base, hs = list(range(19, 19 + h)), 31, list(range(37, 37 + h))
        weights = actual[g:g + h]
        assert (dot(hs, weights) + base * dot(c, weights)) % N == dot(
            [(point + coefficient * base) % N for point, coefficient in zip(hs, c)], weights)

        a = list(range(2, 2 + 2 * g))
        b = [pow(7, i, N) for i in range(2 * g)]
        folding = []
        while len(a) > 1:
            half, t = len(a) // 2, 41 + len(folding)
            inverse = pow(t, -1, N)
            expected = (dot(a, b) + t * t * dot(a[:half], b[half:])
                        + inverse * inverse * dot(a[half:], b[:half])) % N
            a = [(t * x + inverse * y) % N for x, y in zip(a[:half], a[half:])]
            b = [(inverse * x + t * y) % N for x, y in zip(b[:half], b[half:])]
            assert dot(a, b) == expected
            folding.append(t)
        scale = pow(prod(folding) % N, -1, N)
        assert b[0] == evaluate([(scale, 0, [t * t % N for t in reversed(folding)])], 7)


def prepare_norm(g, c, rho, commitment, proof, generators):
    public = (sb(rho) + size(g) + size(g + len(c))
              + b"".join(pb(point) for point in generators[:g + len(c)])
              + size(len(c)) + b"".join(sb(value) for value in c))
    digest = tagged_hash("Purify/BPPP/NormArg/PublicDataV1", public)
    transcript = digest + commitment
    rounds = g.bit_length() - 1
    assert len(proof) == 65 * rounds + 64
    n, ell = (int.from_bytes(proof[-64:-32], "big"), int.from_bytes(proof[-32:], "big"))
    assert n < N and ell < N
    result = add(parse_point(commitment), mul(-n * n * pow(rho, 2 * g, N)))
    gammas = []
    for j in range(rounds):
        pair = proof[65 * j:65 * (j + 1)]
        assert pair[0] < 4
        transcript += pair
        gamma = int.from_bytes(tagged_hash(
            "Purify/BPPP/NormArg/TranscriptV1", transcript + size(0)), "big") % N
        gammas.append(gamma)
        for index, weight in ((0, gamma), (1, gamma * gamma - 1)):
            x = pair[1 + 32 * index:33 + 32 * index]
            sign = (pair[0] >> (1 - index)) & 1
            encoded = bytes([2 + sign]) + x if x != bytes(32) else bytes(33)
            assert x != bytes(32) or sign == 0
            result = add(result, mul(weight, parse_point(encoded)))
    return result, norm_terms(g, len(c), rho, gammas, n, ell)


def ipa_vector(g, c, domain, commitment, proof, rho=3):
    generators = generator_stream(2 * g)
    basis = generators[:]
    for i, coefficient in enumerate(c):
        basis[g + i] = add(basis[g + i], mul(coefficient))
    claim_point, terms = prepare_norm(g, c, rho, commitment, proof, generators)
    a = coefficients(terms, len(basis))
    assert msm(basis, a) == claim_point
    basis_digest = tagged_hash("Purify/BPPP/NormAccumBasisV1",
                              size(len(domain)) + domain + size(g) + size(len(c))
                              + b"".join(sb(value) for value in c)
                              + b"".join(pb(point) for point in basis))
    encoded = basis_digest + size(1) + pb(claim_point) + size(len(terms))
    for scale, offset, factors in terms:
        encoded += sb(scale) + size(offset) + size(len(factors)) + b"".join(map(sb, factors))
    claims_digest = tagged_hash("Purify/BPPP/AccumClaimsV1", encoded)
    beta = challenge("Purify/BPPP/AccumBatchV1", claims_digest)
    encoded = claims_digest + sb(beta) + pb(claim_point)
    x = challenge("Purify/BPPP/AccumEvaluationV1", encoded)
    y = evaluate(terms, x)
    encoded += sb(x) + sb(y)
    opening_seed = tagged_hash("Purify/BPPP/AccumOpeningBaseV1", encoded)
    opening_base = generator_from_seed(tagged_hash("Purify/BPPP/PublicHashToPointV1", opening_seed))
    transcript = tagged_hash("Purify/BPPP/AccumOpeningV1", encoded + pb(opening_base))
    b = [pow(x, i, N) for i in range(len(basis))]
    running = add(claim_point, mul(y, opening_base))
    points = basis[:]
    lefts, rights, ts = [], [], []
    while len(a) > 1:
        half = len(a) // 2
        left = add(msm(points[half:], a[:half]), mul(dot(a[:half], b[half:]), opening_base))
        right = add(msm(points[:half], a[half:]), mul(dot(a[half:], b[:half]), opening_base))
        message = transcript + size(len(ts)) + pb(left) + pb(right)
        t = challenge("Purify/BPPP/AccumRoundV1", message)
        transcript = tagged_hash("Purify/BPPP/AccumRoundV1", message + sb(t))
        inverse = pow(t, -1, N)
        running = add(running, add(mul(t * t, left), mul(inverse * inverse, right)))
        a = [(t * u + inverse * v) % N for u, v in zip(a[:half], a[half:])]
        b = [(inverse * u + t * v) % N for u, v in zip(b[:half], b[half:])]
        points = [add(mul(inverse, u), mul(t, v)) for u, v in zip(points[:half], points[half:])]
        assert running == add(msm(points, a), mul(dot(a, b), opening_base))
        lefts.append(pb(left))
        rights.append(pb(right))
        ts.append(t)
    folded = (pow(prod(ts) % N, -1, N), 0, [t * t % N for t in reversed(ts)])
    assert b[0] == evaluate([folded], x)
    assert msm(basis, coefficients([folded], len(basis))) == points[0]
    # Version-one wire format: interleaved L/R, terminal scalar, folded point.
    step_bytes = b"\x01" + b"".join(left + right for left, right in zip(lefts, rights))
    step_bytes += sb(a[0]) + pb(points[0])
    return {
        "basis_digest": basis_digest.hex(), "claim_point": pb(claim_point).hex(),
        "beta": sb(beta).hex(), "x": sb(x).hex(), "y": sb(y).hex(),
        "opening_base": pb(opening_base).hex(),
        "terminal_scalar": sb(a[0]).hex(), "folded_generator": pb(points[0]).hex(),
        "step_sha256": hashlib.sha256(step_bytes).hexdigest(),
    }


def vectors():
    scalar_checks()
    # Honest standalone norm fixture from the native prover, with public test
    # witnesses n=[2,3,4,5], l=[10,11]. Everything after this proof is recomputed
    # independently using Python integers, hashlib and affine curve arithmetic.
    commitment = bytes.fromhex(
        "02c6e44e644b013e4574def123222a542c5459e4d5a42c51727bf37743409e8ea6")
    proof = bytes.fromhex(
        "02455da6692ecfb83ac85be46193da97399d1ca4199477de1206ac95b0c873c6d47ad"
        "350585e50be5a8928aa48f1113c6c04ab4e70e7f195bef533da316c2d3b6b007b987e"
        "2cf042f59215e4537f49bf5f670c3157dfa1e027bd7e79f9698ce7ac14c1fb376979f"
        "483cbe0f2420967814c7b4c9802f9bf4bf88b4e510f98dee9de5e096d770b9ebccd6"
        "742c508ca59f717184e9635d76f682f614acfa3e76f31c5850ce30cfc56b5b92109e6"
        "b935c423c0bdf728d73d3b991de6839b6fecace33c0e")
    result = ipa_vector(4, [20, 21], b"honest-test", commitment, proof)
    # These independently reproduced values also bind the fixture to the native
    # generator stream, transcript serialization and actual IPA point folds.
    assert result["basis_digest"] == "f1063d8f343ffc9ff8b39722d5d575298468b947049062a791548cd1e4422502"
    assert result["claim_point"] == "03a2e9b0d2f70839be9e427036160c45f18531b8111e5ee1a994a8d3d4af95d4df"
    assert result["terminal_scalar"] == "a1584786c72756ac7e1f91a2cf5997c99a778aa93ff82d1ecedfaa71b38586b0"
    assert result["folded_generator"] == "027804f7f8a1cdd10b0c1537f3162532b430f3fdbf66212fb22db2c1315ed4656d"
    assert result["step_sha256"] == "662b6b3d9dd73e60a8ab438e184c83844db9a1b7affecb20128f57b33f75add5"
    return result


if __name__ == "__main__":
    print(json.dumps(vectors(), indent=2))
