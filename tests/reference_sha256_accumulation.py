#!/usr/bin/env python3
# Copyright (c) 2026 Judica, Inc.
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Independent complete-context vectors for SHA-256 accumulation V2."""

import hashlib
import json
from pathlib import Path

from reference_norm_accumulation import (
    N, add, coefficients, dot, encode_polynomial, evaluate, generator_from_seed,
    generator_stream, msm, mul, pb, prepare_norm, sb, size, tagged_hash,
)
from reference_sha256_transcript import Sha256Transcript


STEP_DOMAIN = b"Purify/BPPP/CandidateAccumStep/v1"
NORM_DOMAIN = b"Purify/BPPP/CandidateNormReduction/v2"
PAIR_TAG = "Purify/BPPP/OpeningGeneratorPairV2"
PUBLIC_POINT_TAG = "Purify/BPPP/PublicHashToPointV1"


def append_point(transcript, point):
    encoded = pb(point)
    transcript.append_point(encoded[0], int.from_bytes(encoded[1:], "big"))


def append_polynomial(transcript, polynomial):
    transcript.append_u64(len(polynomial))
    for scale, offset, factors in polynomial:
        transcript.append_scalar(scale)
        transcript.append_u64(offset)
        transcript.append_u64(len(factors))
        for factor in factors:
            transcript.append_scalar(factor)


def opening_pair(basis_digest, role):
    pair = []
    for index in range(2):
        message = basis_digest + role.to_bytes(8, "little") + bytes([index])
        seed = tagged_hash(PAIR_TAG, message)
        public_seed = tagged_hash(PUBLIC_POINT_TAG, seed)
        pair.append(generator_from_seed(public_seed))
    assert pair[0] is not None and pair[1] is not None and pair[0] != pair[1]
    return pair


def opening_base(transcript, basis_digest, role):
    _, scalar = transcript.opening(basis_digest, role)
    pair = opening_pair(basis_digest, role)
    point = add(pair[0], mul(scalar, pair[1]))
    assert point is not None
    return scalar, pair, point


def run_ipa(basis, a, b, opening, transcript, first_round):
    original_b = b[:]
    points = basis[:]
    lefts, rights, challenges = [], [], []
    while len(a) > 1:
        half = len(a) // 2
        left = add(msm(points[half:], a[:half]),
                   mul(dot(a[:half], b[half:]), opening))
        right = add(msm(points[:half], a[half:]),
                    mul(dot(a[half:], b[:half]), opening))
        append_point(transcript, left)
        append_point(transcript, right)
        _, challenge = transcript.challenge(first_round + len(challenges))
        inverse = pow(challenge, -1, N)
        a = [(challenge * u + inverse * v) % N
             for u, v in zip(a[:half], a[half:])]
        b = [(inverse * u + challenge * v) % N
             for u, v in zip(b[:half], b[half:])]
        points = [add(mul(inverse, u), mul(challenge, v))
                  for u, v in zip(points[:half], points[half:])]
        lefts.append(left)
        rights.append(right)
        challenges.append(challenge)

    scale = 1
    for challenge in challenges:
        scale = scale * pow(challenge, -1, N) % N
    folded = (scale, 0, [challenge * challenge % N
                         for challenge in reversed(challenges)])
    assert b[0] == dot(original_b, coefficients([folded], len(basis)))
    assert points[0] == msm(basis, coefficients([folded], len(basis)))
    proof = (b"".join(pb(left) + pb(right)
                      for left, right in zip(lefts, rights))
             + sb(a[0]) + pb(points[0]))
    return {
        "left": lefts, "right": rights, "challenge": challenges,
        "terminal": a[0], "folded_point": points[0],
        "folded": folded, "proof": proof,
    }


def fixture():
    g, h = 4, 2
    c = [20, 21]
    rho = 3
    prepared_binding = 23
    domain = b"honest-test"
    commitment = bytes.fromhex(
        "02c6e44e644b013e4574def123222a542c5459e4d5a42c51727bf37743409e8ea6")
    proof = bytes.fromhex(
        "02455da6692ecfb83ac85be46193da97399d1ca4199477de1206ac95b0c873c6d47ad"
        "350585e50be5a8928aa48f1113c6c04ab4e70e7f195bef533da316c2d3b6b007b987e"
        "2cf042f59215e4537f49bf5f670c3157dfa1e027bd7e79f9698ce7ac14c1fb376979f"
        "483cbe0f2420967814c7b4c9802f9bf4bf88b4e510f98dee9de5e096d770b9ebccd6"
        "742c508ca59f717184e9635d76f682f614acfa3e76f31c5850ce30cfc56b5b92109e6"
        "b935c423c0bdf728d73d3b991de6839b6fecace33c0e")
    basis = generator_stream(2 * g)
    basis_digest = tagged_hash(
        "Purify/BPPP/NormAccumBasisV2",
        size(len(domain)) + domain + size(g) + size(h)
        + b"".join(pb(point) for point in basis))
    residual, norm_polynomial = prepare_norm(
        g, c, rho, commitment, proof, basis)
    coefficient_commitment = msm(basis[g:g + h], c)
    weights = [(1, 0, norm_polynomial[1][2])]
    expanded_weights = coefficients(weights, h)
    evaluation = dot(c, expanded_weights)
    norm_transcript = Sha256Transcript()
    norm_transcript.append_bytes(NORM_DOMAIN)
    norm_transcript.append_bytes(basis_digest)
    norm_transcript.append_u64(h.bit_length() - 1)
    norm_transcript.append_scalar(prepared_binding)
    append_point(norm_transcript, coefficient_commitment)
    append_polynomial(norm_transcript, weights)
    norm_transcript.append_scalar(evaluation)
    norm_u, norm_pair, norm_opening = opening_base(
        norm_transcript, basis_digest, 1)
    append_point(norm_transcript, norm_opening)
    reduction = run_ipa(
        basis[g:g + h], c[:], expanded_weights, norm_opening,
        norm_transcript, 0)
    folded_h = (reduction["folded"][0], g, reduction["folded"][2])
    norm_point = add(residual,
                     mul(-norm_polynomial[1][0] * evaluation))
    assert norm_point == msm(basis, coefficients(norm_polynomial, 2 * g))
    norm_transcript.append_scalar(reduction["terminal"])
    append_point(norm_transcript, reduction["folded_point"])
    append_point(norm_transcript, norm_point)
    append_polynomial(norm_transcript, norm_polynomial)
    append_polynomial(norm_transcript, [folded_h])
    _, chi = norm_transcript.challenge(h.bit_length() - 1)
    claim_point = add(norm_point, mul(chi, reduction["folded_point"]))
    claim_polynomial = norm_polynomial + [(
        chi * folded_h[0] % N, g, folded_h[2])]
    assert claim_point == msm(basis, coefficients(claim_polynomial, 2 * g))

    step_transcript = Sha256Transcript()
    step_transcript.append_bytes(STEP_DOMAIN)
    step_transcript.append_bytes(basis_digest)
    step_transcript.append_u64((2 * g).bit_length() - 1)
    step_transcript.append_u64(1)
    append_point(step_transcript, claim_point)
    append_polynomial(step_transcript, claim_polynomial)
    _, beta = step_transcript.challenge(0)
    append_point(step_transcript, claim_point)
    _, x = step_transcript.challenge(1)
    y = evaluate(claim_polynomial, x)
    step_transcript.append_scalar(y)
    step_u, step_pair, step_opening = opening_base(
        step_transcript, basis_digest, 2)
    append_point(step_transcript, step_opening)
    step = run_ipa(
        basis, coefficients(claim_polynomial, 2 * g),
        [pow(x, i, N) for i in range(2 * g)], step_opening,
        step_transcript, 2)

    point = lambda value: pb(value).hex()
    scalar = lambda value: sb(value).hex()
    return {
        "basis_digest": basis_digest.hex(),
        "prepared_binding": scalar(prepared_binding),
        "coefficient_commitment": point(coefficient_commitment),
        "coefficient_evaluation": scalar(evaluation),
        "norm_weights": encode_polynomial(weights).hex(),
        "norm_opening_scalar": scalar(norm_u),
        "norm_opening_pair": [point(value) for value in norm_pair],
        "norm_opening": point(norm_opening),
        "norm_round_left": [point(value) for value in reduction["left"]],
        "norm_round_right": [point(value) for value in reduction["right"]],
        "norm_round_challenge": [scalar(value)
                                 for value in reduction["challenge"]],
        "norm_terminal": scalar(reduction["terminal"]),
        "norm_folded_generator": point(reduction["folded_point"]),
        "norm_point": point(norm_point),
        "norm_polynomial": encode_polynomial(norm_polynomial).hex(),
        "folded_polynomial": encode_polynomial([folded_h]).hex(),
        "fusion_challenge": scalar(chi),
        "claim_point": point(claim_point),
        "claim_polynomial": encode_polynomial(claim_polynomial).hex(),
        "reduction_sha256": hashlib.sha256(
            b"\x02" + sb(evaluation) + reduction["proof"]).hexdigest(),
        "step_beta": scalar(beta),
        "step_x": scalar(x),
        "step_y": scalar(y),
        "step_opening_scalar": scalar(step_u),
        "step_opening_pair": [point(value) for value in step_pair],
        "step_opening": point(step_opening),
        "step_round_left": [point(value) for value in step["left"]],
        "step_round_right": [point(value) for value in step["right"]],
        "step_round_challenge": [scalar(value)
                                 for value in step["challenge"]],
        "step_terminal": scalar(step["terminal"]),
        "step_folded_generator": point(step["folded_point"]),
        "step_sha256": hashlib.sha256(b"\x02" + step["proof"]).hexdigest(),
    }


def check_vector():
    path = (Path(__file__).parents[1] / "rust" / "receipt-cycle"
            / "tests" / "vectors" / "sha256_accumulation_v2.json")
    assert json.loads(path.read_text(encoding="ascii")) == fixture()


if __name__ == "__main__":
    check_vector()
    print("SHA-256 accumulation V2 vector: ok")
