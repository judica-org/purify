#!/usr/bin/env python3
"""Independent V4 circuit-proof transcript vector and checker."""

import json
from pathlib import Path

from reference_sha256_transcript import SECP_P as P, Sha256Transcript


N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PRECOMMIT_DOMAIN = b"Purify/BPPP/CircuitNormArg/v4/precommit"
PROOF_DOMAIN = b"Purify/BPPP/CircuitNormArg/v4/proof"
IDENTITY = None


def inverse(value, modulus):
    return pow(value, modulus - 2, modulus)


def add(left, right):
    if left is IDENTITY:
        return right
    if right is IDENTITY:
        return left
    if left[0] == right[0]:
        if (left[1] + right[1]) % P == 0:
            return IDENTITY
        slope = 3 * left[0] * left[0] * inverse(2 * left[1] % P, P)
    else:
        slope = (right[1] - left[1]) * inverse((right[0] - left[0]) % P, P)
    slope %= P
    x = (slope * slope - left[0] - right[0]) % P
    y = (slope * (left[0] - x) - left[1]) % P
    return x, y


def multiply(scalar, point):
    out = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            out = add(out, addend)
        addend = add(addend, addend)
        scalar >>= 1
    return out


GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def point_bytes(point):
    if point is IDENTITY:
        return bytes(33)
    return bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")


def append_point(transcript, point):
    encoded = point_bytes(point)
    transcript.append_point(encoded[0], int.from_bytes(encoded[1:], "big"))


def pair_bytes(left, right):
    parity = 0
    left_x = bytes(32)
    right_x = bytes(32)
    if left is not IDENTITY:
        parity |= (left[1] & 1) << 1
        left_x = left[0].to_bytes(32, "big")
    if right is not IDENTITY:
        parity |= right[1] & 1
        right_x = right[0].to_bytes(32, "big")
    return bytes([parity]) + left_x + right_x


def append_pair(transcript, encoded):
    transcript.append_pair(
        encoded[0],
        int.from_bytes(encoded[1:33], "big"),
        int.from_bytes(encoded[33:65], "big"),
    )


def challenge(transcript, index):
    digest, value = transcript.challenge(index)
    return digest, value


def validate_shape(shape):
    mode = shape["mode"]
    gate_count = shape["gate_count"]
    commitment_count = shape["commitment_count"]
    n_vec_len = shape["n_vec_len"]
    l_vec_len = shape["l_vec_len"]
    public_count = shape["public_commitment_count"]
    values = (
        mode,
        gate_count,
        commitment_count,
        n_vec_len,
        l_vec_len,
        public_count,
    )
    if any(value < 0 or value >= 1 << 64 for value in values):
        raise ValueError("V4 shape value outside u64")
    if mode not in (0, 1):
        raise ValueError("V4 commitment mode")
    if gate_count == 0 or gate_count & (gate_count - 1):
        raise ValueError("V4 padded gate count")
    if n_vec_len != 2 * gate_count or l_vec_len != n_vec_len:
        raise ValueError("V4 vector lengths")
    if mode == 0 and commitment_count >= gate_count:
        raise ValueError("V4 hidden commitment count")
    if mode == 1 and commitment_count == 0:
        raise ValueError("V4 empty public mode")
    if public_count != (commitment_count if mode == 1 else 0):
        raise ValueError("V4 public commitment count")


def append_shape(transcript, shape):
    validate_shape(shape)
    transcript.append_u64(shape["mode"])
    transcript.append_u64(shape["gate_count"])
    transcript.append_u64(shape["commitment_count"])
    transcript.append_u64(shape["n_vec_len"])
    transcript.append_u64(shape["l_vec_len"])
    transcript.append_u64(shape["public_commitment_count"])


def hex32(value):
    return value.to_bytes(32, "big").hex()


def make_vector(mode=1):
    if mode not in (0, 1):
        raise ValueError("V4 fixture mode")
    binding = bytes(range(0x10, 0x30))
    raw_generator_digest = bytes(range(0x80, 0xA0))
    public_commitments = (
        [multiply(1, GENERATOR), multiply(2, GENERATOR)] if mode == 1 else []
    )
    raw_commitment = multiply(3, GENERATOR)
    shape = {
        "mode": mode,
        "gate_count": 8,
        "commitment_count": 2,
        "n_vec_len": 16,
        "l_vec_len": 16,
        "public_commitment_count": len(public_commitments),
    }

    precommit = Sha256Transcript()
    precommit.append_bytes(PRECOMMIT_DOMAIN)
    precommit.append_bytes(binding)
    append_shape(precommit, shape)
    for point in public_commitments:
        append_point(precommit, point)
    append_point(precommit, raw_commitment)
    _, digest = precommit.challenge(0)

    proof = Sha256Transcript()
    proof.append_bytes(PROOF_DOMAIN)
    proof.append_scalar(digest)
    proof.append_bytes(raw_generator_digest)
    append_shape(proof, shape)
    _, rho = challenge(proof, 0)
    _, mul_scale = challenge(proof, 1)
    _, mul_ratio = challenge(proof, 2)
    _, row_ratio = challenge(proof, 3)

    coefficient_commitment = multiply(4, GENERATOR)
    anchored_offset = multiply(5, GENERATOR)
    anchored_commitment = add(raw_commitment, anchored_offset)
    append_point(proof, coefficient_commitment)
    append_point(proof, anchored_offset)
    append_point(proof, anchored_commitment)

    _, eta = challenge(proof, 4)
    batched_commitment = (
        add(public_commitments[0], multiply(eta, public_commitments[1]))
        if mode == 1
        else IDENTITY
    )
    append_point(proof, batched_commitment)
    nonce = (
        multiply(7, GENERATOR)[0].to_bytes(32, "big")
        if mode == 1
        else bytes(32)
    )
    proof.append_bytes(nonce)
    _, dlog_challenge = challenge(proof, 5)
    dlog_response = 11 if mode == 1 else 0
    proof.append_scalar(dlog_response)

    mask_commitment = multiply(9, GENERATOR)
    t2 = 13
    append_point(proof, mask_commitment)
    proof.append_scalar(t2)
    _, alpha = challenge(proof, 6)
    combined_commitment = add(
        anchored_commitment,
        add(
            multiply(alpha, mask_commitment),
            multiply(alpha * alpha % N * t2 % N, GENERATOR),
        ),
    )
    append_point(proof, combined_commitment)

    points = [
        (IDENTITY, multiply(11, GENERATOR)),
        (multiply(12, GENERATOR), IDENTITY),
        (multiply(13, GENERATOR), multiply(14, GENERATOR)),
        (multiply(15, GENERATOR), multiply(16, GENERATOR)),
    ]
    pairs = [pair_bytes(left, right) for left, right in points]
    gammas = []
    for index, encoded in enumerate(pairs):
        append_pair(proof, encoded)
        _, gamma = challenge(proof, 7 + index)
        gammas.append(hex32(gamma))

    terminal_n = 17
    terminal_l = 19
    proof.append_scalar(terminal_n)
    proof.append_scalar(terminal_l)
    _, prepared_binding = proof.challenge(7 + len(pairs))

    return {
        "suite": "Purify/BPPP/CircuitNormArg/v4",
        "circuit_binding_digest": binding.hex(),
        "raw_generator_digest": raw_generator_digest.hex(),
        **shape,
        "public_commitments": [point_bytes(point).hex() for point in public_commitments],
        "raw_commitment": point_bytes(raw_commitment).hex(),
        "precommitment_digest": hex32(digest),
        "rho": hex32(rho),
        "mul_scale": hex32(mul_scale),
        "mul_ratio": hex32(mul_ratio),
        "row_ratio": hex32(row_ratio),
        "coefficient_commitment": point_bytes(coefficient_commitment).hex(),
        "anchored_offset": point_bytes(anchored_offset).hex(),
        "anchored_commitment": point_bytes(anchored_commitment).hex(),
        "eta": hex32(eta),
        "batched_public_commitment": point_bytes(batched_commitment).hex(),
        "dlog_nonce": nonce.hex(),
        "dlog_challenge": hex32(dlog_challenge),
        "dlog_response": hex32(dlog_response),
        "mask_commitment": point_bytes(mask_commitment).hex(),
        "t2": hex32(t2),
        "alpha": hex32(alpha),
        "combined_commitment": point_bytes(combined_commitment).hex(),
        "round_pairs": [encoded.hex() for encoded in pairs],
        "gammas": gammas,
        "terminal_n": hex32(terminal_n),
        "terminal_l": hex32(terminal_l),
        "prepared_binding": hex32(prepared_binding),
    }


def check_vector():
    vector_dir = (
        Path(__file__).parents[1]
        / "rust"
        / "receipt-cycle"
        / "tests"
        / "vectors"
    )
    expected = make_vector()
    actual = json.loads(
        (vector_dir / "sha256_circuit_v4.json").read_text(encoding="ascii")
    )
    assert actual == expected
    hidden_expected = make_vector(0)
    hidden_actual = json.loads(
        (vector_dir / "sha256_circuit_v4_hidden.json").read_text(
            encoding="ascii"
        )
    )
    assert hidden_actual == hidden_expected

    shape = {
        key: expected[key]
        for key in (
            "mode",
            "gate_count",
            "commitment_count",
            "n_vec_len",
            "l_vec_len",
            "public_commitment_count",
        )
    }
    public_commitments = [multiply(1, GENERATOR), multiply(2, GENERATOR)]
    wrong_precommit = Sha256Transcript()
    wrong_precommit.append_bytes(b"Purify/BPPP/CircuitNormArg/v3/precommit")
    wrong_precommit.append_bytes(bytes.fromhex(expected["circuit_binding_digest"]))
    append_shape(wrong_precommit, shape)
    for point in public_commitments:
        append_point(wrong_precommit, point)
    append_point(wrong_precommit, multiply(3, GENERATOR))
    assert wrong_precommit.challenge(0)[1] != int(
        expected["precommitment_digest"], 16
    )

    wrong_proof = Sha256Transcript()
    wrong_proof.append_bytes(b"Purify/BPPP/CircuitNormArg/v3/proof")
    wrong_proof.append_scalar(int(expected["precommitment_digest"], 16))
    wrong_proof.append_bytes(bytes.fromhex(expected["raw_generator_digest"]))
    append_shape(wrong_proof, shape)
    assert wrong_proof.challenge(0)[1] != int(expected["rho"], 16)

    hidden = dict(shape, mode=0, public_commitment_count=0)
    validate_shape(dict(hidden, commitment_count=7))
    for commitment_count in (8, 9):
        try:
            validate_shape(dict(hidden, commitment_count=commitment_count))
        except ValueError:
            pass
        else:
            raise AssertionError("invalid hidden V4 shape accepted")

    validate_shape(
        dict(shape, commitment_count=9, public_commitment_count=9)
    )


if __name__ == "__main__":
    check_vector()
    print("SHA-256 circuit V4 transcript vector: ok")
