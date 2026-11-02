#!/usr/bin/env python3
"""Independent reference for the typed chained SHA-256 transcript."""

import hashlib
from pathlib import Path


SUITE_ID = b"Purify/SHA256Transcript/v1"
SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

FIELD = b"FIEL"
SCALAR = b"SCAL"
POINT = b"POIN"
PAIR = b"PAIR"
BYTE = b"BYTE"
U64 = b"U64 "
CHALLENGE = b"CHAL"
OPENING_BASE = b"OBAS"


def header(item_type, auxiliary):
    assert len(item_type) == 4
    assert 0 <= auxiliary < 1 << 64
    return item_type + auxiliary.to_bytes(8, "big")


def scalar_from_digest(digest):
    encoded = bytes([digest[0] & 0x7F]) + digest[1:]
    value = int.from_bytes(encoded, "big")
    if value == 0:
        raise ValueError("zero SHA-256 transcript challenge")
    assert value < SECP_ORDER
    return value


class Sha256Transcript:
    def __init__(self):
        self.state = hashlib.sha256(SUITE_ID).digest()
        self.pending = bytearray()

    def append_field(self, value):
        assert 0 <= value < 1 << 256
        self.pending += header(FIELD, 0) + value.to_bytes(32, "big")

    def append_scalar(self, value):
        assert 0 <= value < SECP_ORDER
        self.pending += header(SCALAR, 0) + value.to_bytes(32, "big")

    def append_point(self, prefix, x):
        assert prefix in (0, 2, 3)
        assert prefix != 0 or x == 0
        assert 0 <= x < 1 << 256
        self.pending += header(POINT, prefix) + x.to_bytes(32, "big")

    def append_pair(self, parity, first_x, second_x):
        assert 0 <= parity <= 3
        assert 0 <= first_x < 1 << 256
        assert 0 <= second_x < 1 << 256
        self.pending += (
            header(PAIR, parity)
            + first_x.to_bytes(32, "big")
            + second_x.to_bytes(32, "big")
        )

    def append_bytes(self, value):
        self.pending += header(BYTE, len(value)) + value

    def append_u64(self, value):
        self.pending += header(U64, value)

    def challenge(self, round_index):
        digest = hashlib.sha256(
            self.state + self.pending + header(CHALLENGE, round_index)
        ).digest()
        scalar = scalar_from_digest(digest)
        self.state = digest
        self.pending.clear()
        return digest, scalar

    def opening(self, basis_digest, role):
        assert len(basis_digest) == 32
        digest = hashlib.sha256(
            self.state
            + self.pending
            + header(BYTE, len(basis_digest))
            + basis_digest
            + header(OPENING_BASE, role)
        ).digest()
        return digest, scalar_from_digest(digest)


def make_transcript(seed):
    transcript = Sha256Transcript()
    transcript.append_field(seed + 1)
    transcript.append_scalar(seed + 2)
    transcript.append_point(2 + (seed & 1), seed + 3)
    transcript.append_pair(seed & 3, seed + 4, seed + 5)
    transcript.append_bytes(bytes((seed + index) & 0xFF for index in range(33)))
    transcript.append_u64(seed + 6)
    return transcript


def vectors():
    for seed in (1, 17, 255):
        basis = bytes([seed ^ 0x5A]) * 32
        ordinary = make_transcript(seed).challenge(seed + 7)
        opening = make_transcript(seed).opening(basis, 1 + (seed & 1))
        yield seed, basis, ordinary, opening


def check_vectors():
    path = (
        Path(__file__).parents[1]
        / "rust"
        / "receipt-cycle"
        / "tests"
        / "vectors"
        / "sha256_transcript_v1.txt"
    )
    lines = [
        line.split()
        for line in path.read_text(encoding="ascii").splitlines()
        if line.startswith("vector ")
    ]
    expected = list(vectors())
    assert len(lines) == len(expected)
    for words, (seed, basis, ordinary, opening) in zip(lines, expected):
        assert len(words) == 7
        assert int(words[1]) == seed
        assert bytes.fromhex(words[2]) == basis
        assert bytes.fromhex(words[3]) == ordinary[0]
        assert int(words[4], 16) == ordinary[1]
        assert bytes.fromhex(words[5]) == opening[0]
        assert int(words[6], 16) == opening[1]


if __name__ == "__main__":
    check_vectors()
    print("typed SHA-256 transcript vectors: ok")
