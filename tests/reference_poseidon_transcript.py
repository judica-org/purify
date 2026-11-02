#!/usr/bin/env python3
"""Independent reference for the candidate typed Poseidon transcript."""

import hashlib
from pathlib import Path


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
WIDTH = 3
FULL_ROUNDS = 8
PARTIAL_ROUNDS = 64
FIELD_BITS = 256
SUITE_ID = b"Purify/PoseidonTranscript/v1"

FIELD = 0x4649454C
SCALAR = 0x5343414C
POINT = 0x504F494E
PAIR = 0x50414952
BYTE = 0x42595445
U64 = 0x55363420
CHALLENGE = 0x4348414C
OPENING_BASE = 0x4F424153


def header(item_type, auxiliary):
    return (item_type << 64) | auxiliary


class Grain:
    def __init__(self):
        self.state = [1] * 80
        bits = (
            [(1 >> bit) & 1 for bit in range(1, -1, -1)]
            + [(0 >> bit) & 1 for bit in range(3, -1, -1)]
            + [(FIELD_BITS >> bit) & 1 for bit in range(11, -1, -1)]
            + [(WIDTH >> bit) & 1 for bit in range(11, -1, -1)]
            + [(FULL_ROUNDS >> bit) & 1 for bit in range(9, -1, -1)]
            + [(PARTIAL_ROUNDS >> bit) & 1 for bit in range(9, -1, -1)]
        )
        assert len(bits) == 50
        self.state[: len(bits)] = bits
        for _ in range(160):
            self.shift()

    def shift(self):
        value = (
            self.state[62]
            ^ self.state[51]
            ^ self.state[38]
            ^ self.state[23]
            ^ self.state[13]
            ^ self.state[0]
        )
        self.state = self.state[1:] + [value]
        return value

    def bit(self):
        control = self.shift()
        while control == 0:
            self.shift()
            control = self.shift()
        return self.shift()

    def integer(self):
        value = 0
        for _ in range(FIELD_BITS):
            value = (value << 1) | self.bit()
        return value


def mat_mul(left, right):
    return [
        [sum(left[r][i] * right[i][c] for i in range(WIDTH)) % P
         for c in range(WIDTH)]
        for r in range(WIDTH)
    ]


def mat_pow(matrix, exponent):
    out = [[int(r == c) for c in range(WIDTH)] for r in range(WIDTH)]
    base = matrix
    while exponent:
        if exponent & 1:
            out = mat_mul(out, base)
        base = mat_mul(base, base)
        exponent >>= 1
    return out


def mix(matrix, vector):
    return [
        sum(matrix[r][c] * vector[c] for c in range(WIDTH)) % P
        for r in range(WIDTH)
    ]


def determinant(matrix):
    return (
        matrix[0][0] *
        (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1])
        - matrix[0][1] *
        (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0])
        + matrix[0][2] *
        (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0])
    ) % P


def proportional(left, right):
    return all(
        left[i] * right[j] % P == left[j] * right[i] % P
        for i in range(WIDTH)
        for j in range(i + 1, WIDTH)
    )


def krylov_secure(matrix):
    basis = [1, 0, 0]
    first = mix(matrix, basis)
    second = mix(matrix, first)
    columns = [[basis[r], first[r], second[r]] for r in range(WIDTH)]
    return determinant(columns) != 0


def algorithm_one_secure(matrix):
    identity = [[int(r == c) for c in range(WIDTH)] for r in range(WIDTH)]
    powers = [identity, matrix, mat_pow(matrix, 2)]
    for exponent in range(1, 3):
        current = powers[exponent]
        diagonal = [[current[0][0] if r == c else 0
                     for c in range(WIDTH)] for r in range(WIDTH)]
        if current == diagonal:
            return False
        source = current if exponent == 1 else matrix
        vector = [0, source[0][2], -source[0][1] % P]
        if vector == [0] * WIDTH or proportional(vector, mix(current, vector)):
            return False
        for power in powers[1:exponent + 1]:
            if exponent == 1:
                if power[0][1] == 0 and power[0][2] == 0:
                    return False
            elif proportional(vector, mix(power, vector)):
                return False
    return True


def secure_mds(matrix):
    return (
        algorithm_one_secure(matrix)
        and krylov_secure(matrix)
        and all(krylov_secure(mat_pow(matrix, power))
                for power in range(2, 4 * WIDTH + 1))
    )


def parameters():
    grain = Grain()
    constants = []
    while len(constants) < WIDTH * (FULL_ROUNDS + PARTIAL_ROUNDS):
        candidate = grain.integer()
        if candidate < P:
            constants.append(candidate)
    while True:
        values = [grain.integer() % P for _ in range(2 * WIDTH)]
        if len(set(values)) != len(values):
            continue
        matrix = [
            [pow((values[r] + values[WIDTH + c]) % P, P - 2, P)
             for c in range(WIDTH)]
            for r in range(WIDTH)
        ]
        if all(matrix[r][c] for r in range(WIDTH) for c in range(WIDTH)) \
                and secure_mds(matrix):
            return constants, matrix


ROUND_CONSTANTS, MDS = parameters()


def digest(values):
    encoded = b"".join(value.to_bytes(32, "big") for value in values)
    return hashlib.sha256(encoded).hexdigest()


assert digest(ROUND_CONSTANTS) == (
    "de0209e6db9909a2bebd435499a3dd1e199626ac0d1415b55f832c8dd5bdca6d"
)
assert digest(value for row in MDS for value in row) == (
    "b214b9440fa5cb193ab6bc98fad114eaad5da447dc61629c03ab1805328945d5"
)


def permute(state):
    state = list(state)
    for round_index in range(FULL_ROUNDS + PARTIAL_ROUNDS):
        state = [
            (value + ROUND_CONSTANTS[round_index * WIDTH + lane]) % P
            for lane, value in enumerate(state)
        ]
        full = not (
            FULL_ROUNDS // 2
            <= round_index
            < FULL_ROUNDS // 2 + PARTIAL_ROUNDS
        )
        if full:
            state = [pow(value, 5, P) for value in state]
        else:
            state[0] = pow(state[0], 5, P)
        state = mix(MDS, state)
    return state


class Transcript:
    def __init__(self):
        self.state = [int.from_bytes(SUITE_ID, "big"), 0, 0]
        self.rate_index = 0

    def absorb(self, value):
        lane = self.rate_index + 1
        self.state[lane] = (self.state[lane] + value) % P
        self.rate_index += 1
        if self.rate_index == WIDTH - 1:
            self.state = permute(self.state)
            self.rate_index = 0

    def append_field(self, value):
        self.absorb(header(FIELD, 0))
        self.absorb(value)

    def append_scalar(self, value):
        self.absorb(header(SCALAR, 0))
        self.absorb(value)

    def append_point(self, prefix, x):
        self.absorb(header(POINT, prefix))
        self.absorb(x)

    def append_pair(self, parity, first_x, second_x):
        self.absorb(header(PAIR, parity))
        self.absorb(first_x)
        self.absorb(second_x)

    def append_bytes(self, value):
        self.absorb(header(BYTE, len(value)))
        for offset in range(0, len(value), 31):
            self.absorb(int.from_bytes(value[offset:offset + 31], "big"))

    def append_u64(self, value):
        self.absorb(header(U64, value))

    def squeeze(self, item_type, auxiliary, extra=()):
        challenge = Transcript.__new__(Transcript)
        challenge.state = list(self.state)
        challenge.rate_index = self.rate_index
        for value in extra:
            challenge.absorb(value)
        challenge.absorb(header(item_type, auxiliary))
        challenge.absorb(1)
        while challenge.rate_index:
            challenge.absorb(0)
        return challenge.state[1:]

    def challenge(self, round_index):
        return self.squeeze(CHALLENGE, round_index)

    def opening(self, basis_digest, role):
        words = [header(BYTE, len(basis_digest))]
        words += [int.from_bytes(basis_digest[offset:offset + 31], "big")
                  for offset in range(0, len(basis_digest), 31)]
        return self.squeeze(OPENING_BASE, role, words)


def make_transcript(seed):
    transcript = Transcript()
    transcript.append_field(seed + 1)
    transcript.append_scalar(seed + 2)
    transcript.append_point(2 + (seed & 1), seed + 3)
    transcript.append_pair(seed & 3, seed + 4, seed + 5)
    transcript.append_bytes(bytes((seed + i) & 0xFF for i in range(33)))
    transcript.append_u64(seed + 6)
    return transcript


def vectors():
    for seed in (1, 17, 255):
        transcript = make_transcript(seed)
        basis = bytes([seed ^ 0x5A]) * 32
        ordinary = transcript.challenge(seed + 7)
        opening = transcript.opening(basis, 1 + (seed & 1))
        yield seed, basis, ordinary, opening


def check_vectors():
    path = (
        Path(__file__).parents[1]
        / "rust"
        / "receipt-cycle"
        / "tests"
        / "vectors"
        / "algebraic_transcript_v1.txt"
    )
    expected = list(vectors())
    lines = [line.split() for line in path.read_text(encoding="ascii").splitlines()
             if line.startswith("vector ")]
    assert len(lines) == len(expected)
    for words, (seed, basis, ordinary, opening) in zip(lines, expected):
        assert len(words) == 7
        assert int(words[1]) == seed
        assert bytes.fromhex(words[2]) == basis
        assert [int(words[i], 16) for i in (3, 4)] == ordinary
        assert [int(words[i], 16) for i in (5, 6)] == opening

    bytes32_lines = [
        line.split() for line in path.read_text(encoding="ascii").splitlines()
        if line.startswith("bytes32 ")
    ]
    assert len(bytes32_lines) == 2
    for words in bytes32_lines:
        assert len(words) == 4
        value = bytes.fromhex(words[1])
        assert len(value) == 32
        transcript = Transcript()
        transcript.append_bytes(value)
        assert [int(words[i], 16) for i in (2, 3)] == transcript.challenge(0)


if __name__ == "__main__":
    check_vectors()
    print("candidate Poseidon transcript vectors: ok")
