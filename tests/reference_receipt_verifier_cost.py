#!/usr/bin/env python3
# Copyright (c) 2026 Judica, Inc.
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Count the current BP++ child verifier's work, not recursive proof costs.

Source relations:
  src/protocol/bppp.cpp: build_circuit_norm_arg_public_data,
    derive_zk_challenge, verify_experimental_circuit_zk_norm_arg_impl
  src/bridge/bppp_bridge.c: purify_norm_arg_public_digest,
    purify_norm_arg_commit_initial_data
  third_party/secp256k1-zkp/src/modules/bppp/bppp_norm_product_impl.h:
    secp256k1_bppp_rangeproof_norm_product_verify
  third_party/secp256k1-zkp/src/modules/bppp/bppp_transcript_impl.h:
    secp256k1_bppp_challenge_scalar

The parent is assumed to reconstruct statement-only public data outside its
arithmetic circuit. Child-proof-dependent SHA256 work and group equations
remain. The current norm transcript starts with a public statement digest
and its variable commitment. Historical commitment-first counts are included
only as a cost comparison; no old proof verification is implemented here.
The final verifier must compute or authenticate the public digest from the
actual public statement, not accept the assembler's digest without checking.

Counts omit public-data reconstruction, circuit hashing, generator creation,
point parsing, scalar arithmetic, non-native field constraints, and outer
proving/verification. They are not circuit gate counts or lower bounds on a
redesigned protocol. Tagged SHA256 midstates are treated as constants. The
outer challenge count assumes the first rejection-sampling attempt succeeds.
"""

import argparse
from dataclasses import asdict, dataclass
import json


@dataclass(frozen=True)
class Work:
    gates: int
    norm_coordinates: int
    linear_coordinates: int
    inner_rounds: int
    inner_proof_bytes: int
    complete_child_proof_bytes: int
    public_norm_statement_bytes: int
    initial_norm_transcript_bytes: int
    inner_sha256_stream_blocks: int
    inner_sha256_challenge_fork_blocks: int
    outer_challenge_sha256_blocks_first_attempt: int
    proof_dependent_sha256_blocks_first_attempt: int
    historical_commitment_first_transcript_bytes: int
    historical_proof_dependent_sha256_blocks_first_attempt: int
    fixed_generator_msm_terms: int
    base_generator_msm_terms: int
    variable_point_msm_terms: int


def norm_hash_blocks(initial, rounds):
    stream_blocks = (initial + 65 * rounds) // 64
    # Each challenge copies the live transcript, appends an eight-byte index,
    # then finalizes with one padding byte and an eight-byte bit length.
    fork_blocks = sum(
        (((initial + 65 * (i + 1)) % 64) + 8 + 9 + 63) // 64
        for i in range(rounds)
    )
    return stream_blocks, fork_blocks


def profile(gates):
    if gates < 1 or gates & (gates - 1):
        raise ValueError("padded gate count must be a positive power of two")
    norm = 4 * gates
    # External outputs do not occupy the linear vector. Its mandatory blind
    # coordinate makes round_up_power_of_two(gates + 1) equal to 2 * gates.
    linear = 2 * gates
    rounds = norm.bit_length() - 1
    generators = norm + linear
    inner_bytes = 65 * rounds + 64
    # rho32, g_len64, generator_count64, generators33[], c_vec_len64,
    # and c_vec32[]. Hash this statement outside the parent circuit.
    public_bytes = 32 + 8 + 8 + 33 * generators + 8 + 32 * linear
    # Public statement digest32 plus variable commitment33, after a constant
    # tagged midstate. The historical layout hashed the full statement after
    # the commitment, forcing those blocks through the variable chaining state.
    initial = 32 + 33
    stream_blocks, fork_blocks = norm_hash_blocks(initial, rounds)
    historical_initial = 33 + public_bytes
    historical_blocks = sum(norm_hash_blocks(historical_initial, rounds))
    # Binding digest32, anchored A33, S33, t2_32, index64, counter64.
    outer_blocks = (32 + 33 + 33 + 32 + 8 + 8 + 9 + 63) // 64
    return Work(
        gates, norm, linear, rounds, inner_bytes, inner_bytes + 33 + 33 + 32,
        public_bytes, initial, stream_blocks, fork_blocks, outer_blocks,
        stream_blocks + fork_blocks + outer_blocks,
        historical_initial, historical_blocks + outer_blocks,
        generators, 1, 2 * rounds + 1,
    )


def packet_profile(roots):
    if roots < 1:
        raise ValueError("root count must be positive")
    setup, bridge = profile(2048), profile(8192)
    return {
        "roots": roots,
        "child_proof_count": roots + 1,
        "out_of_band_child_proof_bytes": (
            setup.complete_child_proof_bytes + roots * bridge.complete_child_proof_bytes
        ),
        "explicit_recipient_and_ciphertext_bytes": 64 + 192 * roots,
        "proof_dependent_sha256_blocks_first_attempt": (
            setup.proof_dependent_sha256_blocks_first_attempt
            + roots * bridge.proof_dependent_sha256_blocks_first_attempt
        ),
        "historical_proof_dependent_sha256_blocks_first_attempt": (
            setup.historical_proof_dependent_sha256_blocks_first_attempt
            + roots * bridge.historical_proof_dependent_sha256_blocks_first_attempt
        ),
        "fixed_generator_msm_terms": (
            setup.fixed_generator_msm_terms + roots * bridge.fixed_generator_msm_terms
        ),
        "base_generator_msm_terms": roots + 1,
        "variable_point_msm_terms": (
            setup.variable_point_msm_terms + roots * bridge.variable_point_msm_terms
        ),
    }


def self_test():
    # The byte counts independently match the honest #38 proof measurements.
    setup, bridge = profile(2048), profile(8192)
    assert (setup.inner_proof_bytes, setup.complete_child_proof_bytes) == (909, 1007)
    assert (bridge.inner_proof_bytes, bridge.complete_child_proof_bytes) == (1039, 1137)
    assert setup.public_norm_statement_bytes == 536632
    assert bridge.public_norm_statement_bytes == 2146360
    assert setup.initial_norm_transcript_bytes == bridge.initial_norm_transcript_bytes == 65
    assert setup.proof_dependent_sha256_blocks_first_attempt == 30
    assert bridge.proof_dependent_sha256_blocks_first_attempt == 34
    assert setup.historical_proof_dependent_sha256_blocks_first_attempt == 8414
    assert bridge.historical_proof_dependent_sha256_blocks_first_attempt == 33570
    assert packet_profile(2)["out_of_band_child_proof_bytes"] == 3281
    assert packet_profile(2)["explicit_recipient_and_ciphertext_bytes"] == 448
    assert packet_profile(2)["proof_dependent_sha256_blocks_first_attempt"] == 98
    assert packet_profile(100)["proof_dependent_sha256_blocks_first_attempt"] == 3430
    assert packet_profile(100)["historical_proof_dependent_sha256_blocks_first_attempt"] == 3365414

    # Independently count actual byte-buffer block flushes, including forks
    # that cross the SHA256 padding boundary at larger round counts.
    for initial in (65, 536665, 2146393):
        for rounds in (0, 1, 13, 15, 31, 47, 48, 63, 64, 65):
            buffered = initial % 64
            blocks = initial // 64
            for _ in range(rounds):
                buffered += 65
                blocks += buffered // 64
                buffered %= 64
                fork = buffered + 8 + 1
                fork += (56 - fork % 64) % 64
                fork += 8
                blocks += fork // 64
            assert blocks == sum(norm_hash_blocks(initial, rounds))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roots", type=int, default=2)
    parser.add_argument("--gates", type=int, help="also report one custom padded circuit")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.roots < 1:
        parser.error("--roots must be positive")
    if args.gates is not None and (args.gates < 1 or args.gates & (args.gates - 1)):
        parser.error("--gates must be a positive power of two")
    if args.self_test:
        self_test()
    result = {
        "kind": "source-derived verifier workload; not a recursive proof benchmark",
        "setup": asdict(profile(2048)),
        "bridge": asdict(profile(8192)),
        "packet": packet_profile(args.roots),
    }
    if args.gates is not None:
        result["custom"] = asdict(profile(args.gates))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
