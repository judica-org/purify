// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string_view>

#include "../src/protocol/bulletproof_internal.hpp"
#include "purify.hpp"
#include "purify/bppp.hpp"

namespace {

using purify::Bytes;
using purify::ExperimentalBulletproofProof;
using purify::GeneratedKey;
using purify::NativeBulletproofCircuit;
using purify::Result;
using purify::UInt512;

struct SplitMix64 {
    std::uint64_t state;

    explicit SplitMix64(std::uint64_t seed) : state(seed) {}

    std::uint64_t next_u64() {
        std::uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }

    std::size_t bounded(std::size_t upper_bound) {
        return upper_bound == 0 ? 0 : static_cast<std::size_t>(next_u64() % upper_bound);
    }

    unsigned char next_byte() {
        return static_cast<unsigned char>(next_u64() & 0xffU);
    }
};

struct TestContext {
    int failures = 0;

    void expect(bool condition, std::string_view message) {
        if (!condition) {
            ++failures;
            std::cerr << "FAIL: " << message << "\n";
        }
    }
};

template <typename T>
void expect_ok(TestContext& ctx, const Result<T>& result, std::string_view message) {
    if (!result.has_value()) {
        ++ctx.failures;
        std::cerr << "FAIL: " << message << " (" << result.error().name() << ")\n";
        return;
    }
    ctx.expect(true, message);
}

Bytes random_bytes(SplitMix64& rng, std::size_t min_size, std::size_t max_size) {
    const std::size_t width = max_size >= min_size ? (max_size - min_size + 1) : 1;
    const std::size_t size = min_size + rng.bounded(width);
    Bytes out(size);
    for (unsigned char& byte : out) {
        byte = rng.next_byte();
    }
    return out;
}

template <std::size_t N>
std::array<unsigned char, N> random_array(SplitMix64& rng) {
    std::array<unsigned char, N> out{};
    for (unsigned char& byte : out) {
        byte = rng.next_byte();
    }
    return out;
}

Result<GeneratedKey> random_key(SplitMix64& rng) {
    Bytes seed = random_bytes(rng, 16, 64);
    return purify::generate_key(seed);
}

bool proof_rejected_after_tamper(const NativeBulletproofCircuit& circuit,
                                 const ExperimentalBulletproofProof& proof,
                                 std::span<const unsigned char> binding) {
    Result<Bytes> serialized = proof.serialize();
    if (!serialized.has_value() || serialized->empty()) {
        return false;
    }
    Bytes tampered = *serialized;
    tampered[tampered.size() - 1] ^= 0x01;
    Result<ExperimentalBulletproofProof> parsed = ExperimentalBulletproofProof::deserialize(tampered);
    if (!parsed.has_value()) {
        return true;
    }
    Result<bool> verified = purify::verify_experimental_circuit(circuit, *parsed, purify::bppp::base_generator(), binding);
    return !verified.has_value() || !*verified;
}

bool proven_signature_rejected_after_tamper(const purify::puresign::PublicKey& public_key,
                                            std::span<const unsigned char> message,
                                            const purify::puresign::ProvenSignature& signature) {
    Result<Bytes> serialized = signature.serialize();
    if (!serialized.has_value() || serialized->empty()) {
        return false;
    }
    Bytes tampered = *serialized;
    tampered[tampered.size() - 1] ^= 0x40;
    Result<purify::puresign::ProvenSignature> parsed = purify::puresign::ProvenSignature::deserialize(tampered);
    if (!parsed.has_value()) {
        return true;
    }
    Result<bool> verified = public_key.verify_message_signature_with_proof(message, *parsed);
    return !verified.has_value() || !*verified;
}

bool proven_signature_plusplus_rejected_after_tamper(const purify::puresign_plusplus::PublicKey& public_key,
                                                     std::span<const unsigned char> message,
                                                     const purify::puresign_plusplus::ProvenSignature& signature) {
    Result<Bytes> serialized = signature.serialize();
    if (!serialized.has_value() || serialized->empty()) {
        return false;
    }
    Bytes tampered = *serialized;
    tampered[tampered.size() - 1] ^= 0x20;
    Result<purify::puresign_plusplus::ProvenSignature> parsed =
        purify::puresign_plusplus::ProvenSignature::deserialize(tampered);
    if (!parsed.has_value()) {
        return true;
    }
    Result<bool> verified = public_key.verify_message_signature_with_proof(message, *parsed);
    return !verified.has_value() || !*verified;
}

void test_seeded_key_and_circuit_properties(TestContext& ctx) {
    SplitMix64 rng(0x1234567890abcdefULL);

    Bytes short_seed = random_bytes(rng, 0, 15);
    Result<GeneratedKey> short_seed_key = purify::generate_key(short_seed);
    ctx.expect(!short_seed_key.has_value() && short_seed_key.error().code == purify::ErrorCode::RangeViolation,
               "generate_key rejects randomized seed material shorter than 16 bytes");

    for (std::size_t i = 0; i < 12; ++i) {
        Bytes seed = random_bytes(rng, 16, 64);
        Result<GeneratedKey> first = purify::generate_key(seed);
        Result<GeneratedKey> second = purify::generate_key(seed);
        expect_ok(ctx, first, "generate_key(seed) succeeds");
        expect_ok(ctx, second, "generate_key(seed) is repeatable");
        if (!first.has_value() || !second.has_value()) {
            continue;
        }

        ctx.expect(first->secret == second->secret, "seeded key generation is deterministic for the secret");
        ctx.expect(first->public_key == second->public_key, "seeded key generation is deterministic for the public key");

        Result<GeneratedKey> derived = purify::derive_key(first->secret);
        expect_ok(ctx, derived, "derive_key succeeds on a generated secret");
        if (derived.has_value()) {
            ctx.expect(derived->public_key == first->public_key, "derive_key reproduces the generated public key");
        }

        Result<purify::Bip340Key> bip340 = purify::derive_bip340_key(first->secret);
        expect_ok(ctx, bip340, "derive_bip340_key succeeds on a generated secret");

        Result<purify::puresign::PublicKey> public_key = purify::puresign::PublicKey::from_secret(first->secret);
        expect_ok(ctx, public_key, "puresign::PublicKey::from_secret succeeds on a generated secret");
        if (bip340.has_value() && public_key.has_value()) {
            ctx.expect(public_key->bip340_pubkey == bip340->xonly_pubkey,
                       "PureSign public key bundle matches derive_bip340_key");
        }

        Bytes message = random_bytes(rng, 0, 48);
        Result<purify::FieldElement> value = purify::eval(first->secret, message);
        expect_ok(ctx, value, "eval succeeds on a generated secret");

        Result<purify::BulletproofWitnessData> witness = purify::prove_assignment_data(message, first->secret);
        expect_ok(ctx, witness, "prove_assignment_data succeeds on a generated secret");
        if (!value.has_value() || !witness.has_value()) {
            continue;
        }

        ctx.expect(witness->public_key == first->public_key, "witness generation preserves the generated public key");
        ctx.expect(witness->output == *value, "witness output matches direct eval");

        Result<NativeBulletproofCircuit> circuit = purify::verifier_circuit(message, first->public_key);
        expect_ok(ctx, circuit, "verifier_circuit succeeds on a generated public key");
        if (circuit.has_value()) {
            ctx.expect(circuit->evaluate(witness->assignment), "native verifier circuit accepts the generated witness");
        }

        Result<bool> verified = purify::evaluate_verifier_circuit(message, *witness);
        expect_ok(ctx, verified, "evaluate_verifier_circuit succeeds on a generated witness");
        if (verified.has_value()) {
            ctx.expect(*verified, "evaluate_verifier_circuit accepts the generated witness");
        }

        Result<Bytes> assignment = witness->assignment.serialize();
        expect_ok(ctx, assignment, "assignment serialization succeeds on randomized witness data");
        if (assignment.has_value()) {
            ctx.expect(!assignment->empty(), "assignment serialization is non-empty for randomized witness data");
        }
    }
}

void test_random_experimental_proof_properties(TestContext& ctx) {
    SplitMix64 rng(0x0f0e0d0c0b0a0908ULL);

    Result<GeneratedKey> key = random_key(rng);
    expect_ok(ctx, key, "random_key succeeds for experimental proof properties");
    if (!key.has_value()) {
        return;
    }

    Bytes message = random_bytes(rng, 0, 48);
    Result<purify::BulletproofWitnessData> witness = purify::prove_assignment_data(message, key->secret);
    expect_ok(ctx, witness, "prove_assignment_data succeeds for experimental proof properties");
    Result<NativeBulletproofCircuit> circuit = purify::verifier_circuit(message, key->public_key);
    expect_ok(ctx, circuit, "verifier_circuit succeeds for experimental proof properties");
    if (!witness.has_value() || !circuit.has_value()) {
        return;
    }

    std::array<unsigned char, 32> nonce = random_array<32>(rng);
    Bytes binding = random_bytes(rng, 0, 32);
    Result<ExperimentalBulletproofProof> proof =
        purify::prove_experimental_circuit(*circuit, witness->assignment, nonce, purify::bppp::base_generator(), binding);
    expect_ok(ctx, proof, "prove_experimental_circuit succeeds on randomized Purify circuits");
    if (!proof.has_value()) {
        return;
    }

    Result<bool> verified =
        purify::verify_experimental_circuit(*circuit, *proof, purify::bppp::base_generator(), binding);
    expect_ok(ctx, verified, "verify_experimental_circuit succeeds on randomized Purify proofs");
    if (verified.has_value()) {
        ctx.expect(*verified, "randomized experimental circuit proof verifies");
    }

    Result<Bytes> encoded = proof->serialize();
    expect_ok(ctx, encoded, "ExperimentalBulletproofProof serializes in property coverage");
    if (!encoded.has_value()) {
        return;
    }
    Result<ExperimentalBulletproofProof> decoded = ExperimentalBulletproofProof::deserialize(*encoded);
    expect_ok(ctx, decoded, "ExperimentalBulletproofProof deserializes in property coverage");
    if (decoded.has_value()) {
        Result<bool> reparsed =
            purify::verify_experimental_circuit(*circuit, *decoded, purify::bppp::base_generator(), binding);
        expect_ok(ctx, reparsed, "reparsed experimental proof verifies in property coverage");
        if (reparsed.has_value()) {
            ctx.expect(*reparsed, "reparsed experimental proof is accepted");
        }
    }

    Result<bool> wrong_binding =
        purify::verify_experimental_circuit(*circuit, *proof, purify::bppp::base_generator(),
                                            purify::bytes_from_ascii("property-wrong-binding"));
    expect_ok(ctx, wrong_binding, "verify_experimental_circuit runs with a wrong binding in property coverage");
    if (wrong_binding.has_value()) {
        ctx.expect(!*wrong_binding, "experimental proof rejects a mismatched statement binding");
    }

    ctx.expect(proof_rejected_after_tamper(*circuit, *proof, binding),
               "tampering an experimental proof is rejected");
}

void test_template_split_eval_differential(TestContext& ctx) {
    SplitMix64 rng(0x6b8b4567327b23c6ULL);

    for (std::size_t i = 0; i < 8; ++i) {
        Result<GeneratedKey> key = random_key(rng);
        expect_ok(ctx, key, "random_key succeeds for split-eval differential coverage");
        if (!key.has_value()) {
            continue;
        }

        Bytes message = random_bytes(rng, 0, 48);
        Result<purify::BulletproofWitnessData> witness = purify::prove_assignment_data(message, key->secret);
        expect_ok(ctx, witness, "prove_assignment_data succeeds for split-eval differential coverage");
        Result<purify::NativeBulletproofCircuitTemplate> circuit_template = purify::verifier_circuit_template(message);
        expect_ok(ctx, circuit_template, "verifier_circuit_template succeeds for split-eval differential coverage");
        if (!witness.has_value() || !circuit_template.has_value()) {
            continue;
        }

        Result<purify::NativeBulletproofCircuit::PackedWithSlack> full =
            circuit_template->instantiate_packed(key->public_key);
        expect_ok(ctx, full, "instantiate_packed succeeds for split-eval differential coverage");
        if (!full.has_value()) {
            continue;
        }

        auto compare_split_vs_full = [&](const purify::BulletproofAssignmentData& assignment,
                                         const UInt512& pubkey,
                                         std::string_view label) {
            Result<bool> partial = circuit_template->partial_evaluate(assignment);
            Result<bool> final = circuit_template->final_evaluate(assignment, pubkey);
            expect_ok(ctx, partial, label);
            expect_ok(ctx, final, label);
            if (!partial.has_value() || !final.has_value()) {
                return;
            }

            Result<purify::NativeBulletproofCircuit::PackedWithSlack> instantiated =
                circuit_template->instantiate_packed(pubkey);
            expect_ok(ctx, instantiated, label);
            if (!instantiated.has_value()) {
                return;
            }

            bool split_ok = *partial && *final;
            bool full_ok = instantiated->evaluate(assignment);
            ctx.expect(split_ok == full_ok, label);
        };

        compare_split_vs_full(witness->assignment, key->public_key,
                              "split-eval matches full packed evaluation on honest witness data");

        purify::BulletproofAssignmentData bad_base = witness->assignment;
        bad_base.output[0] = bad_base.output[0] + purify::FieldElement::one();
        compare_split_vs_full(bad_base, key->public_key,
                              "split-eval matches full packed evaluation when a multiplication gate is broken");

        purify::BulletproofAssignmentData bad_final = witness->assignment;
        bad_final.commitments[0] = bad_final.commitments[0] + purify::FieldElement::one();
        compare_split_vs_full(bad_final, key->public_key,
                              "split-eval matches full packed evaluation when only the final commitment binding is broken");

        Result<GeneratedKey> other = random_key(rng);
        expect_ok(ctx, other, "second random_key succeeds for wrong-pubkey split-eval differential coverage");
        if (other.has_value() && other->public_key != key->public_key) {
            compare_split_vs_full(witness->assignment, other->public_key,
                                  "split-eval matches full packed evaluation for a wrong public key");
        }
    }
}

void test_assume_valid_proof_matches_validated_proof(TestContext& ctx) {
    SplitMix64 rng(0x1234fedcba987654ULL);

    for (std::size_t i = 0; i < 2; ++i) {
        Result<GeneratedKey> key = random_key(rng);
        expect_ok(ctx, key, "random_key succeeds for assume-valid proof differential coverage");
        if (!key.has_value()) {
            continue;
        }

        Bytes message = random_bytes(rng, 0, 48);
        Result<purify::BulletproofWitnessData> witness = purify::prove_assignment_data(message, key->secret);
        expect_ok(ctx, witness, "prove_assignment_data succeeds for assume-valid proof differential coverage");
        Result<purify::NativeBulletproofCircuitTemplate> circuit_template = purify::verifier_circuit_template(message);
        expect_ok(ctx, circuit_template, "verifier_circuit_template succeeds for assume-valid proof differential coverage");
        if (!witness.has_value() || !circuit_template.has_value()) {
            continue;
        }

        Result<bool> partial = circuit_template->partial_evaluate(witness->assignment);
        Result<bool> final = circuit_template->final_evaluate(witness->assignment, witness->public_key);
        expect_ok(ctx, partial, "partial_evaluate succeeds before assume-valid proof differential");
        expect_ok(ctx, final, "final_evaluate succeeds before assume-valid proof differential");
        if (!partial.has_value() || !final.has_value() || !*partial || !*final) {
            continue;
        }

        Result<purify::NativeBulletproofCircuit::PackedWithSlack> circuit =
            circuit_template->instantiate_packed(witness->public_key);
        expect_ok(ctx, circuit, "instantiate_packed succeeds for assume-valid proof differential coverage");
        if (!circuit.has_value()) {
            continue;
        }

        std::array<unsigned char, 32> nonce = random_array<32>(rng);
        Bytes binding = random_bytes(rng, 0, 32);
        Result<ExperimentalBulletproofProof> validated =
            purify::prove_experimental_circuit(*circuit, witness->assignment, nonce,
                                               purify::bppp::base_generator(), binding);
        expect_ok(ctx, validated, "validated packed proof succeeds in differential coverage");
        Result<ExperimentalBulletproofProof> skipped =
            purify::prove_experimental_circuit_assume_valid(*circuit, witness->assignment, nonce,
                                                            purify::bppp::base_generator(), binding);
        expect_ok(ctx, skipped, "assume-valid packed proof succeeds in differential coverage");
        if (!validated.has_value() || !skipped.has_value()) {
            continue;
        }

        ctx.expect(validated->commitment == skipped->commitment,
                   "assume-valid and validated proving produce the same commitment");
        ctx.expect(validated->proof == skipped->proof,
                   "assume-valid and validated proving produce identical proof bytes");
    }
}

void test_random_puresign_proven_signature_properties(TestContext& ctx) {
    SplitMix64 rng(0xfeedfacedeadbeefULL);

    Result<GeneratedKey> key = random_key(rng);
    expect_ok(ctx, key, "random_key succeeds for PureSign property coverage");
    if (!key.has_value()) {
        return;
    }

    Result<purify::puresign::KeyPair> key_pair = purify::puresign::KeyPair::from_secret(key->secret);
    expect_ok(ctx, key_pair, "KeyPair::from_secret succeeds for randomized PureSign coverage");
    if (!key_pair.has_value()) {
        return;
    }
    const purify::puresign::PublicKey& public_key = key_pair->public_key();

    Bytes message = random_bytes(rng, 1, 40);
    Result<purify::puresign::Signature> direct = key_pair->sign_message(message);
    expect_ok(ctx, direct, "KeyPair::sign_message succeeds for randomized PureSign coverage");

    Result<purify::puresign::ProvenSignature> proven = key_pair->sign_message_with_proof(message);
    expect_ok(ctx, proven, "KeyPair::sign_message_with_proof succeeds for randomized PureSign coverage");
    if (!direct.has_value() || !proven.has_value()) {
        return;
    }

    ctx.expect(direct->bytes == proven->signature.bytes,
               "sign_message_with_proof preserves the deterministic BIP340 signature bytes");

    Result<bool> verified = public_key.verify_message_signature_with_proof(message, *proven);
    expect_ok(ctx, verified, "PublicKey::verify_message_signature_with_proof succeeds for randomized PureSign coverage");
    if (verified.has_value()) {
        ctx.expect(*verified, "randomized PureSign message signature with proof verifies");
    }

    Result<bool> wrong_message = public_key.verify_message_signature_with_proof(random_bytes(rng, 1, 24), *proven);
    expect_ok(ctx, wrong_message,
              "PublicKey::verify_message_signature_with_proof runs on a wrong message in property coverage");
    if (wrong_message.has_value()) {
        ctx.expect(!*wrong_message, "PureSign message proof rejects a mismatched message");
    }

    ctx.expect(proven_signature_rejected_after_tamper(public_key, message, *proven),
               "tampering a ProvenSignature is rejected");
}

void test_random_puresign_plusplus_proven_signature_properties(TestContext& ctx) {
    SplitMix64 rng(0xdecafbad12345678ULL);

    Result<GeneratedKey> key = random_key(rng);
    expect_ok(ctx, key, "random_key succeeds for PureSign++ property coverage");
    if (!key.has_value()) {
        return;
    }

    Result<purify::puresign_plusplus::KeyPair> key_pair =
        purify::puresign_plusplus::KeyPair::from_secret(key->secret);
    expect_ok(ctx, key_pair, "PureSign++ KeyPair::from_secret succeeds for randomized coverage");
    if (!key_pair.has_value()) {
        return;
    }
    const purify::puresign_plusplus::PublicKey& public_key = key_pair->public_key();

    Bytes message = random_bytes(rng, 1, 40);
    Result<purify::puresign_plusplus::Signature> direct = key_pair->sign_message(message);
    expect_ok(ctx, direct, "PureSign++ KeyPair::sign_message succeeds for randomized coverage");

    Result<purify::puresign_plusplus::ProvenSignature> proven = key_pair->sign_message_with_proof(message);
    expect_ok(ctx, proven, "PureSign++ KeyPair::sign_message_with_proof succeeds for randomized coverage");
    if (!direct.has_value() || !proven.has_value()) {
        return;
    }

    ctx.expect(direct->bytes == proven->signature.bytes,
               "PureSign++ sign_message_with_proof preserves deterministic BIP340 bytes");

    Result<bool> verified = public_key.verify_message_signature_with_proof(message, *proven);
    expect_ok(ctx, verified, "PureSign++ PublicKey::verify_message_signature_with_proof succeeds");
    if (verified.has_value()) {
        ctx.expect(*verified, "randomized PureSign++ message signature with proof verifies");
    }

    Result<bool> wrong_message = public_key.verify_message_signature_with_proof(random_bytes(rng, 1, 24), *proven);
    expect_ok(ctx, wrong_message, "PureSign++ PublicKey::verify_message_signature_with_proof runs on a wrong message");
    if (wrong_message.has_value()) {
        ctx.expect(!*wrong_message, "PureSign++ message proof rejects a mismatched message");
    }

    ctx.expect(proven_signature_plusplus_rejected_after_tamper(public_key, message, *proven),
               "tampering a PureSign++ ProvenSignature is rejected");
}

}  // namespace

int main() {
    TestContext ctx;

    test_seeded_key_and_circuit_properties(ctx);
    test_random_experimental_proof_properties(ctx);
    test_template_split_eval_differential(ctx);
    test_assume_valid_proof_matches_validated_proof(ctx);
    test_random_puresign_proven_signature_properties(ctx);
    test_random_puresign_plusplus_proven_signature_properties(ctx);

    if (ctx.failures != 0) {
        std::cerr << ctx.failures << " property test(s) failed\n";
        return 1;
    }

    std::cout << "all property tests passed\n";
    return 0;
}
