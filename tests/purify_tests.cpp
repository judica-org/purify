// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <iostream>
#include <string_view>
#include <utility>

#include "purify.hpp"
#include "purify_bppp.hpp"

namespace {

using purify::BulletproofAssignmentData;
using purify::BulletproofTranscript;
using purify::Bytes;
using purify::ErrorCode;
using purify::Expr;
using purify::FieldElement;
using purify::NativeBulletproofCircuit;
using purify::Result;
using purify::Status;
using purify::Transcript;
using purify::UInt512;

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
        std::cerr << "FAIL: " << message << " (" << result.error().name() << ")\n";
        ++ctx.failures;
        return;
    }
    ctx.expect(true, message);
}

void expect_ok(TestContext& ctx, const Status& status, std::string_view message) {
    ctx.expect(status.has_value(), message);
}

template <typename T>
void expect_error(TestContext& ctx, const Result<T>& result, ErrorCode code, std::string_view message) {
    ctx.expect(!result.has_value() && result.error().code == code, message);
}

Bytes sample_message() {
    return Bytes{0x01, 0x23, 0x45, 0x67};
}

Result<UInt512> sample_secret() {
    return UInt512::try_from_hex(
        "11427c7268288dddf0cd24af3d30524fd817a91e103e7e02eb28b78db81cb350"
        "b3d2562f45fa8ecd711d1becc02fa348cf2187429228e7aac6644a3da2824e93");
}

std::string hex32(const std::array<unsigned char, 32>& bytes) {
    return purify::UInt256::from_bytes_be(bytes.data(), bytes.size()).to_hex();
}

void test_known_sample(TestContext& ctx) {
    Result<UInt512> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses");
    if (!secret.has_value()) {
        return;
    }

    Bytes message = sample_message();
    Result<FieldElement> value = purify::eval(*secret, message);
    expect_ok(ctx, value, "sample eval succeeds");
    if (value.has_value()) {
        ctx.expect(value->to_hex() == "afae82108c66397451ce376bc95751c398e40eaf8c768d1b18cc9dd4161cee35",
                   "sample eval matches the reference output");
    }

    Result<purify::BulletproofWitnessData> witness = purify::prove_assignment_data(message, *secret);
    expect_ok(ctx, witness, "sample witness generation succeeds");
    if (!witness.has_value()) {
        return;
    }

    Result<bool> verifier_ok = purify::evaluate_verifier_circuit(message, *witness);
    expect_ok(ctx, verifier_ok, "sample verifier circuit evaluation succeeds");
    if (verifier_ok.has_value()) {
        ctx.expect(*verifier_ok, "sample verifier circuit accepts the generated witness");
    }

    Result<std::string> verifier_program = purify::verifier(message, witness->public_key);
    expect_ok(ctx, verifier_program, "sample verifier serialization succeeds");
    if (verifier_program.has_value()) {
        ctx.expect(!verifier_program->empty(), "sample verifier serialization is non-empty");
    }

    Result<Bytes> assignment = purify::prove_assignment(message, *secret);
    expect_ok(ctx, assignment, "sample assignment serialization succeeds");
    if (assignment.has_value()) {
        ctx.expect(!assignment->empty(), "sample assignment serialization is non-empty");
    }
}

void test_secret_hardening_path(TestContext& ctx) {
    Result<UInt512> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for secret hardening checks");
    if (!secret.has_value()) {
        return;
    }

    Result<std::pair<purify::UInt256, purify::UInt256>> unpacked = purify::unpack_secret(*secret);
    expect_ok(ctx, unpacked, "sample secret unpacks for hardened multiplication checks");
    if (!unpacked.has_value()) {
        return;
    }

    Bytes message = sample_message();
    Bytes m1_input = purify::bytes_from_ascii("Eval/1/");
    m1_input.insert(m1_input.end(), message.begin(), message.end());
    Result<purify::JacobianPoint> m1 = purify::hash_to_curve(m1_input, purify::curve1());
    expect_ok(ctx, m1, "hash_to_curve for curve1 succeeds in hardened multiplication checks");
    Bytes m2_input = purify::bytes_from_ascii("Eval/2/");
    m2_input.insert(m2_input.end(), message.begin(), message.end());
    Result<purify::JacobianPoint> m2 = purify::hash_to_curve(m2_input, purify::curve2());
    expect_ok(ctx, m2, "hash_to_curve for curve2 succeeds in hardened multiplication checks");
    if (!m1.has_value() || !m2.has_value()) {
        return;
    }

    purify::AffinePoint p1_public = purify::curve1().affine(purify::curve1().mul(purify::generator1(), unpacked->first));
    purify::AffinePoint p2_public = purify::curve2().affine(purify::curve2().mul(purify::generator2(), unpacked->second));
    purify::AffinePoint q1_public = purify::curve1().affine(purify::curve1().mul(*m1, unpacked->first));
    purify::AffinePoint q2_public = purify::curve2().affine(purify::curve2().mul(*m2, unpacked->second));

    Result<purify::AffinePoint> p1_secret = purify::curve1().mul_secret_affine(purify::generator1(), unpacked->first);
    expect_ok(ctx, p1_secret, "hardened generator multiplication succeeds on curve1");
    Result<purify::AffinePoint> p2_secret = purify::curve2().mul_secret_affine(purify::generator2(), unpacked->second);
    expect_ok(ctx, p2_secret, "hardened generator multiplication succeeds on curve2");
    Result<purify::AffinePoint> q1_secret = purify::curve1().mul_secret_affine(*m1, unpacked->first);
    expect_ok(ctx, q1_secret, "hardened message multiplication succeeds on curve1");
    Result<purify::AffinePoint> q2_secret = purify::curve2().mul_secret_affine(*m2, unpacked->second);
    expect_ok(ctx, q2_secret, "hardened message multiplication succeeds on curve2");
    if (!p1_secret.has_value() || !p2_secret.has_value() || !q1_secret.has_value() || !q2_secret.has_value()) {
        return;
    }

    ctx.expect(p1_secret->x == p1_public.x && p1_secret->y == p1_public.y,
               "hardened curve1 generator multiplication matches the existing arithmetic");
    ctx.expect(p2_secret->x == p2_public.x && p2_secret->y == p2_public.y,
               "hardened curve2 generator multiplication matches the existing arithmetic");
    ctx.expect(q1_secret->x == q1_public.x && q1_secret->y == q1_public.y,
               "hardened curve1 message multiplication matches the existing arithmetic");
    ctx.expect(q2_secret->x == q2_public.x && q2_secret->y == q2_public.y,
               "hardened curve2 message multiplication matches the existing arithmetic");
}

void test_library_key_generation(TestContext& ctx) {
    std::array<unsigned char, 32> seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<unsigned char>(i);
    }

    Result<purify::GeneratedKey> seeded_a = purify::generate_key(std::span<const unsigned char>(seed));
    expect_ok(ctx, seeded_a, "seeded generate_key succeeds");
    Result<purify::GeneratedKey> seeded_b = purify::generate_key(std::span<const unsigned char>(seed));
    expect_ok(ctx, seeded_b, "seeded generate_key is repeatable");
    if (seeded_a.has_value() && seeded_b.has_value()) {
        ctx.expect(seeded_a->secret == seeded_b->secret, "seeded generate_key is deterministic");
        ctx.expect(seeded_a->public_key == seeded_b->public_key, "seeded generate_key derives a stable public key");
    }

    Bytes short_seed(15, 0x42);
    expect_error(ctx, purify::generate_key(std::span<const unsigned char>(short_seed)), ErrorCode::RangeViolation,
                 "generate_key rejects seed material shorter than 16 bytes");

    std::array<unsigned char, 16> min_seed{};
    for (std::size_t i = 0; i < min_seed.size(); ++i) {
        min_seed[i] = static_cast<unsigned char>(0xa0 + i);
    }
    Result<purify::GeneratedKey> min_seed_a = purify::generate_key(std::span<const unsigned char>(min_seed));
    expect_ok(ctx, min_seed_a, "minimum-length seeded generate_key succeeds");
    Result<purify::GeneratedKey> min_seed_b = purify::generate_key(std::span<const unsigned char>(min_seed));
    expect_ok(ctx, min_seed_b, "minimum-length seeded generate_key is repeatable");
    if (min_seed_a.has_value() && min_seed_b.has_value()) {
        ctx.expect(min_seed_a->secret == min_seed_b->secret, "minimum-length seeded generate_key is deterministic");
        ctx.expect(min_seed_a->public_key == min_seed_b->public_key,
                   "minimum-length seeded generate_key derives a stable public key");
    }

    auto fill_one = [](std::span<unsigned char> bytes) noexcept {
        std::fill(bytes.begin(), bytes.end(), static_cast<unsigned char>(0));
        if (!bytes.empty()) {
            bytes.back() = 1;
        }
    };
    Result<purify::GeneratedKey> callable_key = purify::generate_key(fill_one);
    expect_ok(ctx, callable_key, "generate_key accepts a no-fail byte-fill callable");
    Result<purify::GeneratedKey> expected_one = purify::derive_key(purify::UInt512::one());
    expect_ok(ctx, expected_one, "derive_key succeeds for the packed secret one");
    if (callable_key.has_value() && expected_one.has_value()) {
        ctx.expect(callable_key->secret == expected_one->secret, "callable-based generate_key uses the supplied bytes");
        ctx.expect(callable_key->public_key == expected_one->public_key,
                   "callable-based generate_key derives the expected public key");
    }

    auto fill_two = [](std::span<unsigned char> bytes) noexcept -> Status {
        std::fill(bytes.begin(), bytes.end(), static_cast<unsigned char>(0));
        if (!bytes.empty()) {
            bytes.back() = 2;
        }
        return {};
    };
    Result<purify::GeneratedKey> checked_callable_key = purify::generate_key(fill_two);
    expect_ok(ctx, checked_callable_key, "generate_key accepts a checked byte-fill callable");

    Result<purify::GeneratedKey> os_key = purify::generate_key();
    expect_ok(ctx, os_key, "default generate_key succeeds");
    if (os_key.has_value()) {
        ctx.expect(purify::is_valid_secret_key(os_key->secret), "default generate_key returns a canonical packed secret");
        Result<purify::GeneratedKey> roundtrip = purify::derive_key(os_key->secret);
        expect_ok(ctx, roundtrip, "default generate_key output round-trips through derive_key");
        if (roundtrip.has_value()) {
            ctx.expect(roundtrip->public_key == os_key->public_key,
                       "default generate_key public key matches a round-trip derivation");
        }
    }
}

void test_bip340_key_derivation(TestContext& ctx) {
    Result<UInt512> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for BIP340 derivation");
    if (!secret.has_value()) {
        return;
    }

    Result<purify::Bip340Key> key_a = purify::derive_bip340_key(*secret);
    expect_ok(ctx, key_a, "derive_bip340_key succeeds");
    Result<purify::Bip340Key> key_b = purify::derive_bip340_key(*secret);
    expect_ok(ctx, key_b, "derive_bip340_key is deterministic");
    if (!key_a.has_value() || !key_b.has_value()) {
        return;
    }

    ctx.expect(key_a->seckey == key_b->seckey, "derive_bip340_key returns a stable secret key");
    ctx.expect(key_a->xonly_pubkey == key_b->xonly_pubkey, "derive_bip340_key returns a stable x-only pubkey");
    ctx.expect(hex32(key_a->seckey) == "d63b91a76a1231be98f516d544312b7337ece46564e002ed50df0cd77a1b610e",
               "derive_bip340_key matches the expected sample canonical seckey");
    ctx.expect(hex32(key_a->xonly_pubkey) == "82b3533efb11978a9447ba70d452f022d10bd9b8347985fdc9b36aa984190856",
               "derive_bip340_key matches the expected sample x-only pubkey");

    std::array<unsigned char, 32> canonical = key_a->seckey;
    std::array<unsigned char, 32> xonly = {};
    ctx.expect(purify_bip340_key_from_seckey(canonical.data(), xonly.data()) == 1,
               "bridge accepts the derived canonical BIP340 secret key");
    ctx.expect(canonical == key_a->seckey,
               "derive_bip340_key returns an idempotently canonicalized even-Y secret key");
    ctx.expect(xonly == key_a->xonly_pubkey,
               "derived x-only pubkey matches the canonical secret key");
}

void test_secret_key_validation(TestContext& ctx) {
    Bytes message = sample_message();

    UInt512 invalid = purify::key_space_size();
    expect_error(ctx, purify::derive_key(invalid), ErrorCode::RangeViolation,
                 "derive_key rejects the packed-secret upper bound");
    expect_error(ctx, purify::eval(invalid, message), ErrorCode::RangeViolation,
                 "eval rejects the packed-secret upper bound");
    expect_error(ctx, purify::prove_assignment_data(message, invalid), ErrorCode::RangeViolation,
                 "prove_assignment_data rejects the packed-secret upper bound");
    expect_error(ctx, purify::derive_bip340_key(invalid), ErrorCode::RangeViolation,
                 "derive_bip340_key rejects the packed-secret upper bound");

    UInt512 last_valid = purify::key_space_size();
    last_valid.sub_assign(purify::widen<8>(purify::half_n1()));
    expect_ok(ctx, purify::derive_key(last_valid), "derive_key accepts the last canonical packed secret");
}

void test_public_key_validation(TestContext& ctx) {
    Bytes message = sample_message();

    UInt512 invalid = purify::packed_public_key_space_size();
    expect_error(ctx, purify::verifier(message, invalid), ErrorCode::RangeViolation,
                 "verifier rejects the packed-public-key upper bound");
    expect_error(ctx, purify::verifier_circuit(message, invalid), ErrorCode::RangeViolation,
                 "verifier_circuit rejects the packed-public-key upper bound");
}

void test_equal_lowering(TestContext& ctx) {
    Transcript transcript;
    Expr witness = transcript.secret(std::nullopt);
    transcript.equal(witness, Expr(0));

    BulletproofTranscript bp;
    Status lower_status = bp.from_transcript(transcript, 0);
    expect_ok(ctx, lower_status, "from_transcript lowers equality constraints with raw witnesses");
    if (!lower_status.has_value()) {
        return;
    }

    NativeBulletproofCircuit circuit = bp.native_circuit();
    auto vars = transcript.varmap();
    vars[0] = FieldElement::one();
    Result<BulletproofAssignmentData> bad_assignment = bp.assignment_data(vars, FieldElement::zero());
    expect_ok(ctx, bad_assignment, "assignment_data materializes a raw-witness equality assignment");
    if (bad_assignment.has_value()) {
        ctx.expect(!circuit.evaluate(*bad_assignment), "lowered equality constraint rejects a non-zero witness");
    }

    vars[0] = FieldElement::zero();
    Result<BulletproofAssignmentData> good_assignment = bp.assignment_data(vars, FieldElement::zero());
    expect_ok(ctx, good_assignment, "assignment_data materializes a satisfying raw-witness equality assignment");
    if (good_assignment.has_value()) {
        ctx.expect(circuit.evaluate(*good_assignment), "lowered equality constraint accepts the satisfying witness");
    }
}

void test_expr_builder(TestContext& ctx) {
    Transcript transcript;
    Expr x = transcript.secret(FieldElement::from_int(3));
    Expr y = transcript.secret(FieldElement::from_int(5));

    Expr built = purify::ExprBuilder::reserved(x.linear().size() + y.linear().size())
        .add(7)
        .add_scaled(x, 2)
        .add_scaled(y, -3)
        .build();
    Expr expected = Expr(7) + 2 * x - 3 * y;

    ctx.expect(built == expected, "ExprBuilder flattens affine combinations equivalently");
    ctx.expect(transcript.evaluate(built) == transcript.evaluate(expected),
               "ExprBuilder preserves affine evaluation semantics");
}

void test_bppp_move_overload(TestContext& ctx) {
    purify::bppp::NormArgInputs inputs;
    Result<purify::bppp::NormArgProof> proof = purify::bppp::prove_norm_arg(std::move(inputs));
    expect_error(ctx, proof, ErrorCode::EmptyInput, "rvalue prove_norm_arg overload preserves empty-input validation");
}

void test_experimental_bulletproof_roundtrip(TestContext& ctx) {
    NativeBulletproofCircuit circuit(1, 1, 0);
    std::size_t constraint = circuit.add_constraint(FieldElement::zero());
    circuit.add_output_term(0, constraint, FieldElement::one());
    circuit.add_commitment_term(0, constraint, FieldElement::from_int(-1));

    BulletproofAssignmentData assignment;
    assignment.left = {FieldElement::from_int(3)};
    assignment.right = {FieldElement::from_int(4)};
    assignment.output = {FieldElement::from_int(12)};
    assignment.commitments = {FieldElement::from_int(12)};

    std::array<unsigned char, 32> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<unsigned char>(i + 1);
    }
    Bytes binding = purify::bytes_from_ascii("toy-circuit-binding");

    Result<purify::ExperimentalBulletproofProof> proof =
        purify::prove_experimental_circuit(circuit, assignment, nonce, purify::bppp::base_generator(), binding);
    expect_ok(ctx, proof, "prove_experimental_circuit succeeds on a one-gate circuit");
    if (!proof.has_value()) {
        return;
    }

    ctx.expect(proof->commitment != purify::BulletproofPointBytes{},
               "experimental circuit proof includes a concrete public commitment");

    Result<bool> verified =
        purify::verify_experimental_circuit(circuit, *proof, purify::bppp::base_generator(), binding);
    expect_ok(ctx, verified, "verify_experimental_circuit succeeds on the generated proof");
    if (verified.has_value()) {
        ctx.expect(*verified, "experimental circuit proof verifies");
    }

    Result<Bytes> encoded = proof->serialize();
    expect_ok(ctx, encoded, "ExperimentalBulletproofProof serializes");
    if (!encoded.has_value()) {
        return;
    }
    Result<purify::ExperimentalBulletproofProof> decoded =
        purify::ExperimentalBulletproofProof::deserialize(*encoded);
    expect_ok(ctx, decoded, "ExperimentalBulletproofProof round-trips");
    if (!decoded.has_value()) {
        return;
    }

    Result<bool> reparsed =
        purify::verify_experimental_circuit(circuit, *decoded, purify::bppp::base_generator(), binding);
    expect_ok(ctx, reparsed, "verify_experimental_circuit accepts the reparsed proof");
    if (reparsed.has_value()) {
        ctx.expect(*reparsed, "reparsed experimental circuit proof verifies");
    }

    Result<bool> wrong_binding =
        purify::verify_experimental_circuit(circuit, *proof, purify::bppp::base_generator(),
                                            purify::bytes_from_ascii("toy-circuit-binding-wrong"));
    expect_ok(ctx, wrong_binding, "verify_experimental_circuit runs with a wrong binding");
    if (wrong_binding.has_value()) {
        ctx.expect(!*wrong_binding, "experimental circuit proof is bound to the supplied statement bytes");
    }
}

void test_puresign_message_signing(TestContext& ctx) {
    Result<UInt512> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for PureSign message signing");
    if (!secret.has_value()) {
        return;
    }

    Bytes message = sample_message();

    Result<purify::puresign::PublicKey> public_key = purify::puresign::derive_public_key(*secret);
    expect_ok(ctx, public_key, "derive_public_key succeeds");
    Result<purify::puresign::PreparedNonceWithProof> prepared_with_proof =
        purify::puresign::prepare_message_nonce_with_proof(*secret, message);
    expect_ok(ctx, prepared_with_proof, "prepare_message_nonce_with_proof succeeds");
    Result<purify::puresign::PreparedNonce> prepared_a = purify::puresign::prepare_message_nonce(*secret, message);
    expect_ok(ctx, prepared_a, "prepare_message_nonce succeeds");
    Result<purify::puresign::PreparedNonce> prepared_b = purify::puresign::prepare_message_nonce(*secret, message);
    expect_ok(ctx, prepared_b, "prepare_message_nonce is deterministic");
    if (!public_key.has_value() || !prepared_with_proof.has_value() || !prepared_a.has_value() || !prepared_b.has_value()) {
        return;
    }

    Result<bool> nonce_proof_ok =
        purify::puresign::verify_message_nonce_proof(*public_key, message, prepared_with_proof->proof());
    expect_ok(ctx, nonce_proof_ok, "verify_message_nonce_proof succeeds on the generated proof");
    if (nonce_proof_ok.has_value()) {
        ctx.expect(*nonce_proof_ok, "generated message-bound nonce proof verifies");
    }
    Result<bool> wrong_nonce_proof =
        purify::puresign::verify_message_nonce_proof(*public_key, Bytes{0x89}, prepared_with_proof->proof());
    expect_ok(ctx, wrong_nonce_proof, "verify_message_nonce_proof runs on a wrong message");
    if (wrong_nonce_proof.has_value()) {
        ctx.expect(!*wrong_nonce_proof, "message-bound nonce proof rejects a different message");
    }

    ctx.expect(prepared_a->public_nonce().xonly == prepared_b->public_nonce().xonly,
               "message-bound public nonces are deterministic");
    ctx.expect(prepared_a->scalar() == prepared_b->scalar(),
               "message-bound secret nonce scalars are deterministic");

    Result<purify::puresign::Signature> direct = purify::puresign::sign_message(*secret, message);
    expect_ok(ctx, direct, "sign_message succeeds");
    Result<purify::puresign::Signature> cached =
        purify::puresign::sign_message_with_prepared(*secret, message, std::move(*prepared_a));
    expect_ok(ctx, cached, "sign_message_with_prepared succeeds");
    if (!direct.has_value() || !cached.has_value()) {
        return;
    }

    Result<purify::puresign::ProvenSignature> proven =
        purify::puresign::sign_message_with_prepared_proof(*secret, message, std::move(*prepared_with_proof));
    expect_ok(ctx, proven, "sign_message_with_prepared_proof succeeds");
    if (proven.has_value()) {
        Result<bool> proven_ok =
            purify::puresign::verify_message_signature_with_proof(*public_key, message, *proven);
        expect_ok(ctx, proven_ok, "verify_message_signature_with_proof succeeds");
        if (proven_ok.has_value()) {
            ctx.expect(*proven_ok, "message signature with proof verifies");
        }

        Result<Bytes> nonce_proof_bytes = proven->nonce_proof.serialize();
        expect_ok(ctx, nonce_proof_bytes, "NonceProof serializes");
        if (nonce_proof_bytes.has_value()) {
            ctx.expect(!nonce_proof_bytes->empty() && (*nonce_proof_bytes)[0] == 2,
                       "NonceProof uses the unique-derivation wire format version");
            Result<purify::puresign::NonceProof> parsed_nonce_proof =
                purify::puresign::NonceProof::deserialize(*nonce_proof_bytes);
            expect_ok(ctx, parsed_nonce_proof, "NonceProof round-trips");

            Bytes legacy_nonce_proof = *nonce_proof_bytes;
            legacy_nonce_proof[0] = 1;
            expect_error(ctx, purify::puresign::NonceProof::deserialize(legacy_nonce_proof),
                         ErrorCode::BackendRejectedInput,
                         "NonceProof rejects the old counter-bearing wire format");
        }

        Result<Bytes> proven_bytes = proven->serialize();
        expect_ok(ctx, proven_bytes, "ProvenSignature serializes");
        if (proven_bytes.has_value()) {
            Result<purify::puresign::ProvenSignature> parsed_proven =
                purify::puresign::ProvenSignature::deserialize(*proven_bytes);
            expect_ok(ctx, parsed_proven, "ProvenSignature round-trips");
            if (parsed_proven.has_value()) {
                Result<bool> parsed_ok =
                    purify::puresign::verify_message_signature_with_proof(*public_key, message, *parsed_proven);
                expect_ok(ctx, parsed_ok, "parsed message signature with proof verifies");
                if (parsed_ok.has_value()) {
                    ctx.expect(*parsed_ok, "parsed message signature with proof is accepted");
                }
            }
        }
    }

    ctx.expect(direct->bytes == cached->bytes, "cached message-bound signing matches direct signing");
    ctx.expect(direct->nonce().xonly == prepared_b->public_nonce().xonly,
               "signature nonce matches the prepared public nonce");

    Result<bool> verified = purify::puresign::verify_signature(*public_key, message, *direct);
    expect_ok(ctx, verified, "verify_signature succeeds on a PureSign message signature");
    if (verified.has_value()) {
        ctx.expect(*verified, "PureSign message signature verifies");
    }

    Bytes public_key_bytes = public_key->serialize();
    ctx.expect(public_key_bytes.size() == purify::puresign::PublicKey::kSerializedSize,
               "PureSign public key serialization has the expected size");
    Result<purify::puresign::PublicKey> parsed_public_key = purify::puresign::PublicKey::deserialize(public_key_bytes);
    expect_ok(ctx, parsed_public_key, "PureSign public key round-trips");

    Bytes nonce_bytes = prepared_b->public_nonce().serialize();
    ctx.expect(nonce_bytes.size() == purify::puresign::Nonce::kSerializedSize,
               "PureSign nonce serialization has the expected size");
    Result<purify::puresign::Nonce> parsed_nonce = purify::puresign::Nonce::deserialize(nonce_bytes);
    expect_ok(ctx, parsed_nonce, "PureSign nonce round-trips");
    if (parsed_nonce.has_value()) {
        ctx.expect(parsed_nonce->xonly == prepared_b->public_nonce().xonly, "PureSign nonce deserialization preserves x-only bytes");
    }

    Bytes signature_bytes = direct->serialize();
    ctx.expect(signature_bytes.size() == purify::puresign::Signature::kSerializedSize,
               "PureSign signature serialization has the expected size");
    Result<purify::puresign::Signature> parsed_signature = purify::puresign::Signature::deserialize(signature_bytes);
    expect_ok(ctx, parsed_signature, "PureSign signature round-trips");
    if (parsed_public_key.has_value() && parsed_signature.has_value()) {
        Result<bool> reparsed_verified = purify::puresign::verify_signature(*parsed_public_key, message, *parsed_signature);
        expect_ok(ctx, reparsed_verified, "verify_signature accepts parsed PureSign artifacts");
        if (reparsed_verified.has_value()) {
            ctx.expect(*reparsed_verified, "parsed PureSign artifacts verify");
        }
    }
}

void test_puresign_topic_signing(TestContext& ctx) {
    Result<UInt512> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for PureSign topic signing");
    if (!secret.has_value()) {
        return;
    }

    Bytes message = sample_message();
    Bytes topic = purify::bytes_from_ascii("session-1");

    Result<purify::puresign::PublicKey> public_key = purify::puresign::derive_public_key(*secret);
    expect_ok(ctx, public_key, "derive_public_key succeeds for topic signing");
    Result<purify::puresign::PreparedNonceWithProof> prepared_with_proof =
        purify::puresign::prepare_topic_nonce_with_proof(*secret, topic);
    expect_ok(ctx, prepared_with_proof, "prepare_topic_nonce_with_proof succeeds");
    Result<purify::puresign::PreparedNonce> prepared_a = purify::puresign::prepare_topic_nonce(*secret, topic);
    expect_ok(ctx, prepared_a, "prepare_topic_nonce succeeds");
    Result<purify::puresign::PreparedNonce> prepared_b = purify::puresign::prepare_topic_nonce(*secret, topic);
    expect_ok(ctx, prepared_b, "prepare_topic_nonce is deterministic");
    if (!public_key.has_value() || !prepared_with_proof.has_value() || !prepared_a.has_value() || !prepared_b.has_value()) {
        return;
    }

    Result<bool> nonce_proof_ok =
        purify::puresign::verify_topic_nonce_proof(*public_key, topic, prepared_with_proof->proof());
    expect_ok(ctx, nonce_proof_ok, "verify_topic_nonce_proof succeeds on the generated proof");
    if (nonce_proof_ok.has_value()) {
        ctx.expect(*nonce_proof_ok, "generated topic-bound nonce proof verifies");
    }

    ctx.expect(prepared_a->public_nonce().xonly == prepared_b->public_nonce().xonly,
               "topic-bound public nonces are deterministic");
    ctx.expect(prepared_a->scalar() == prepared_b->scalar(),
               "topic-bound secret nonce scalars are deterministic");

    Result<purify::puresign::Signature> direct = purify::puresign::sign_with_topic(*secret, message, topic);
    expect_ok(ctx, direct, "sign_with_topic succeeds");
    Result<purify::puresign::Signature> cached =
        purify::puresign::sign_with_prepared_topic(*secret, message, std::move(*prepared_a));
    expect_ok(ctx, cached, "sign_with_prepared_topic succeeds");
    if (!direct.has_value() || !cached.has_value()) {
        return;
    }

    Result<purify::puresign::ProvenSignature> proven =
        purify::puresign::sign_with_prepared_topic_proof(*secret, message, std::move(*prepared_with_proof));
    expect_ok(ctx, proven, "sign_with_prepared_topic_proof succeeds");
    if (proven.has_value()) {
        Result<bool> proven_ok =
            purify::puresign::verify_topic_signature_with_proof(*public_key, message, topic, *proven);
        expect_ok(ctx, proven_ok, "verify_topic_signature_with_proof succeeds");
        if (proven_ok.has_value()) {
            ctx.expect(*proven_ok, "topic-bound signature with proof verifies");
        }
    }

    ctx.expect(direct->bytes == cached->bytes, "cached topic-bound signing matches direct signing");
    ctx.expect(direct->nonce().xonly == prepared_b->public_nonce().xonly,
               "topic-bound signature nonce matches the prepared public nonce");

    expect_error(ctx, purify::puresign::prepare_topic_nonce(*secret, Bytes{}), ErrorCode::EmptyInput,
                 "prepare_topic_nonce rejects an empty topic");
}

void test_puresign_binding_checks(TestContext& ctx) {
    Result<UInt512> secret = sample_secret();
    expect_ok(ctx, secret, "sample secret parses for PureSign binding checks");
    if (!secret.has_value()) {
        return;
    }

    Bytes message = sample_message();
    Bytes wrong_message = Bytes{0x89, 0xab};
    Bytes topic = purify::bytes_from_ascii("session-2");

    Result<purify::puresign::PreparedNonce> message_nonce = purify::puresign::prepare_message_nonce(*secret, message);
    expect_ok(ctx, message_nonce, "prepare_message_nonce succeeds for binding checks");
    if (message_nonce.has_value()) {
        expect_error(ctx, purify::puresign::sign_message_with_prepared(*secret, wrong_message, std::move(*message_nonce)),
                     ErrorCode::BindingMismatch,
                     "message-bound prepared nonces reject signing a different message");
    }

    Result<purify::puresign::PreparedNonce> topic_nonce = purify::puresign::prepare_topic_nonce(*secret, topic);
    expect_ok(ctx, topic_nonce, "prepare_topic_nonce succeeds for binding checks");
    if (topic_nonce.has_value()) {
        expect_error(ctx, purify::puresign::sign_message_with_prepared(*secret, message, std::move(*topic_nonce)),
                     ErrorCode::BindingMismatch,
                     "topic-bound prepared nonces reject the message-bound signing API");
    }
}

}  // namespace

int main() {
    TestContext ctx;

    test_known_sample(ctx);
    test_secret_hardening_path(ctx);
    test_library_key_generation(ctx);
    test_bip340_key_derivation(ctx);
    test_secret_key_validation(ctx);
    test_public_key_validation(ctx);
    test_equal_lowering(ctx);
    test_expr_builder(ctx);
    test_bppp_move_overload(ctx);
    test_experimental_bulletproof_roundtrip(ctx);
    test_puresign_message_signing(ctx);
    test_puresign_topic_signing(ctx);
    test_puresign_binding_checks(ctx);

    if (ctx.failures != 0) {
        std::cerr << ctx.failures << " test(s) failed\n";
        return 1;
    }

    std::cout << "all tests passed\n";
    return 0;
}
