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
    ctx.expect(result.has_value(), message);
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

void test_secret_key_validation(TestContext& ctx) {
    Bytes message = sample_message();

    UInt512 invalid = purify::key_space_size();
    expect_error(ctx, purify::derive_key(invalid), ErrorCode::RangeViolation,
                 "derive_key rejects the packed-secret upper bound");
    expect_error(ctx, purify::eval(invalid, message), ErrorCode::RangeViolation,
                 "eval rejects the packed-secret upper bound");
    expect_error(ctx, purify::prove_assignment_data(message, invalid), ErrorCode::RangeViolation,
                 "prove_assignment_data rejects the packed-secret upper bound");

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

void test_bppp_move_overload(TestContext& ctx) {
    purify::bppp::NormArgInputs inputs;
    Result<purify::bppp::NormArgProof> proof = purify::bppp::prove_norm_arg(std::move(inputs));
    expect_error(ctx, proof, ErrorCode::EmptyInput, "rvalue prove_norm_arg overload preserves empty-input validation");
}

}  // namespace

int main() {
    TestContext ctx;

    test_known_sample(ctx);
    test_secret_hardening_path(ctx);
    test_library_key_generation(ctx);
    test_secret_key_validation(ctx);
    test_public_key_validation(ctx);
    test_equal_lowering(ctx);
    test_bppp_move_overload(ctx);

    if (ctx.failures != 0) {
        std::cerr << ctx.failures << " test(s) failed\n";
        return 1;
    }

    std::cout << "all tests passed\n";
    return 0;
}
