// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <iostream>
#include <string_view>

#include "purify.hpp"

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
    vars["v[0]"] = FieldElement::one();
    vars["V0"] = FieldElement::zero();
    Result<BulletproofAssignmentData> bad_assignment = bp.assignment_data(vars);
    expect_ok(ctx, bad_assignment, "assignment_data materializes a raw-witness equality assignment");
    if (bad_assignment.has_value()) {
        ctx.expect(!circuit.evaluate(*bad_assignment), "lowered equality constraint rejects a non-zero witness");
    }

    vars["v[0]"] = FieldElement::zero();
    Result<BulletproofAssignmentData> good_assignment = bp.assignment_data(vars);
    expect_ok(ctx, good_assignment, "assignment_data materializes a satisfying raw-witness equality assignment");
    if (good_assignment.has_value()) {
        ctx.expect(circuit.evaluate(*good_assignment), "lowered equality constraint accepts the satisfying witness");
    }
}

}  // namespace

int main() {
    TestContext ctx;

    test_known_sample(ctx);
    test_secret_key_validation(ctx);
    test_public_key_validation(ctx);
    test_equal_lowering(ctx);

    if (ctx.failures != 0) {
        std::cerr << ctx.failures << " test(s) failed\n";
        return 1;
    }

    std::cout << "all tests passed\n";
    return 0;
}
