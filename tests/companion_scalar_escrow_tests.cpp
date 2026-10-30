// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <optional>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "purify/bppp.hpp"
#include "purify/puresign/accountable.hpp"
#include "test_harness.hpp"

namespace {

using purify_test::TestContext;
using purify_test::expect_ok;
using purify::Bytes;
using purify::Expr;
using purify::FieldElement;
using purify::Result;
using purify::UInt256;
using purify::UInt512;
using PointPair = std::pair<purify::JacobianPoint, purify::JacobianPoint>;

// A local honest-witness experiment. No production codec, decryption service,
// malicious-prover soundness, chosen-ciphertext or MPC claim is made here.
struct Ciphertext {
    std::array<UInt512, 2> ephemeral;
    std::array<FieldElement, 2> masked;
};

struct Opening {
    const purify::SecretKey& payload;
    std::array<const purify::GeneratedKey*, 2> ephemeral;
};

Result<PointPair> decode_points(const UInt512& encoded) {
    PURIFY_ASSIGN_OR_RETURN(const auto& coords, purify::unpack_public(encoded), "scalar_escrow:unpack");
    PURIFY_ASSIGN_OR_RETURN(const auto& x1, FieldElement::try_from_uint256(coords.first), "scalar_escrow:x1");
    PURIFY_ASSIGN_OR_RETURN(const auto& x2, FieldElement::try_from_uint256(coords.second), "scalar_escrow:x2");
    const auto first = purify::curve1().lift_x(x1);
    const auto second = purify::curve2().lift_x(x2);
    if (!first || !second || first->infinity || second->infinity ||
        !purify::curve1().mul(*first, purify::order_n1()).infinity ||
        !purify::curve2().mul(*second, purify::order_n2()).infinity) {
        return purify::unexpected_error(purify::ErrorCode::BackendRejectedInput, "scalar_escrow:points");
    }
    return PointPair{*first, *second};
}

Result<purify::GeneratedKey> key_from_pair(UInt256 first, UInt256 second) {
    if (first.is_zero() || second.is_zero() || purify::half_n1() < first || purify::half_n2() < second) {
        return purify::unexpected_error(purify::ErrorCode::RangeViolation, "scalar_escrow:canonical_pair");
    }
    first.sub_assign(UInt256::one());
    second.sub_assign(UInt256::one());
    auto packed = purify::multiply(purify::half_n1(), second);
    packed.add_assign(purify::widen<8>(first));
    PURIFY_ASSIGN_OR_RETURN(auto secret, purify::SecretKey::from_packed(packed), "scalar_escrow:secret");
    return purify::derive_key(std::move(secret));
}

Result<purify::GeneratedKey> recipient_from_scalar(const FieldElement& scalar) {
    if (scalar.is_zero()) {
        return purify::unexpected_error(purify::ErrorCode::RangeViolation, "scalar_escrow:zero_coalition");
    }
    const auto value = scalar.to_uint256();
    const auto magnitude = purify::prime_p().shifted_right(1) < value ? scalar.negate().to_uint256() : value;
    auto first = magnitude;
    auto second = magnitude;
    if (purify::half_n1() < first) { first = purify::order_n1(); first.sub_assign(magnitude); }
    if (purify::half_n2() < second) { second = purify::order_n2(); second.sub_assign(magnitude); }
    return key_from_pair(first, second);
}

Result<FieldElement> shared_pad(const purify::SecretKey& secret, const UInt512& peer) {
    PURIFY_ASSIGN_OR_RETURN(const auto& scalars, purify::unpack_secret(secret.packed()), "scalar_escrow:secret");
    PURIFY_ASSIGN_OR_RETURN(const auto& points, decode_points(peer), "scalar_escrow:peer");
    PURIFY_ASSIGN_OR_RETURN(const auto& first,
        purify::curve1().mul_secret_affine(points.first, scalars.first), "scalar_escrow:shared_first");
    PURIFY_ASSIGN_OR_RETURN(const auto& second,
        purify::curve2().mul_secret_affine(points.second, scalars.second), "scalar_escrow:shared_second");
    return purify::combine(first.x, second.x);
}

Result<Ciphertext> encrypt(const UInt512& recipient, const Opening& opening) {
    PURIFY_ASSIGN_OR_RETURN(const auto& scalars, purify::unpack_secret(opening.payload.packed()), "scalar_escrow:payload");
    const std::array<UInt256, 2> payload{scalars.first, scalars.second};
    Ciphertext out;
    for (std::size_t i = 0; i < 2; ++i) {
        PURIFY_ASSIGN_OR_RETURN(const auto& pad, shared_pad(opening.ephemeral[i]->secret, recipient), "scalar_escrow:pad");
        out.ephemeral[i] = opening.ephemeral[i]->public_key;
        out.masked[i] = FieldElement::from_uint256(payload[i]) + pad;
    }
    return out;
}

Expr exceeds_bound(purify::Transcript& transcript, const std::vector<Expr>& bits, const UInt256& bound) {
    Expr equal_prefix(1);
    Expr exceeds(0);
    for (std::size_t i = bits.size(); i != 0; --i) {
        const Expr first_one = transcript.mul(equal_prefix, bits[i - 1]);
        if (bound.bit(i - 1)) equal_prefix = first_one;
        else {
            exceeds = exceeds + first_one;
            equal_prefix = equal_prefix - first_one;
        }
    }
    return exceeds;
}

std::vector<Expr> ordinary_bits(purify::Transcript& transcript, const std::optional<UInt256>& value) {
    std::vector<Expr> bits;
    bits.reserve(255);
    for (std::size_t i = 0; i < 255; ++i) {
        const auto bit = value ? std::optional<FieldElement>(FieldElement::from_u64(value->bit(i))) : std::nullopt;
        bits.push_back(transcript.boolean(transcript.secret(bit)));
    }
    return bits;
}

std::vector<Expr> signed_window_bits(purify::Transcript& transcript, const std::vector<Expr>& ordinary) {
    auto bits = ordinary;
    for (std::size_t i = 3; i < bits.size(); i += 3) {
        bits[i] = Expr(1) - ordinary[i];
        for (std::size_t offset : {1U, 2U}) {
            bits[i - offset] = Expr(1) - ordinary[i] - ordinary[i - offset]
                + 2 * transcript.mul(ordinary[i], ordinary[i - offset]);
        }
    }
    return bits;
}

Expr canonical_payload(purify::Transcript& transcript, const std::vector<Expr>& bits, UInt256 limit) {
    limit.sub_assign(UInt256::one());
    transcript.equal(exceeds_bound(transcript, bits, limit), Expr(0));
    Expr value(1);
    FieldElement power = FieldElement::one();
    for (const auto& bit : bits) {
        value = value + power * bit;
        power = power + power;
    }
    return value;
}

Result<purify::CircuitMainResult> escrow_relation(purify::Transcript& transcript, const UInt512& recipient,
                                                const Ciphertext& ciphertext, const Opening* opening) {
    PURIFY_ASSIGN_OR_RETURN(const auto& receiver, decode_points(recipient), "scalar_escrow:recipient");
    std::array<std::pair<UInt256, UInt256>, 2> ephemeral_coords;
    for (std::size_t i = 0; i < 2; ++i) {
        PURIFY_RETURN_IF_ERROR(decode_points(ciphertext.ephemeral[i]), "scalar_escrow:ephemeral");
        PURIFY_ASSIGN_OR_RETURN(ephemeral_coords[i], purify::unpack_public(ciphertext.ephemeral[i]), "scalar_escrow:coords");
    }
    std::array<std::optional<UInt256>, 2> payload_values;
    if (opening) {
        PURIFY_ASSIGN_OR_RETURN(const auto& pair, purify::unpack_secret(opening->payload.packed()), "scalar_escrow:payload");
        payload_values = {pair.first, pair.second};
        for (auto& value : payload_values) value->sub_assign(UInt256::one());
    }
    // Keep every Boolean gate first, before recoding, comparison or EC work.
    std::array<std::vector<Expr>, 2> payload_bits{
        ordinary_bits(transcript, payload_values[0]), ordinary_bits(transcript, payload_values[1])};
    // Only payloads need canonical half-order representatives. These signed
    // Boolean windows still encode nonzero scalars below each curve order;
    // x-only shared points are invariant under choosing the opposite sign.
    std::array<std::array<std::vector<Expr>, 2>, 2> ephemeral_bits;
    for (std::size_t i = 0; i < 2; ++i) {
        std::array<std::vector<int>, 2> values{std::vector<int>(255, -1), std::vector<int>(255, -1)};
        if (opening) {
            PURIFY_ASSIGN_OR_RETURN(const auto& pair, purify::unpack_secret(opening->ephemeral[i]->secret.packed()),
                                    "scalar_escrow:ephemeral_secret");
            PURIFY_ASSIGN_OR_RETURN(values[0], purify::key_to_bits(pair.first, purify::half_n1()), "scalar_escrow:r1_bits");
            PURIFY_ASSIGN_OR_RETURN(values[1], purify::key_to_bits(pair.second, purify::half_n2()), "scalar_escrow:r2_bits");
        }
        for (std::size_t component = 0; component < 2; ++component) {
            auto& bits = ephemeral_bits[i][component];
            bits.reserve(255);
            for (int bit : values[component]) {
                bits.push_back(transcript.boolean(transcript.secret(bit < 0 ? std::nullopt :
                    std::optional<FieldElement>(FieldElement::from_int(bit)))));
            }
        }
    }
    const std::array<Expr, 2> plaintext{
        canonical_payload(transcript, payload_bits[0], purify::half_n1()),
        canonical_payload(transcript, payload_bits[1], purify::half_n2())};
    const auto first_bits = signed_window_bits(transcript, payload_bits[0]);
    const auto second_bits = signed_window_bits(transcript, payload_bits[1]);
    const Expr first_key = purify::circuit_ec_multiply_x(purify::curve1(), transcript, purify::generator1(), first_bits);
    const Expr second_key = purify::circuit_ec_multiply_x(purify::curve2(), transcript, purify::generator2(), second_bits);
    for (std::size_t i = 0; i < 2; ++i) {
        const auto& bits = ephemeral_bits[i];
        const Expr a1 = purify::circuit_ec_multiply_x(purify::curve1(), transcript, purify::generator1(), bits[0]);
        const Expr a2 = purify::circuit_ec_multiply_x(purify::curve2(), transcript, purify::generator2(), bits[1]);
        transcript.equal(a1, Expr(FieldElement::from_uint256(ephemeral_coords[i].first)));
        transcript.equal(a2, Expr(FieldElement::from_uint256(ephemeral_coords[i].second)));
        const Expr s1 = purify::circuit_ec_multiply_x(purify::curve1(), transcript, receiver.first, bits[0]);
        const Expr s2 = purify::circuit_ec_multiply_x(purify::curve2(), transcript, receiver.second, bits[1]);
        transcript.equal(plaintext[i] + purify::circuit_combine(transcript, s1, s2), Expr(ciphertext.masked[i]));
    }
    // The sole public commitment is fixed to G. All encrypted values are
    // constrained by native equations; none is an independently blinded output.
    return purify::CircuitMainResult{Expr(1), first_key, second_key, 6 * 255};
}

Result<purify::NativeBulletproofCircuit> public_circuit(const UInt512& recipient, const UInt512& payload,
                                                      const Ciphertext& ciphertext) {
    PURIFY_RETURN_IF_ERROR(decode_points(payload), "scalar_escrow:old_root");
    purify::Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& relation, escrow_relation(transcript, recipient, ciphertext, nullptr), "scalar_escrow:relation");
    purify::BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits), "scalar_escrow:lower");
    PURIFY_RETURN_IF_ERROR(bp.add_pubkey_and_out(payload, relation.p1x, relation.p2x, relation.out), "scalar_escrow:bind");
    return bp.native_circuit();
}

Result<purify::BulletproofAssignmentData> assignment(const UInt512& recipient, const UInt512& payload,
                                                   const Ciphertext& ciphertext, const Opening& opening) {
    purify::Transcript transcript;
    PURIFY_ASSIGN_OR_RETURN(const auto& relation, escrow_relation(transcript, recipient, ciphertext, &opening), "scalar_escrow:witness");
    purify::BulletproofTranscript bp;
    PURIFY_RETURN_IF_ERROR(bp.from_transcript(transcript, relation.n_bits), "scalar_escrow:lower");
    PURIFY_RETURN_IF_ERROR(bp.add_pubkey_and_out(payload, relation.p1x, relation.p2x, relation.out), "scalar_escrow:bind");
    return bp.assignment_data(transcript.varmap(), FieldElement::one());
}

Bytes ciphertext_bytes(const Ciphertext& ciphertext) {
    Bytes out;
    out.reserve(192);
    for (std::size_t i = 0; i < 2; ++i) {
        const auto ephemeral = ciphertext.ephemeral[i].to_bytes_be();
        const auto masked = ciphertext.masked[i].to_bytes_be();
        out.insert(out.end(), ephemeral.begin(), ephemeral.end());
        out.insert(out.end(), masked.begin(), masked.end());
    }
    return out;
}

Bytes binding(const UInt512& recipient, const UInt512& payload, const Ciphertext& ciphertext, const Bytes& context) {
    const auto recipient_bytes = recipient.to_bytes_be();
    const auto payload_bytes = payload.to_bytes_be();
    const auto encrypted = ciphertext_bytes(ciphertext);
    const auto hash = purify::TaggedHash("Purify/CompanionScalarEscrow/HonestV1").digest_many<4>(
        {recipient_bytes, payload_bytes, encrypted, context});
    return Bytes(hash.begin(), hash.end());
}

Result<purify::bppp::PointBytes> secp_point(const FieldElement& scalar, purify_secp_context* secp) {
    const purify::bppp::ScalarBytes zero{};
    const auto generator = purify::bppp::base_generator(secp);
    return purify::bppp::pedersen_commit_char(zero, scalar.to_bytes_be(), secp, generator, generator);
}

Result<bool> verify(const UInt512& recipient, const UInt512& payload, const Ciphertext& ciphertext,
                    const Bytes& context, const purify::bppp::ExperimentalCircuitZkNormArgProof& proof,
                    purify_secp_context* secp) {
    PURIFY_ASSIGN_OR_RETURN(const auto& circuit, public_circuit(recipient, payload, ciphertext), "scalar_escrow:public");
    PURIFY_ASSIGN_OR_RETURN(const auto& generator, secp_point(FieldElement::one(), secp), "scalar_escrow:fixed_output");
    const std::array<purify::bppp::PointBytes, 1> output{generator};
    return purify::bppp::verify_experimental_circuit_zk_norm_arg_with_public_commitments(
        circuit, proof, output, secp, binding(recipient, payload, ciphertext, context));
}

Result<purify::GeneratedKey> decrypt_checked(const purify::SecretKey& recipient_secret, const UInt512& recipient,
                                            const UInt512& payload, const Ciphertext& ciphertext, const Bytes& context,
                                            const purify::bppp::ExperimentalCircuitZkNormArgProof& proof,
                                            purify_secp_context* secp) {
    PURIFY_ASSIGN_OR_RETURN(const auto& accepted, verify(recipient, payload, ciphertext, context, proof, secp), "scalar_escrow:verify");
    if (!accepted) return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "scalar_escrow:invalid_proof");
    PURIFY_ASSIGN_OR_RETURN(const auto& receiver, purify::derive_key(recipient_secret), "scalar_escrow:recipient_secret");
    if (receiver.public_key != recipient) {
        return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "scalar_escrow:wrong_recipient");
    }
    std::array<UInt256, 2> plaintext;
    for (std::size_t i = 0; i < 2; ++i) {
        PURIFY_ASSIGN_OR_RETURN(const auto& pad, shared_pad(recipient_secret, ciphertext.ephemeral[i]), "scalar_escrow:decrypt_pad");
        plaintext[i] = (ciphertext.masked[i] - pad).to_uint256();
    }
    PURIFY_ASSIGN_OR_RETURN(auto root, key_from_pair(plaintext[0], plaintext[1]), "scalar_escrow:canonical_plaintext");
    if (root.public_key != payload) {
        return purify::unexpected_error(purify::ErrorCode::BindingMismatch, "scalar_escrow:wrong_plaintext");
    }
    return root;
}

void test_companion_scalar_escrow(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "scalar escrow secp context creates");
    if (!secp) return;
    // The old root is independent of, and chosen before, the new coalition.
    std::array<unsigned char, 32> seed{};
    seed.fill(0x31);
    auto old_root = purify::generate_key(seed);
    const auto q = FieldElement::from_u64(6).negate();
    auto coalition_point = secp_point(q, secp.get());
    auto recipient = recipient_from_scalar(q);
    seed.fill(0x51);
    auto first_ephemeral = purify::generate_key(seed);
    seed.fill(0x63);
    auto second_ephemeral = purify::generate_key(seed);
    expect_ok(ctx, old_root, "old root predates coalition encryption");
    expect_ok(ctx, coalition_point, "toy coalition has its full signing point");
    expect_ok(ctx, recipient, "known coalition scalar supplies the companion recipient");
    expect_ok(ctx, first_ephemeral, "first independent pad key generates");
    expect_ok(ctx, second_ephemeral, "second independent pad key generates");
    if (!old_root || !coalition_point || !recipient || !first_ephemeral || !second_ephemeral) return;
    Opening opening{old_root->secret, {&*first_ephemeral, &*second_ephemeral}};
    auto ciphertext = encrypt(recipient->public_key, opening);
    expect_ok(ctx, ciphertext, "both canonical old-root scalars encrypt");
    if (!ciphertext) return;
    auto circuit = public_circuit(recipient->public_key, old_root->public_key, *ciphertext);
    auto witness = assignment(recipient->public_key, old_root->public_key, *ciphertext, opening);
    expect_ok(ctx, circuit, "public escrow circuit binds root, recipient and ciphertext");
    expect_ok(ctx, witness, "honest encryption witness constructs");
    if (!circuit || !witness) return;
    ctx.expect(circuit->evaluate(*witness), "honest ciphertext satisfies every native equation");
    const auto context = purify::bytes_from_ascii("public toy preexisting-root/coalition/purpose");
    const auto generator = secp_point(FieldElement::one(), secp.get());
    expect_ok(ctx, generator, "fixed public output is G");
    if (!generator) return;
    const std::array<purify::bppp::PointBytes, 1> output{*generator};
    purify::bppp::ScalarBytes nonce{};
    nonce.fill(0xb7);
    const auto start = std::chrono::steady_clock::now();
    auto proof = purify::bppp::prove_experimental_circuit_zk_norm_arg_with_public_commitments(
        *circuit, *witness, nonce, output, secp.get(), binding(recipient->public_key, old_root->public_key, *ciphertext, context));
    const auto proved = std::chrono::steady_clock::now();
    expect_ok(ctx, proof, "experimental backend proves the honest scalar-encryption relation");
    if (!proof) return;
    // This is extraction algebra, not complete certificate validation. Nonce
    // evidence and Q-to-recipient setup authentication remain external; the
    // canonical_recovery_root suite separately exercises that setup proof.
    const auto slot = purify::bytes_from_ascii("old-root/domain=1/epoch=2/slot=3");
    purify::accountable::ConflictContext conflict{{}, {}, slot};
    std::copy(coalition_point->begin() + 1, coalition_point->end(), conflict.signing_key.begin());
    const auto body_a = purify::bytes_from_ascii("toy decision A");
    const auto body_b = purify::bytes_from_ascii("toy decision B");
    auto challenge_a = purify::accountable::signature_challenge(conflict, body_a, secp.get());
    auto challenge_b = purify::accountable::signature_challenge(conflict, body_b, secp.get());
    expect_ok(ctx, challenge_a, "first toy challenge derives");
    expect_ok(ctx, challenge_b, "second toy challenge derives");
    if (!challenge_a || !challenge_b) return;
    const auto r = FieldElement::from_u64(9);
    auto response_a = purify::accountable::ScalarSignature::deserialize((r + *challenge_a * q).to_bytes_be());
    auto response_b = purify::accountable::ScalarSignature::deserialize((r + *challenge_b * q).to_bytes_be());
    expect_ok(ctx, response_a, "first toy response encodes");
    expect_ok(ctx, response_b, "second toy response encodes");
    if (!response_a || !response_b) return;
    auto extracted = purify::accountable::recover_same_slot_key(conflict, body_a, *response_a, body_b, *response_b, secp.get());
    expect_ok(ctx, extracted, "same-slot responses extract the exact coalition scalar");
    if (!extracted) return;
    ctx.expect(*extracted == q.to_bytes_be(), "extraction preserves the canonical signing scalar and sign");
    auto recovered_recipient = recipient_from_scalar(FieldElement::from_bytes32(*extracted));
    expect_ok(ctx, recovered_recipient, "extracted scalar derives the canonical companion recipient");
    if (!recovered_recipient) return;
    ctx.expect(recovered_recipient->public_key == recipient->public_key, "extracted scalar reaches the registered recipient");
    const auto decrypt_start = std::chrono::steady_clock::now();
    auto decrypted = decrypt_checked(recovered_recipient->secret, recipient->public_key, old_root->public_key, *ciphertext, context, *proof, secp.get());
    const auto recovered = std::chrono::steady_clock::now();
    expect_ok(ctx, decrypted, "public verification precedes successful root recovery");
    if (decrypted) ctx.expect(decrypted->secret == old_root->secret, "decryption recovers both exact canonical old-root scalars");
    if (!decrypted) return;
    for (unsigned char marker : {0x93, 0xa5}) {
        seed.fill(marker);
        auto owner = purify::generate_key(seed);
        expect_ok(ctx, owner, "independent leaf owner is separate from every encryption ephemeral");
        if (!owner) return;
        auto original = shared_pad(old_root->secret, owner->public_key);
        auto recovered_leaf = shared_pad(decrypted->secret, owner->public_key);
        auto owned = shared_pad(owner->secret, old_root->public_key);
        expect_ok(ctx, original, "old root derives the leaf scalar");
        expect_ok(ctx, recovered_leaf, "decrypted old root derives the leaf scalar");
        expect_ok(ctx, owned, "independent owner derives the leaf scalar");
        if (!original || !recovered_leaf || !owned) return;
        ctx.expect(*original == *recovered_leaf && *owned == *recovered_leaf,
                   "extracted coalition scalar unlocks each original owner leaf scalar");
    }
    ctx.expect(ciphertext_bytes(*ciphertext).size() == 192, "ciphertext retains two ephemeral pairs and two field elements");

    auto changed_context = context;
    changed_context.push_back(0);
    auto rejected = verify(recipient->public_key, old_root->public_key, *ciphertext, changed_context, *proof, secp.get());
    ctx.expect(!rejected || !*rejected, "unchanged escrow proof rejects another context");
    rejected = verify(first_ephemeral->public_key, old_root->public_key, *ciphertext, context, *proof, secp.get());
    ctx.expect(!rejected || !*rejected, "unchanged escrow proof rejects another recipient");
    rejected = verify(recipient->public_key, first_ephemeral->public_key, *ciphertext, context, *proof, secp.get());
    ctx.expect(!rejected || !*rejected, "unchanged escrow proof rejects another old root");
    auto changed = *ciphertext;
    changed.masked[0] = changed.masked[0] + FieldElement::one();
    rejected = verify(recipient->public_key, old_root->public_key, changed, context, *proof, secp.get());
    ctx.expect(!rejected || !*rejected, "unchanged escrow proof rejects a changed encrypted scalar");
    changed = *ciphertext;
    std::swap(changed.ephemeral[0], changed.ephemeral[1]);
    rejected = verify(recipient->public_key, old_root->public_key, changed, context, *proof, secp.get());
    ctx.expect(!rejected || !*rejected, "unchanged escrow proof rejects reordered ephemeral keys");
    ctx.expect(!decrypt_checked(first_ephemeral->secret, recipient->public_key, old_root->public_key, *ciphertext, context, *proof, secp.get()),
               "wrong decryption secret rejects even with the correct public ciphertext");
    changed.ephemeral[0] = purify::packed_public_key_space_size();
    ctx.expect(!public_circuit(recipient->public_key, old_root->public_key, changed), "noncanonical ephemeral rejects before circuit construction");

    // Bounds are verified as ordinary arithmetic; no invalid proof is generated.
    for (const auto& limit : {purify::half_n1(), purify::half_n2()}) {
        auto bound = limit;
        bound.sub_assign(UInt256::one());
        purify::Transcript transcript;
        const auto bits = ordinary_bits(transcript, limit);
        const auto exceeds = transcript.evaluate(exceeds_bound(transcript, bits, bound));
        ctx.expect(exceeds && exceeds->is_one(), "payload comparator rejects a scalar above its canonical half-order range");
    }
    for (bool upper : {false, true}) {
        auto payload = key_from_pair(upper ? purify::half_n1() : UInt256::one(), upper ? purify::half_n2() : UInt256::one());
        seed.fill(upper ? 0x75 : 0x74);
        auto e0 = purify::generate_key(seed);
        seed.fill(upper ? 0x87 : 0x86);
        auto e1 = purify::generate_key(seed);
        expect_ok(ctx, payload, "canonical payload boundary key constructs");
        expect_ok(ctx, e0, "boundary first pad is fresh");
        expect_ok(ctx, e1, "boundary second pad is fresh");
        if (!payload || !e0 || !e1) return;
        if (!upper) ctx.expect(payload->secret.packed().is_zero(), "packed zero is the valid scalar pair (1,1)");
        const Opening boundary{payload->secret, {&*e0, &*e1}};
        auto encrypted = encrypt(recipient->public_key, boundary);
        expect_ok(ctx, encrypted, "canonical boundary scalars encrypt");
        if (!encrypted) return;
        auto relation = public_circuit(recipient->public_key, payload->public_key, *encrypted);
        auto values = assignment(recipient->public_key, payload->public_key, *encrypted, boundary);
        expect_ok(ctx, relation, "boundary public relation builds");
        expect_ok(ctx, values, "boundary witness constructs");
        if (relation && values) ctx.expect(relation->evaluate(*values), "minimum and maximum canonical payloads satisfy the native relation");
    }
    const auto proof_bytes = proof->proof.size() + proof->a_commitment.size() + proof->s_commitment.size() + proof->t2.size();
    std::cout << "companion_scalar_escrow gates=" << circuit->n_gates << " constraints=" << circuit->c.size()
              << " inner_proof_bytes=" << proof->proof.size() << " complete_proof_bytes=" << proof_bytes
              << " ciphertext_bytes=192 bridge_bytes=" << proof_bytes + 192
              << " root_and_recipient_bytes=128 context_bytes=" << context.size()
              << " all_public_bytes=" << proof_bytes + 192 + 128 + context.size()
              << " prove_ms=" << std::chrono::duration<double, std::milli>(proved - start).count()
              << " verify_and_decrypt_ms=" << std::chrono::duration<double, std::milli>(recovered - decrypt_start).count() << '\n';
}

} // namespace

void run_companion_scalar_escrow_tests(TestContext& ctx) {
    test_companion_scalar_escrow(ctx);
}
