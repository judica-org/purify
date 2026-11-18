// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <span>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "test_harness.hpp"

namespace {

using purify::FieldElement;
using purify::Result;
using purify::accountable::ConflictContext;
using purify::accountable::NonceHostBoundSigningRoster;
using purify::accountable::ScalarSignature;
using purify::accountable::SigningRoster;
using purify::puresign_plusplus::CertificateNonceNativeReceipt;
using purify::puresign_plusplus::CertificateNonceNativeResponse;
using purify::puresign_plusplus::CertificateNonceParentAccumulator;
using purify::puresign_plusplus::CertificateNonceParentPublicInputs;
using purify::puresign_plusplus::CertificateNonceParentScope;
using purify::puresign_plusplus::CertificateNonceRecursiveResponseView;
using purify::puresign_plusplus::CertificateNonceResponseFrame;
using purify::puresign_plusplus::CertificateNonceResponseVerificationView;
using purify::puresign_plusplus::NonceProof;
using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;

using Point = std::array<unsigned char, 33>;

Result<std::pair<FieldElement, Point>> even_secret_and_point(
    FieldElement scalar, purify_secp_context* secp_context)
{
    const auto original = scalar.to_bytes_be();
    auto normalized = original;
    std::array<unsigned char, 32> xonly{};
    if (purify_bip340_key_from_seckey(
            secp_context, normalized.data(), xonly.data()) == 0) {
        return purify::unexpected_error(
            purify::ErrorCode::RangeViolation,
            "certificate_nonce_parent_test:signing_key");
    }
    Point point{};
    point[0] = normalized == original ? 0x02 : 0x03;
    std::copy(xonly.begin(), xonly.end(), point.begin() + 1);
    if (point[0] == 0x03) {
        scalar = scalar.negate();
        point[0] = 0x02;
    }
    return std::pair{scalar, point};
}

CertificateNonceResponseFrame response_frame(
    const purify::bppp::accumulation::Digest& context_digest,
    std::uint64_t response_ordinal)
{
    CertificateNonceResponseFrame frame{};
    frame.certificate_context_digest = context_digest;
    frame.total_responses = 2;
    frame.response_ordinal = response_ordinal;
    frame.electorate_index =
        static_cast<std::uint32_t>(7 + response_ordinal);
    frame.electorate_weight = 50 + response_ordinal;
    frame.scope = CertificateNonceParentScope::AccountableTopic;
    return frame;
}

void test_recursive_manifest_vectors(TestContext& ctx)
{
    purify::bppp::accumulation::Digest context_digest{};
    context_digest.fill(0x11);
    purify::bppp::accumulation::Digest first_step{};
    first_step.fill(0x22);
    purify::bppp::accumulation::Digest second_step{};
    second_step.fill(0x33);

    auto seed = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest_seed(context_digest, 2);
    expect_ok(ctx, seed, "certificate manifest seed derives");
    if (!seed) return;
    ctx.expect(
        seed->bytes() ==
            purify::UInt256::from_hex(
                "2d0bb6c8254e72de3989292fd006aa7f"
                "091fd6b2f3c2a80ce721c6e647cb47e3")
                .to_bytes_be(),
        "certificate manifest seed matches the Rust vector");

    auto first = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest_step(
            *seed, 0, 0, first_step);
    expect_ok(ctx, first, "first certificate manifest step derives");
    if (!first) return;
    ctx.expect(
        first->bytes() ==
            purify::UInt256::from_hex(
                "3a84a6d47d7f6ffb2e103602bf93bf65"
                "a18db0733436302a635cecd1a2c9432c")
                .to_bytes_be(),
        "first certificate manifest step matches the Rust vector");

    auto second = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest_step(
            *first, 0, 1, second_step);
    expect_ok(ctx, second, "second certificate manifest step derives");
    if (!second) return;
    ctx.expect(
        second->bytes() ==
            purify::UInt256::from_hex(
                "4d0d41244c51fab3a31baac488adee3a"
                "fc287436de90a6c1df0f9a45b6568271")
                .to_bytes_be(),
        "second certificate manifest step matches the Rust vector");

    auto reordered = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest_step(
            *first, 1, 0, second_step);
    expect_ok(ctx, reordered,
              "reordered certificate manifest step derives");
    if (!reordered) return;
    ctx.expect(*reordered != *second,
               "certificate manifest binds response and member order");
}

void test_native_receipt_size(TestContext& ctx)
{
    std::array<std::size_t, 1> member_counts{};
    ctx.expect(
        !purify::puresign_plusplus::
             certificate_nonce_native_receipt_size(member_counts),
        "zero-member certificate response size rejects");
    member_counts[0] =
        CertificateNonceParentPublicInputs::kMemberBatchCapacity + 1;
    ctx.expect(
        !purify::puresign_plusplus::
             certificate_nonce_native_receipt_size(member_counts),
        "oversized certificate response size rejects");

    const std::array<std::size_t, 2> two_singletons{1, 1};
    auto size = purify::puresign_plusplus::
        certificate_nonce_native_receipt_size(two_singletons);
    expect_ok(ctx, size, "two-response certificate size derives");
    if (!size) return;
    constexpr std::size_t expected =
        CertificateNonceNativeReceipt::kHeaderSerializedSize +
        2 * (CertificateNonceNativeReceipt::kResponseHeaderSerializedSize +
             CertificateNonceNativeReceipt::kReductionSerializedSize +
             CertificateNonceNativeReceipt::kStepSerializedSize) +
        CertificateNonceNativeReceipt::kStepSerializedSize;
    ctx.expect(*size == expected,
               "native certificate size accounts for every proof exactly");
}

void test_native_certificate_parent(TestContext& ctx)
{
#if PURIFY_USE_LEGACY_FIELD_HASHES
    ctx.expect(true,
               "certificate nonce parents require the modern hash suite");
    return;
#else
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr,
               "certificate nonce parent secp context creates");
    if (!secp) return;

    auto signing = even_secret_and_point(
        FieldElement::from_u64(3), secp.get());
    expect_ok(ctx, signing, "certificate signing key derives");
    if (!signing) return;
    const std::array<Point, 1> signing_keys{signing->second};
    auto raw_roster = SigningRoster::aggregate(signing_keys, secp.get());
    expect_ok(ctx, raw_roster, "certificate signing roster aggregates");
    if (!raw_roster) return;

    std::array<unsigned char, 32> nonce_seed{};
    nonce_seed.fill(0xd1);
    auto generated = purify::generate_key(nonce_seed);
    expect_ok(ctx, generated, "certificate nonce host secret derives");
    if (!generated) return;
    auto nonce_signer = purify::puresign_plusplus::KeyPair::from_secret(
        generated->secret, secp.get());
    expect_ok(ctx, nonce_signer, "certificate nonce host derives");
    if (!nonce_signer) return;
    auto host = nonce_signer->public_key();
    std::copy(signing->second.begin() + 1, signing->second.end(),
              host.bip340_pubkey.begin());
    const std::array hosts{host};

    purify::accountable::CoalitionCoreDigest coalition_core{};
    coalition_core.fill(0x44);
    auto roster = purify::accountable::bind_nonce_hosts(
        std::move(*raw_roster), coalition_core, hosts, secp.get());
    expect_ok(ctx, roster, "certificate nonce host binds to roster");
    if (!roster) return;

    const auto slot = purify::bytes_from_ascii(
        "certificate/domain=4/epoch=8/slot=3");
    const auto body = purify::bytes_from_ascii("decision:root-a");
    const ConflictContext signing_context{
        roster->signing_key(), roster->nonce_host_commitment(),
        roster->coalition_core_digest(), slot};
    auto topic = purify::accountable::nonce_evaluation_input(
        signing_context, secp.get());
    expect_ok(ctx, topic, "certificate nonce topic derives");
    if (!topic) return;
    auto cache =
        purify::puresign_plusplus::TopicProofCache::build(*topic);
    expect_ok(ctx, cache, "certificate nonce proof cache builds");
    if (!cache) return;

    purify::bppp::ExperimentalCircuitCache circuit_cache;
    auto prepared_nonce = nonce_signer->prepare_topic_nonce_with_proof(
        *cache, secp.get(), &circuit_cache);
    expect_ok(ctx, prepared_nonce,
              "certificate member produces a V4 nonce proof");
    if (!prepared_nonce) return;
    auto proof_bytes = prepared_nonce->proof().serialize(secp.get());
    expect_ok(ctx, proof_bytes, "V4 certificate nonce proof serializes");
    if (!proof_bytes) return;
    ctx.expect(
        proof_bytes->size() == NonceProof::kSerializedSize &&
            proof_bytes->front() == NonceProof::kSerializationVersion,
        "certificate nonce proof uses the exact V4 wire frame");
    auto proof = NonceProof::deserialize(*proof_bytes, secp.get());
    expect_ok(ctx, proof, "V4 certificate nonce proof reparses");
    if (!proof) return;
    auto legacy_version = *proof_bytes;
    legacy_version.front() = 3;
    expect_error(
        ctx, NonceProof::deserialize(legacy_version, secp.get()),
        purify::ErrorCode::BackendRejectedInput,
        "certificate nonce proof rejects the old wire version");

    auto raw_nonce = prepared_nonce->raw_scalar();
    expect_ok(ctx, raw_nonce, "certificate raw nonce scalar exports");
    if (!raw_nonce) return;
    auto challenge = purify::accountable::signature_challenge(
        signing_context, body, secp.get());
    expect_ok(ctx, challenge, "certificate response challenge derives");
    if (!challenge) return;
    const auto response_scalar =
        FieldElement::from_bytes32(*raw_nonce) +
        *challenge * roster->members().front().coefficient *
            signing->first;
    auto response = ScalarSignature::deserialize(
        response_scalar.to_bytes_be());
    expect_ok(ctx, response, "certificate scalar response constructs");
    if (!response) return;

    auto accumulator = CertificateNonceParentAccumulator::create(
        secp.get());
    expect_ok(ctx, accumulator,
              "certificate parent accumulator creates");
    if (!accumulator) return;
    auto leaf = accumulator->leaves().prepare(
        hosts.front(), *cache, *proof, secp.get(), &circuit_cache);
    expect_ok(ctx, leaf,
              "certificate parent authenticates the V4 nonce leaf");
    if (!leaf) return;
    std::vector<purify::puresign_plusplus::
                    PreparedCertificateNonceLeaf>
        leaves;
    leaves.push_back(std::move(*leaf));

    auto tampered_proof_bytes = *proof_bytes;
    tampered_proof_bytes.back() ^= 1;
    auto tampered_proof = NonceProof::deserialize(
        tampered_proof_bytes, secp.get());
    bool tamper_rejected = !tampered_proof;
    if (tampered_proof) {
        tamper_rejected = !accumulator->leaves().prepare(
            hosts.front(), *cache, *tampered_proof, secp.get(),
            &circuit_cache);
    }
    ctx.expect(tamper_rejected,
               "changed V4 nonce proof rejects before leaf admission");

    auto changed_slot = slot;
    changed_slot.back() ^= 1;
    const ConflictContext changed_context{
        roster->signing_key(), roster->nonce_host_commitment(),
        roster->coalition_core_digest(), changed_slot};
    auto changed_topic = purify::accountable::nonce_evaluation_input(
        changed_context, secp.get());
    expect_ok(ctx, changed_topic, "changed certificate topic derives");
    if (!changed_topic) return;
    auto changed_cache =
        purify::puresign_plusplus::TopicProofCache::build(*changed_topic);
    expect_ok(ctx, changed_cache,
              "changed certificate nonce cache builds");
    if (!changed_cache) return;
    ctx.expect(
        !accumulator->leaves().prepare(
            hosts.front(), *changed_cache, *proof, secp.get(),
            &circuit_cache),
        "V4 certificate nonce proof cannot cross topics");

    purify::bppp::accumulation::Digest certificate_context{};
    certificate_context.fill(0x77);
    auto first_inputs = CertificateNonceParentPublicInputs::create(
        response_frame(certificate_context, 0), *roster,
        signing_context, hosts, body, *response, leaves, secp.get());
    expect_ok(ctx, first_inputs,
              "first certificate response inputs validate");
    if (!first_inputs) return;
    auto second_inputs = CertificateNonceParentPublicInputs::create(
        response_frame(certificate_context, 1), *roster,
        signing_context, hosts, body, *response, leaves, secp.get());
    expect_ok(ctx, second_inputs,
              "second certificate response inputs validate");
    if (!second_inputs) return;

    auto first_proof = accumulator->prove_response(
        *first_inputs, leaves, secp.get());
    expect_ok(ctx, first_proof,
              "first certificate response accumulation proves");
    if (!first_proof) return;
    auto second_proof = accumulator->prove_response(
        *second_inputs, leaves, secp.get());
    expect_ok(ctx, second_proof,
              "second certificate response accumulation proves");
    if (!second_proof) return;
    auto first_pending = accumulator->verify_response(
        *first_inputs, leaves, *first_proof, secp.get());
    expect_ok(ctx, first_pending,
              "first certificate response accumulation verifies");
    if (!first_pending) return;
    auto second_pending = accumulator->verify_response(
        *second_inputs, leaves, *second_proof, secp.get());
    expect_ok(ctx, second_pending,
              "second certificate response accumulation verifies");
    if (!second_pending) return;

    std::vector<purify::puresign_plusplus::
                    PendingCertificateNonceParent>
        children;
    children.push_back(std::move(*first_pending));
    children.push_back(std::move(*second_pending));
    auto tree_proof = accumulator->prove_parent(children, secp.get());
    expect_ok(ctx, tree_proof,
              "certificate response parents accumulate");
    if (!tree_proof) return;
    auto root = accumulator->verify_parent(
        children, *tree_proof, secp.get());
    expect_ok(ctx, root, "certificate response parent verifies");
    if (!root) return;
    expect_ok(ctx, accumulator->decide_root(*root, secp.get()),
              "certificate native root completes final decision");

    auto first_native = CertificateNonceNativeResponse::create(
        first_inputs->statement_digest(), *first_proof);
    auto second_native = CertificateNonceNativeResponse::create(
        second_inputs->statement_digest(), *second_proof);
    expect_ok(ctx, first_native,
              "first native certificate response creates");
    expect_ok(ctx, second_native,
              "second native certificate response creates");
    if (!first_native || !second_native) return;
    std::vector<CertificateNonceNativeResponse> native_responses;
    native_responses.push_back(std::move(*first_native));
    native_responses.push_back(std::move(*second_native));
    std::vector<purify::puresign_plusplus::CertificateNonceTreeProof>
        native_tree_proofs{*tree_proof};
    auto native_receipt = CertificateNonceNativeReceipt::create(
        certificate_context, std::move(native_responses),
        std::move(native_tree_proofs));
    expect_ok(ctx, native_receipt,
              "native certificate receipt creates");
    if (!native_receipt) return;
    auto encoded = purify::puresign_plusplus::
        serialize_certificate_nonce_native_receipt(
            *accumulator, *native_receipt, secp.get());
    expect_ok(ctx, encoded, "native certificate receipt serializes");
    if (!encoded) return;
    const std::array<std::size_t, 2> member_counts{1, 1};
    auto expected_size = purify::puresign_plusplus::
        certificate_nonce_native_receipt_size(member_counts);
    expect_ok(ctx, expected_size,
              "native certificate receipt size derives");
    if (!expected_size) return;
    ctx.expect(encoded->size() == *expected_size,
               "native certificate receipt has its exact derived size");

    auto parsed = purify::puresign_plusplus::
        parse_certificate_nonce_native_receipt(
            *accumulator, *encoded, secp.get());
    expect_ok(ctx, parsed, "native certificate receipt reparses");
    if (!parsed) return;
    auto reencoded = purify::puresign_plusplus::
        serialize_certificate_nonce_native_receipt(
            *accumulator, *parsed, secp.get());
    expect_ok(ctx, reencoded,
              "parsed native certificate receipt reserializes");
    if (!reencoded) return;
    ctx.expect(*reencoded == *encoded,
               "native certificate receipt round-trips exactly");

    const std::array verification_views{
        CertificateNonceResponseVerificationView{
            *first_inputs, leaves},
        CertificateNonceResponseVerificationView{
            *second_inputs, leaves},
    };
    expect_ok(ctx,
              accumulator->verify_native_receipt(
                  *parsed, verification_views, secp.get()),
              "native certificate receipt verifies end to end");

    std::vector<CertificateNonceNativeResponse> reordered_responses{
        parsed->responses()[1], parsed->responses()[0]};
    auto reordered_receipt = CertificateNonceNativeReceipt::create(
        certificate_context, std::move(reordered_responses),
        {parsed->tree_proofs().front()});
    expect_ok(ctx, reordered_receipt,
              "reordered native receipt remains structurally valid");
    if (!reordered_receipt) return;
    ctx.expect(
        !accumulator->verify_native_receipt(
            *reordered_receipt, verification_views, secp.get()),
        "native certificate verification binds response order");

    std::vector<CertificateNonceNativeResponse> changed_tree_responses{
        parsed->responses().begin(), parsed->responses().end()};
    auto changed_tree_proof = parsed->tree_proofs().front();
    changed_tree_proof.accumulation.terminal_scalar.front() ^= 1;
    auto changed_tree_receipt = CertificateNonceNativeReceipt::create(
        certificate_context, std::move(changed_tree_responses),
        {std::move(changed_tree_proof)});
    expect_ok(ctx, changed_tree_receipt,
              "changed tree proof remains structurally valid");
    if (!changed_tree_receipt) return;
    ctx.expect(
        !accumulator->verify_native_receipt(
            *changed_tree_receipt, verification_views, secp.get()),
        "native certificate verification rejects a changed tree proof");

    auto bad_encoding = *encoded;
    bad_encoding.front() ^= 1;
    ctx.expect(
        !purify::puresign_plusplus::
             parse_certificate_nonce_native_receipt(
                 *accumulator, bad_encoding, secp.get()),
        "native certificate parser rejects changed magic");
    bad_encoding = *encoded;
    bad_encoding.pop_back();
    ctx.expect(
        !purify::puresign_plusplus::
             parse_certificate_nonce_native_receipt(
                 *accumulator, bad_encoding, secp.get()),
        "native certificate parser rejects truncation");
    bad_encoding = *encoded;
    bad_encoding.push_back(0);
    ctx.expect(
        !purify::puresign_plusplus::
             parse_certificate_nonce_native_receipt(
                 *accumulator, bad_encoding, secp.get()),
        "native certificate parser rejects trailing bytes");

    auto changed_context_encoding = *encoded;
    changed_context_encoding[48] ^= 1;
    auto changed_context_receipt = purify::puresign_plusplus::
        parse_certificate_nonce_native_receipt(
            *accumulator, changed_context_encoding, secp.get());
    expect_ok(ctx, changed_context_receipt,
              "changed public context remains canonically encoded");
    if (!changed_context_receipt) return;
    ctx.expect(
        !accumulator->verify_native_receipt(
            *changed_context_receipt, verification_views, secp.get()),
        "native certificate verification binds the public context");

    auto changed_statement_encoding = *encoded;
    changed_statement_encoding[
        CertificateNonceNativeReceipt::kHeaderSerializedSize] ^= 1;
    auto changed_statement_receipt = purify::puresign_plusplus::
        parse_certificate_nonce_native_receipt(
            *accumulator, changed_statement_encoding, secp.get());
    expect_ok(ctx, changed_statement_receipt,
              "changed statement digest remains canonically encoded");
    if (!changed_statement_receipt) return;
    ctx.expect(
        !accumulator->verify_native_receipt(
            *changed_statement_receipt, verification_views, secp.get()),
        "native certificate verification binds each statement digest");

    const std::array descriptors{leaves.front().public_descriptor()};
    const std::array recursive_responses{
        CertificateNonceRecursiveResponseView(
            first_inputs->authorization(), signing_context, hosts,
            body, *response, descriptors),
        CertificateNonceRecursiveResponseView(
            second_inputs->authorization(), signing_context, hosts,
            body, *response, descriptors),
    };
    auto public_manifest = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest(
            accumulator->leaves(), certificate_context,
            recursive_responses, secp.get());
    expect_ok(ctx, public_manifest,
              "public certificate manifest resolves without proofs");
    if (!public_manifest) return;
    auto public_frame = purify::puresign_plusplus::
        serialize_certificate_parent_public_frame(*public_manifest);
    expect_ok(ctx, public_frame,
              "public certificate prover frame serializes");
    if (!public_frame) return;
    constexpr std::array<unsigned char, 16> public_frame_magic{
        'P', 'u', 'r', 'i', 'f', 'y', '/', 'C',
        'e', 'r', 't', 'P', 'u', 'b', '1', 0};
    ctx.expect(
        public_frame->size() ==
                purify::puresign_plusplus::
                    kCertificateParentPublicFrameSize &&
            std::equal(
                public_frame_magic.begin(), public_frame_magic.end(),
                public_frame->begin()),
        "certificate prover frame has the fixed public boundary");

    auto changed_descriptors = descriptors;
    changed_descriptors.front().leaf_binding.back() ^= 1;
    const std::array changed_recursive_responses{
        CertificateNonceRecursiveResponseView(
            first_inputs->authorization(), signing_context, hosts,
            body, *response, changed_descriptors),
        recursive_responses[1],
    };
    auto changed_manifest = purify::puresign_plusplus::
        certificate_nonce_recursive_manifest(
            accumulator->leaves(), certificate_context,
            changed_recursive_responses, secp.get());
    expect_ok(ctx, changed_manifest,
              "changed public leaf resolves a distinct manifest");
    if (!changed_manifest) return;
    ctx.expect(
        changed_manifest->manifest() != public_manifest->manifest(),
        "public certificate manifest binds each leaf descriptor");

#if defined(PURIFY_HAS_CERTIFICATE_PARENT_VERIFIER)
    ctx.expect(
        !purify::puresign_plusplus::CertificateParentVerifier::load(""),
        "certificate verifier rejects an empty artifact path");
    const char* verifier_artifact = std::getenv(
        "PURIFY_CERTIFICATE_PARENT_VERIFIER_ARTIFACT");
    const char* proof_path = std::getenv(
        "PURIFY_CERTIFICATE_PARENT_PROOF");
    const bool has_artifact =
        verifier_artifact != nullptr && *verifier_artifact != '\0';
    const bool has_proof =
        proof_path != nullptr && *proof_path != '\0';
    ctx.expect(has_artifact == has_proof,
               "certificate verifier resources are supplied together");
    if (has_artifact && has_proof) {
        std::array<
            unsigned char,
            purify::puresign_plusplus::CertificateParentVerifier::
                kProofSize>
            recursive_proof{};
        std::ifstream proof_file(proof_path, std::ios::binary);
        ctx.expect(proof_file.is_open(),
                   "qualified certificate proof opens");
        if (!proof_file.is_open()) return;
        proof_file.read(
            reinterpret_cast<char*>(recursive_proof.data()),
            static_cast<std::streamsize>(recursive_proof.size()));
        const bool exact_proof =
            proof_file.gcount() ==
                static_cast<std::streamsize>(recursive_proof.size()) &&
            proof_file.peek() == std::ifstream::traits_type::eof();
        ctx.expect(exact_proof,
                   "qualified certificate proof has the exact size");
        if (!exact_proof) return;
        auto verifier = purify::puresign_plusplus::
            CertificateParentVerifier::load(verifier_artifact);
        expect_ok(ctx, verifier,
                  "qualified certificate verifier artifact loads");
        if (!verifier) return;
        expect_ok(ctx,
                  verifier->verify(
                      *public_manifest, recursive_proof, *accumulator,
                      secp.get()),
                  "recursive verifier accepts the native public manifest");
        ctx.expect(
            !verifier->verify(
                *changed_manifest, recursive_proof, *accumulator,
                secp.get()),
            "recursive verifier rejects a changed public manifest");
        recursive_proof.back() ^= 1;
        ctx.expect(
            !verifier->verify(
                *public_manifest, recursive_proof, *accumulator,
                secp.get()),
            "recursive verifier rejects a changed proof");
    }
#endif
#endif
}

} // namespace

void run_certificate_nonce_parent_tests(TestContext& ctx)
{
    test_recursive_manifest_vectors(ctx);
    test_native_receipt_size(ctx);
    test_native_certificate_parent(ctx);
}
