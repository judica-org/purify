// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "slashability_e2e_fixture.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <string>
#include <utility>

#include "purify.hpp"
#include "purify/accumulation.hpp"
#include "../src/puresign/anchor_escrow_internal.hpp"

namespace purify_test::slashability {
namespace {

using purify::FieldElement;
using purify::Result;
using purify::accountable::PartialResponse;
using purify::accountable::ScalarSignature;

using Point = std::array<unsigned char, 33>;

Result<Point> public_point(FieldElement scalar,
                           purify_secp_context* secp_context) {
    const auto original = scalar.to_bytes_be();
    auto normalized = original;
    std::array<unsigned char, 32> xonly{};
    if (purify_bip340_key_from_seckey(
            secp_context, normalized.data(), xonly.data()) == 0) {
        return purify::unexpected_error(
            purify::ErrorCode::RangeViolation,
            "slashability_fixture:public_point");
    }
    Point point{};
    point[0] = normalized == original ? 0x02 : 0x03;
    std::copy(xonly.begin(), xonly.end(), point.begin() + 1);
    return point;
}

Result<std::pair<FieldElement, Point>> even_member(
    FieldElement scalar, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(
        auto point, public_point(scalar, secp_context),
        "slashability_fixture:even_member");
    if (point[0] == 0x03) {
        scalar = scalar.negate();
        point[0] = 0x02;
    }
    return std::pair{scalar, point};
}

Result<std::vector<PartialResponse>> partials(
    const purify::accountable::NonceHostBoundSigningRoster& roster,
    std::span<const FieldElement> secrets,
    std::span<const FieldElement> nonces,
    const FieldElement& challenge) {
    if (secrets.size() != roster.members().size() ||
        nonces.size() != secrets.size()) {
        return purify::unexpected_error(
            purify::ErrorCode::SizeMismatch,
            "slashability_fixture:partial_count");
    }
    std::vector<PartialResponse> out;
    out.reserve(secrets.size());
    for (std::size_t i = 0; i < secrets.size(); ++i) {
        const auto value =
            nonces[i] + challenge * roster.members()[i].coefficient *
                            secrets[i];
        PURIFY_ASSIGN_OR_RETURN(
            auto response,
            ScalarSignature::deserialize(value.to_bytes_be()),
            "slashability_fixture:partial");
        out.push_back({response});
    }
    return out;
}

purify::accountable::AnchorReference anchor_reference(
    std::size_t index) {
    purify::accountable::AnchorReference out{};
    out.fill(0x61);
    out.back() = static_cast<unsigned char>(index + 1);
    return out;
}

purify::accountable::AnchorEscrowContextDigest anchor_context(
    std::size_t index) {
    auto input = purify::bytes_from_ascii(
        "slashability-e2e/domain=11/epoch=19/anchor=");
    const auto suffix = std::to_string(index);
    input.insert(input.end(), suffix.begin(), suffix.end());
    return purify::TaggedHash("Purify/Test/SlashabilityE2EContext/v1")
        .digest(input);
}

} // namespace

Result<CoalitionFixture> make_all_evil_coalition(
    purify_secp_context* secp_context) {
    const std::array candidates{
        FieldElement::from_u64(3), FieldElement::from_u64(6),
        FieldElement::from_u64(8)};
    std::array<Point, 3> public_keys{};
    std::vector<FieldElement> member_secrets;
    member_secrets.reserve(candidates.size());
    for (std::size_t i = 0; i < candidates.size(); ++i) {
        PURIFY_ASSIGN_OR_RETURN(
            auto member, even_member(candidates[i], secp_context),
            "slashability_fixture:member");
        member_secrets.push_back(member.first);
        public_keys[i] = member.second;
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto roster,
        purify::accountable::SigningRoster::aggregate(
            public_keys, secp_context),
        "slashability_fixture:roster");

    std::vector<purify::puresign_plusplus::KeyPair> nonce_signers;
    std::vector<purify::puresign_plusplus::PublicKey> nonce_hosts;
    nonce_signers.reserve(public_keys.size());
    nonce_hosts.reserve(public_keys.size());
    for (std::size_t i = 0; i < public_keys.size(); ++i) {
        std::array<unsigned char, 32> seed{};
        seed[0] = 0xd1;
        seed[1] = static_cast<unsigned char>(i + 1);
        PURIFY_ASSIGN_OR_RETURN(
            auto generated, purify::generate_key(seed),
            "slashability_fixture:nonce_host_secret");
        PURIFY_ASSIGN_OR_RETURN(
            auto signer,
            purify::puresign_plusplus::KeyPair::from_secret(
                generated.secret, secp_context),
            "slashability_fixture:nonce_host");
        auto host = signer.public_key();
        std::copy(public_keys[i].begin() + 1, public_keys[i].end(),
                  host.bip340_pubkey.begin());
        nonce_hosts.push_back(host);
        nonce_signers.push_back(std::move(signer));
    }

    purify::accountable::CoalitionCoreDigest core_digest{};
    core_digest.fill(0x73);
    PURIFY_ASSIGN_OR_RETURN(
        auto registry_roster,
        purify::accountable::bind_nonce_hosts(
            std::move(roster), core_digest, nonce_hosts, secp_context),
        "slashability_fixture:nonce_hosts");

    auto signing_scalar = FieldElement::zero();
    for (std::size_t i = 0; i < member_secrets.size(); ++i) {
        signing_scalar = signing_scalar +
            registry_roster.members()[i].coefficient *
                member_secrets[i];
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto root,
        purify::accountable::derive_recovery_root(signing_scalar),
        "slashability_fixture:recovery_root");
    PURIFY_ASSIGN_OR_RETURN(
        auto setup_proof,
        purify::accountable::prove_recovery_root_setup(
            registry_roster, root.public_key, signing_scalar,
            secp_context),
        "slashability_fixture:setup_proof");
    PURIFY_ASSIGN_OR_RETURN(
        auto recovery_roster,
        purify::accountable::verify_recovery_root_setup(
            registry_roster, root.public_key, setup_proof,
            secp_context),
        "slashability_fixture:verify_setup");

    return CoalitionFixture{
        std::move(registry_roster), std::move(recovery_roster),
        std::move(setup_proof), signing_scalar,
        std::move(member_secrets), std::move(nonce_signers),
        std::move(nonce_hosts)};
}

Result<NativeAccumulationReferenceFixture>
make_native_accumulation_reference(
    const CoalitionFixture& coalition, std::size_t anchor_count,
    purify_secp_context* secp_context) {
    if (anchor_count == 0 || anchor_count > 255) {
        return purify::unexpected_error(
            purify::ErrorCode::RangeViolation,
            "slashability_fixture:anchor_count");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto accumulator,
        purify::accountable::ConstructionReceiptAccumulator::create(
            secp_context),
        "slashability_fixture:accumulator");
    purify::accountable::ResolvedConstructionSetupDigestBytes
        setup_digest_bytes{};
    setup_digest_bytes.fill(0x72);
    PURIFY_ASSIGN_OR_RETURN(
        auto setup_digest,
        purify::accountable::ResolvedConstructionSetupDigest::create(
            setup_digest_bytes),
        "slashability_fixture:setup_digest");
    purify::bppp::ExperimentalCircuitCache shared_cache;
    PURIFY_ASSIGN_OR_RETURN(
        auto setup,
        accumulator.resolve_setup_record(
            coalition.registry_roster,
            coalition.recovery_roster.recovery_root(),
            coalition.setup_proof, std::move(setup_digest),
            secp_context, &shared_cache),
        "slashability_fixture:resolve_setup");
    PURIFY_ASSIGN_OR_RETURN(
        auto current,
        purify::bppp::accumulation::parse_root_claim(
            accumulator.anchors().basis(), setup.seed_root(),
            secp_context),
        "slashability_fixture:parse_seed");

    std::vector<EscrowedAnchorFixture> anchors;
    std::vector<purify::accountable::ConstructionReceiptEntry>
        payload_entries;
    std::vector<purify::accountable::ResolvedConstructionReceiptEntry>
        resolved_entries;
    anchors.reserve(anchor_count);
    payload_entries.reserve(anchor_count);
    resolved_entries.reserve(anchor_count);

    for (std::size_t i = 0; i < anchor_count; ++i) {
        std::array<unsigned char, 32> seed{};
        seed[0] = 0xa7;
        seed[1] = static_cast<unsigned char>(i + 1);
        PURIFY_ASSIGN_OR_RETURN(
            auto recovery_key, purify::generate_key(seed),
            "slashability_fixture:anchor_key");
        PURIFY_ASSIGN_OR_RETURN(
            auto punishment_key,
            purify::accountable::derive_anchor_punishment_key(
                recovery_key, secp_context),
            "slashability_fixture:punishment_key");
        const auto context = anchor_context(i);
        purify::bppp::ScalarBytes auxiliary_randomness{};
        auxiliary_randomness.back() =
            static_cast<unsigned char>(i + 1);
        PURIFY_ASSIGN_OR_RETURN(
            auto record,
            purify::accountable::
                create_anchor_escrow_with_aux_randomness(
                    coalition.recovery_roster, recovery_key,
                    punishment_key.public_key(), context,
                    auxiliary_randomness, secp_context,
                    &shared_cache),
            "slashability_fixture:anchor_escrow");
        PURIFY_ASSIGN_OR_RETURN(
            const auto verified,
            purify::accountable::verify_anchor_escrow(
                coalition.recovery_roster, recovery_key.public_key,
                punishment_key.public_key(), context, record,
                secp_context, &shared_cache),
            "slashability_fixture:verify_anchor_escrow");
        if (!verified) {
            return purify::unexpected_error(
                purify::ErrorCode::EquationMismatch,
                "slashability_fixture:anchor_escrow_false");
        }
        PURIFY_ASSIGN_OR_RETURN(
            auto prepared,
            accumulator.anchors().prepare(
                coalition.recovery_roster, recovery_key.public_key,
                punishment_key.public_key(), context, record,
                secp_context, &shared_cache),
            "slashability_fixture:prepare_anchor");
        const auto precommitment = prepared.circuit_precommitment();
        PURIFY_ASSIGN_OR_RETURN(
            auto parent_constants,
            accumulator.anchors().derive_parent_constants(
                coalition.recovery_roster, recovery_key.public_key,
                punishment_key.public_key(), context,
                record.ciphertext(), precommitment, secp_context,
                &shared_cache),
            "slashability_fixture:parent_constants");
        PURIFY_ASSIGN_OR_RETURN(
            auto reduction,
            purify::bppp::accumulation::
                prove_algebraic_norm_reduction(
                    accumulator.anchors().basis(), prepared.norm(),
                    secp_context),
            "slashability_fixture:anchor_reduction");
        PURIFY_ASSIGN_OR_RETURN(
            auto leaf,
            purify::bppp::accumulation::
                verify_algebraic_norm_reduction(
                    accumulator.anchors().basis(), prepared.norm(),
                    reduction, secp_context),
            "slashability_fixture:verify_anchor_reduction");
        const std::array claims{current, leaf};
        PURIFY_ASSIGN_OR_RETURN(
            auto step,
            purify::bppp::accumulation::prove_algebraic_step(
                accumulator.anchors().basis(), claims, secp_context),
            "slashability_fixture:parent_step");
        PURIFY_ASSIGN_OR_RETURN(
            auto next,
            purify::bppp::accumulation::verify_algebraic_step(
                accumulator.anchors().basis(), claims, step,
                secp_context),
            "slashability_fixture:verify_parent_step");
        current = std::move(next);

        const auto reference = anchor_reference(i);
        payload_entries.push_back(
            {record.ciphertext(), precommitment});
        resolved_entries.emplace_back(
            reference, recovery_key.public_key,
            punishment_key.public_key(), context);
        anchors.push_back(
            {std::move(recovery_key), std::move(punishment_key),
             context, std::move(record), reference, precommitment,
             std::move(parent_constants)});
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto encoded_root,
        purify::bppp::accumulation::serialize_root_claim(
            accumulator.anchors().basis(), current, secp_context),
        "slashability_fixture:serialize_root");
    if (encoded_root.size() !=
        purify::accountable::ConstructionReceiptAccumulator::
            kRootClaimSerializedSize) {
        return purify::unexpected_error(
            purify::ErrorCode::SizeMismatch,
            "slashability_fixture:root_size");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto parsed_root,
        purify::bppp::accumulation::parse_root_claim(
            accumulator.anchors().basis(), encoded_root,
            secp_context),
        "slashability_fixture:reparse_root");
    PURIFY_RETURN_IF_ERROR(
        purify::bppp::accumulation::decide(
            accumulator.anchors().basis(), parsed_root,
            secp_context),
        "slashability_fixture:decide_root");

    PURIFY_ASSIGN_OR_RETURN(
        auto payload,
        purify::accountable::ConstructionReceiptPayload::create(
            coalition.recovery_roster.recovery_root(),
            std::move(payload_entries)),
        "slashability_fixture:payload");
    PURIFY_ASSIGN_OR_RETURN(
        auto statement,
        purify::accountable::construction_receipt_statement_digest(
            payload, setup.resolved_digest(), resolved_entries),
        "slashability_fixture:statement");
    std::array<unsigned char,
               purify::accountable::ConstructionReceiptAccumulator::
                   kRootClaimSerializedSize>
        root_bytes{};
    std::copy(encoded_root.begin(), encoded_root.end(),
              root_bytes.begin());

    return NativeAccumulationReferenceFixture{
        std::move(accumulator), std::move(setup), std::move(payload),
        std::move(resolved_entries), std::move(anchors), statement,
        root_bytes};
}

Result<purify::accountable::ExposedCoalitionKey>
expose_conflicting_coalition_key(
    CoalitionFixture& coalition,
    const purify::accountable::ConstructionReceiptStatementDigest&
        first_statement,
    purify_secp_context* secp_context) {
    const auto slot = purify::bytes_from_ascii(
        "slashability-e2e/domain=11/epoch=19/slot=7");
    purify::accountable::ConflictContext context{
        coalition.registry_roster.signing_key(),
        coalition.registry_roster.nonce_host_commitment(),
        coalition.registry_roster.coalition_core_digest(), slot};
    PURIFY_ASSIGN_OR_RETURN(
        auto topic,
        purify::accountable::nonce_evaluation_input(
            context, secp_context),
        "slashability_fixture:nonce_topic");
    PURIFY_ASSIGN_OR_RETURN(
        auto proof_cache,
        purify::puresign_plusplus::TopicProofCache::build(topic),
        "slashability_fixture:nonce_cache");

    purify::bppp::ExperimentalCircuitCache shared_cache;
    std::vector<purify::puresign_plusplus::NonceProof> proofs;
    std::vector<FieldElement> raw_nonces;
    proofs.reserve(coalition.nonce_signers.size());
    raw_nonces.reserve(coalition.nonce_signers.size());
    for (auto& signer : coalition.nonce_signers) {
        PURIFY_ASSIGN_OR_RETURN(
            auto prepared,
            signer.prepare_topic_nonce_with_proof(
                proof_cache, secp_context, &shared_cache),
            "slashability_fixture:nonce_proof");
        PURIFY_ASSIGN_OR_RETURN(
            auto raw_scalar, prepared.raw_scalar(),
            "slashability_fixture:raw_nonce");
        raw_nonces.push_back(FieldElement::from_bytes32(raw_scalar));
        proofs.push_back(prepared.proof());
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto nonce_set,
        purify::accountable::verify_coalition_nonce_set(
            coalition.registry_roster, context,
            coalition.nonce_hosts, proofs, secp_context,
            &shared_cache),
        "slashability_fixture:nonce_set");

    const purify::Bytes first_body(first_statement.begin(),
                                   first_statement.end());
    auto second_body = first_body;
    second_body.front() ^= 1;
    PURIFY_ASSIGN_OR_RETURN(
        auto first_challenge,
        purify::accountable::signature_challenge(
            context, first_body, secp_context),
        "slashability_fixture:first_challenge");
    PURIFY_ASSIGN_OR_RETURN(
        auto second_challenge,
        purify::accountable::signature_challenge(
            context, second_body, secp_context),
        "slashability_fixture:second_challenge");
    PURIFY_ASSIGN_OR_RETURN(
        auto first_partials,
        partials(coalition.registry_roster,
                 coalition.member_secrets, raw_nonces,
                 first_challenge),
        "slashability_fixture:first_partials");
    PURIFY_ASSIGN_OR_RETURN(
        auto second_partials,
        partials(coalition.registry_roster,
                 coalition.member_secrets, raw_nonces,
                 second_challenge),
        "slashability_fixture:second_partials");
    PURIFY_ASSIGN_OR_RETURN(
        auto first,
        purify::accountable::aggregate_responses(
            coalition.registry_roster, nonce_set, context,
            first_body, first_partials, secp_context),
        "slashability_fixture:first_response");
    PURIFY_ASSIGN_OR_RETURN(
        auto second,
        purify::accountable::aggregate_responses(
            coalition.registry_roster, nonce_set, context,
            second_body, second_partials, secp_context),
        "slashability_fixture:second_response");
    return purify::accountable::recover_verified_same_slot_key(
        first, second, secp_context);
}

} // namespace purify_test::slashability
