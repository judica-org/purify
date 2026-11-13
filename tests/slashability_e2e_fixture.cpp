// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "slashability_e2e_fixture.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <utility>

#include "purify.hpp"
#include "purify/accumulation.hpp"
#include "../src/protocol/accumulation_test_support.hpp"
#include "../src/puresign/anchor_escrow_internal.hpp"

namespace purify_test::slashability {
namespace {

using purify::FieldElement;
using purify::Result;
using purify::accountable::PartialResponse;
using purify::accountable::ScalarSignature;

using Point = std::array<unsigned char, 33>;

constexpr std::array<unsigned char, 16> kParentProverFixtureMagic{
    'P', 'u', 'r', 'i', 'f', 'y', '/', 'N',
    'o', 'v', 'a', '/', 'W', 'i', 't', '3'};
constexpr std::size_t kParentDescriptorSize = 130;
constexpr std::size_t kReductionProofSize = 1'022;
constexpr std::size_t kParentStepProofSize = 1'056;
constexpr std::size_t kParentProverSetupSize =
    kParentDescriptorSize + 33 +
    purify::accountable::RecoveryRootContribution::kSerializedSize +
    kReductionProofSize + kParentStepProofSize;
constexpr std::size_t kParentProverAnchorSize =
    kParentDescriptorSize + 33 +
    purify::accountable::AnchorEscrowRecord::kSerializedSize +
    kReductionProofSize + kParentStepProofSize;

template <std::size_t N>
void append(purify::Bytes& output,
            const std::array<unsigned char, N>& bytes) {
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append(purify::Bytes& output,
            std::span<const unsigned char> bytes) {
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_u32_be(purify::Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<unsigned char>((value >> 24) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 16) & 0xffU));
    output.push_back(static_cast<unsigned char>((value >> 8) & 0xffU));
    output.push_back(static_cast<unsigned char>(value & 0xffU));
}

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

/** Build a short-verifier-valid step with no fixed-basis opening. */
Result<purify::bppp::accumulation::AlgebraicStepProof>
synthesize_adversarial_step(
    const purify::bppp::accumulation::Basis& basis,
    std::span<const purify::bppp::accumulation::PendingClaim> claims,
    purify_secp_context* secp_context) {
    std::size_t rounds = 0;
    for (auto dimension = basis.dimension(); dimension > 1;
         dimension /= 2) {
        ++rounds;
    }
    purify::bppp::accumulation::AlgebraicStepProof proof;
    proof.left.resize(rounds);
    proof.right.resize(rounds);
    proof.terminal_scalar = FieldElement::one().to_bytes_be();
    PURIFY_ASSIGN_OR_RETURN(
        proof.folded_generator,
        purify::bppp::accumulation::test_support::
            algebraic_step_equation_residual(
                basis, claims, proof, secp_context),
        "slashability_fixture:adversarial_step_residual");
    return proof;
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

    purify::accountable::CoalitionFormationInput formation_input{};
    formation_input.genesis_hash.fill(0x71);
    formation_input.deployment_id.fill(0x72);
    formation_input.permit.transaction_id.fill(0x73);
    formation_input.permit.output_index = 9;
    formation_input.manifest_digest.fill(0x74);
    PURIFY_ASSIGN_OR_RETURN(
        auto formation,
        purify::accountable::CoalitionFormation::create(formation_input),
        "slashability_fixture:formation");
    PURIFY_ASSIGN_OR_RETURN(
        auto registry_roster,
        purify::accountable::bind_formation_nonce_hosts(
            std::move(roster), formation, nonce_hosts, secp_context),
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

    std::vector<purify::accountable::RecoveryRootContribution>
        contributions;
    contributions.reserve(member_secrets.size());
    purify::bppp::ExperimentalCircuitCache contribution_cache;
    for (std::size_t i = 0; i < member_secrets.size(); ++i) {
        PURIFY_ASSIGN_OR_RETURN(
            auto contribution,
            purify::accountable::prove_recovery_root_contribution(
                registry_roster, formation, i, member_secrets[i],
                secp_context, &contribution_cache),
            "slashability_fixture:recovery_contribution");
        contributions.push_back(std::move(contribution));
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto distributed_setup,
        purify::accountable::verify_distributed_recovery_setup(
            registry_roster, formation, contributions, secp_context,
            &contribution_cache),
        "slashability_fixture:distributed_setup");

    return CoalitionFixture{
        std::move(registry_roster), std::move(recovery_roster),
        std::move(setup_proof), std::move(formation),
        std::move(contributions), std::move(distributed_setup),
        signing_scalar,
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
        purify::accountable::ResolvedConstructionSetup::create(
            coalition.registry_roster, coalition.formation,
            coalition.distributed_setup.roster().recovery_root(),
            std::move(setup_digest)),
        "slashability_fixture:resolve_setup");
    std::array<unsigned char,
               purify::accountable::ConstructionReceiptAccumulator::
                   kRootClaimSerializedSize>
        empty_root{};
    PURIFY_ASSIGN_OR_RETURN(
        auto current,
        purify::bppp::accumulation::parse_root_claim(
            accumulator.leaves().basis(), empty_root,
            secp_context),
        "slashability_fixture:parse_empty_root");

    std::vector<RecoverySetupLeafFixture> setup_leaves;
    std::vector<EscrowedAnchorFixture> anchors;
    std::vector<purify::accountable::ConstructionReceiptSetupEntry>
        payload_setup_entries;
    std::vector<purify::accountable::ConstructionReceiptAnchorEntry>
        payload_anchor_entries;
    std::vector<purify::accountable::ResolvedConstructionReceiptEntry>
        resolved_entries;
    setup_leaves.reserve(coalition.contributions.size());
    anchors.reserve(anchor_count);
    payload_setup_entries.reserve(coalition.contributions.size());
    payload_anchor_entries.reserve(anchor_count);
    resolved_entries.reserve(anchor_count);

    for (std::size_t i = 0; i < coalition.contributions.size(); ++i) {
        const auto& contribution = coalition.contributions[i];
        PURIFY_ASSIGN_OR_RETURN(
            auto prepared,
            accumulator.leaves().prepare(
                coalition.registry_roster, coalition.formation, i,
                contribution, secp_context, &shared_cache),
            "slashability_fixture:prepare_setup_leaf");
        const auto precommitment = prepared.circuit_precommitment();
        PURIFY_ASSIGN_OR_RETURN(
            auto parent_constants,
            accumulator.leaves().derive_parent_constants(
                coalition.registry_roster, coalition.formation, i,
                contribution.share(), precommitment, secp_context),
            "slashability_fixture:setup_parent_constants");
        PURIFY_ASSIGN_OR_RETURN(
            auto reduction,
            purify::bppp::accumulation::prove_algebraic_norm_reduction(
                accumulator.leaves().basis(), prepared.norm(),
                secp_context),
            "slashability_fixture:setup_reduction");
        PURIFY_ASSIGN_OR_RETURN(
            auto leaf,
            purify::bppp::accumulation::verify_algebraic_norm_reduction(
                accumulator.leaves().basis(), prepared.norm(), reduction,
                secp_context),
            "slashability_fixture:verify_setup_reduction");
        const std::array claims{current, leaf};
        PURIFY_ASSIGN_OR_RETURN(
            auto step,
            purify::bppp::accumulation::prove_algebraic_step(
                accumulator.leaves().basis(), claims, secp_context),
            "slashability_fixture:setup_parent_step");
        PURIFY_ASSIGN_OR_RETURN(
            auto next,
            purify::bppp::accumulation::verify_algebraic_step(
                accumulator.leaves().basis(), claims, step,
                secp_context),
            "slashability_fixture:verify_setup_parent_step");
        current = std::move(next);

        payload_setup_entries.emplace_back(
            contribution.share(), precommitment);
        PURIFY_ASSIGN_OR_RETURN(
            auto weighted_member_key,
            public_point(
                coalition.registry_roster.members()[i].coefficient *
                    coalition.member_secrets[i],
                secp_context),
            "slashability_fixture:weighted_member_key");
        setup_leaves.push_back(
            {contribution, precommitment, std::move(parent_constants),
             weighted_member_key, std::move(reduction),
             std::move(step)});
    }

    for (std::size_t i = 0; i < anchor_count; ++i) {
        std::array<unsigned char, 32> seed{};
        seed[0] = 0xa7;
        seed[1] = static_cast<unsigned char>(i + 1);
        PURIFY_ASSIGN_OR_RETURN(
            auto recovery_key, purify::generate_key(seed),
            "slashability_fixture:anchor_key");
        PURIFY_ASSIGN_OR_RETURN(
            auto punishment_key,
            purify::accountable::AnchorPunishmentKey::from_secret(
                FieldElement::from_u64(0x31 + i).to_bytes_be(),
                secp_context),
            "slashability_fixture:punishment_key");
        const auto context = anchor_context(i);
        purify::bppp::ScalarBytes auxiliary_randomness{};
        auxiliary_randomness.back() =
            static_cast<unsigned char>(i + 1);
        PURIFY_ASSIGN_OR_RETURN(
            auto record,
            purify::accountable::
                create_anchor_escrow_with_aux_randomness(
                    coalition.distributed_setup.roster(),
                    recovery_key.public_key,
                    punishment_key, context,
                    auxiliary_randomness, secp_context,
                    &shared_cache),
            "slashability_fixture:anchor_escrow");
        PURIFY_ASSIGN_OR_RETURN(
            const auto verified,
            purify::accountable::verify_anchor_escrow(
                coalition.distributed_setup.roster(),
                recovery_key.public_key,
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
            accumulator.leaves().prepare(
                coalition.distributed_setup.roster(),
                recovery_key.public_key,
                punishment_key.public_key(), context, record,
                secp_context, &shared_cache),
            "slashability_fixture:prepare_anchor");
        const auto precommitment = prepared.circuit_precommitment();
        PURIFY_ASSIGN_OR_RETURN(
            auto parent_constants,
            accumulator.leaves().derive_parent_constants(
                coalition.distributed_setup.roster(),
                recovery_key.public_key,
                punishment_key.public_key(), context,
                record.ciphertext(), precommitment, secp_context),
            "slashability_fixture:parent_constants");
        PURIFY_ASSIGN_OR_RETURN(
            auto reduction,
            purify::bppp::accumulation::
                prove_algebraic_norm_reduction(
                    accumulator.leaves().basis(), prepared.norm(),
                    secp_context),
            "slashability_fixture:anchor_reduction");
        PURIFY_ASSIGN_OR_RETURN(
            auto leaf,
            purify::bppp::accumulation::
                verify_algebraic_norm_reduction(
                    accumulator.leaves().basis(), prepared.norm(),
                    reduction, secp_context),
            "slashability_fixture:verify_anchor_reduction");
        const std::array claims{current, leaf};
        PURIFY_ASSIGN_OR_RETURN(
            auto step,
            purify::bppp::accumulation::prove_algebraic_step(
                accumulator.leaves().basis(), claims, secp_context),
            "slashability_fixture:parent_step");
        PURIFY_ASSIGN_OR_RETURN(
            auto next,
            purify::bppp::accumulation::verify_algebraic_step(
                accumulator.leaves().basis(), claims, step,
                secp_context),
            "slashability_fixture:verify_parent_step");
        current = std::move(next);

        const auto reference = anchor_reference(i);
        payload_anchor_entries.emplace_back(
            record.ciphertext(), precommitment);
        resolved_entries.emplace_back(
            reference, recovery_key.public_key,
            punishment_key.public_key(), context);
        anchors.push_back(
            {std::move(recovery_key), std::move(punishment_key),
             context, std::move(record), reference, precommitment,
             std::move(parent_constants), std::move(reduction),
             std::move(step)});
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto encoded_root,
        purify::bppp::accumulation::serialize_root_claim(
            accumulator.leaves().basis(), current, secp_context),
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
            accumulator.leaves().basis(), encoded_root,
            secp_context),
        "slashability_fixture:reparse_root");
    PURIFY_RETURN_IF_ERROR(
        purify::bppp::accumulation::decide(
            accumulator.leaves().basis(), parsed_root,
            secp_context),
        "slashability_fixture:decide_root");

    PURIFY_ASSIGN_OR_RETURN(
        auto payload,
        purify::accountable::ConstructionReceiptPayload::create(
            coalition.distributed_setup.roster().recovery_root(),
            std::move(payload_setup_entries),
            std::move(payload_anchor_entries)),
        "slashability_fixture:payload");
    PURIFY_ASSIGN_OR_RETURN(
        auto statement,
        purify::accountable::construction_receipt_statement_digest(
            payload, setup.resolved_digest(), resolved_entries),
        "slashability_fixture:statement");

    return NativeAccumulationReferenceFixture{
        std::move(accumulator), std::move(setup), std::move(payload),
        std::move(resolved_entries), std::move(setup_leaves),
        std::move(anchors), statement};
}

namespace {

struct ParentProverAnchorWitness {
    const purify::accountable::AnchorEscrowRecord* record;
    const purify::bppp::accumulation::AlgebraicNormReductionProof*
        reduction;
    const purify::bppp::accumulation::AlgebraicStepProof* step;
};

Result<purify::Bytes> serialize_parent_prover_fixture_impl(
    const NativeAccumulationReferenceFixture& fixture,
    std::span<const ParentProverAnchorWitness> anchor_witnesses,
    std::span<const unsigned char> final_root,
    purify_secp_context* secp_context) {
    constexpr std::size_t kHeaderSize =
        kParentProverFixtureMagic.size() + 32 + 32 + 64 + 4 + 4;
    constexpr std::size_t kFinalRootSize =
        purify::accountable::ConstructionReceiptAccumulator::
            kRootClaimSerializedSize;
    const auto setup_count = fixture.setup_leaves.size();
    const auto anchor_count = fixture.anchors.size();
    if (setup_count == 0 || anchor_count == 0 ||
        setup_count >
            static_cast<std::size_t>(
                std::numeric_limits<std::uint32_t>::max()) ||
        anchor_count >
            static_cast<std::size_t>(
                std::numeric_limits<std::uint32_t>::max())) {
        return purify::unexpected_error(
            purify::ErrorCode::RangeViolation,
            "slashability_fixture:prover_leaf_count");
    }
    if (fixture.payload.setup_entries().size() != setup_count ||
        fixture.payload.anchor_entries().size() != anchor_count ||
        fixture.resolved_entries.size() != anchor_count ||
        anchor_witnesses.size() != anchor_count ||
        final_root.size() != kFinalRootSize) {
        return purify::unexpected_error(
            purify::ErrorCode::SizeMismatch,
            "slashability_fixture:prover_leaf_alignment");
    }
    const auto available =
        std::numeric_limits<std::size_t>::max() - kHeaderSize -
        kFinalRootSize;
    if (setup_count > available / kParentProverSetupSize ||
        anchor_count >
            (available - setup_count * kParentProverSetupSize) /
                kParentProverAnchorSize) {
        return purify::unexpected_error(
            purify::ErrorCode::Overflow,
            "slashability_fixture:prover_fixture_size");
    }
    const auto expected_size =
        kHeaderSize + setup_count * kParentProverSetupSize +
        anchor_count * kParentProverAnchorSize + kFinalRootSize;

    purify::Bytes encoded;
    encoded.reserve(expected_size);
    append(encoded, kParentProverFixtureMagic);
    append(encoded, fixture.statement);
    append(encoded, fixture.setup.resolved_digest().bytes());
    append(encoded, fixture.payload.recovery_root().to_bytes_be());
    append_u32_be(encoded, static_cast<std::uint32_t>(setup_count));
    append_u32_be(encoded, static_cast<std::uint32_t>(anchor_count));

    const auto& raw_generator_digest = fixture.setup_leaves.front()
                                           .parent_constants
                                           .raw_generator_digest;
    for (const auto& setup_leaf : fixture.setup_leaves) {
        if (setup_leaf.parent_constants.raw_generator_digest !=
            raw_generator_digest) {
            return purify::unexpected_error(
                purify::ErrorCode::BindingMismatch,
                "slashability_fixture:prover_setup_witness_shape");
        }
        PURIFY_ASSIGN_OR_RETURN(
            auto reduction_proof,
            purify::bppp::accumulation::
                serialize_algebraic_norm_reduction(
                    fixture.accumulator.leaves().basis(),
                    setup_leaf.reduction, secp_context),
            "slashability_fixture:serialize_prover_setup_reduction");
        PURIFY_ASSIGN_OR_RETURN(
            auto parent_step_proof,
            purify::bppp::accumulation::serialize_algebraic_step(
                fixture.accumulator.leaves().basis(),
                setup_leaf.parent_step, secp_context),
            "slashability_fixture:serialize_prover_setup_step");
        if (reduction_proof.size() != kReductionProofSize ||
            parent_step_proof.size() != kParentStepProofSize) {
            return purify::unexpected_error(
                purify::ErrorCode::InternalMismatch,
                "slashability_fixture:prover_setup_proof_size");
        }
        append(encoded,
               setup_leaf.parent_constants.circuit_binding_digest);
        append(encoded, setup_leaf.circuit_precommitment);
        append(encoded,
               setup_leaf.parent_constants.coefficient_commitment);
        append(encoded, setup_leaf.parent_constants.anchored_offset);
        append(encoded, setup_leaf.weighted_member_key);
        PURIFY_ASSIGN_OR_RETURN(
            auto contribution,
            setup_leaf.contribution.serialize(secp_context),
            "slashability_fixture:serialize_prover_contribution");
        if (contribution.size() !=
            purify::accountable::RecoveryRootContribution::
                kSerializedSize) {
            return purify::unexpected_error(
                purify::ErrorCode::InternalMismatch,
                "slashability_fixture:prover_contribution_size");
        }
        append(encoded, contribution);
        append(encoded, reduction_proof);
        append(encoded, parent_step_proof);
    }

    for (std::size_t index = 0; index < anchor_count; ++index) {
        const auto& anchor = fixture.anchors[index];
        const auto& witness = anchor_witnesses[index];
        if (anchor.parent_constants.raw_generator_digest !=
                raw_generator_digest ||
            witness.record == nullptr ||
            witness.reduction == nullptr || witness.step == nullptr) {
            return purify::unexpected_error(
                purify::ErrorCode::BindingMismatch,
                "slashability_fixture:prover_witness_shape");
        }
        PURIFY_ASSIGN_OR_RETURN(
            auto reduction_proof,
            purify::bppp::accumulation::
                serialize_algebraic_norm_reduction(
                    fixture.accumulator.leaves().basis(),
                    *witness.reduction, secp_context),
            "slashability_fixture:serialize_prover_anchor_reduction");
        PURIFY_ASSIGN_OR_RETURN(
            auto parent_step_proof,
            purify::bppp::accumulation::serialize_algebraic_step(
                fixture.accumulator.leaves().basis(), *witness.step,
                secp_context),
            "slashability_fixture:serialize_prover_anchor_step");
        if (reduction_proof.size() != kReductionProofSize ||
            parent_step_proof.size() != kParentStepProofSize) {
            return purify::unexpected_error(
                purify::ErrorCode::InternalMismatch,
                "slashability_fixture:prover_anchor_proof_size");
        }
        append(encoded,
               anchor.parent_constants.circuit_binding_digest);
        append(encoded, anchor.circuit_precommitment);
        append(encoded,
               anchor.parent_constants.coefficient_commitment);
        append(encoded, anchor.parent_constants.anchored_offset);

        Point punishment_point{};
        punishment_point[0] = 0x02;
        std::copy(anchor.punishment_key.public_key().xonly().begin(),
                  anchor.punishment_key.public_key().xonly().end(),
                  punishment_point.begin() + 1);
        append(encoded, punishment_point);

        PURIFY_ASSIGN_OR_RETURN(
            auto record, witness.record->serialize(secp_context),
            "slashability_fixture:serialize_prover_record");
        if (record.size() !=
            purify::accountable::AnchorEscrowRecord::kSerializedSize) {
            return purify::unexpected_error(
                purify::ErrorCode::InternalMismatch,
                "slashability_fixture:prover_record_size");
        }
        append(encoded, record);
        append(encoded, reduction_proof);
        append(encoded, parent_step_proof);
    }
    append(encoded, final_root);
    if (encoded.size() != expected_size) {
        return purify::unexpected_error(
            purify::ErrorCode::InternalMismatch,
            "slashability_fixture:prover_encoded_size");
    }
    return encoded;
}

} // namespace

Result<purify::Bytes> serialize_parent_prover_fixture(
    const purify::accountable::VerifiedDistributedRecoverySetup&
        verified_setup,
    const NativeAccumulationReferenceFixture& fixture,
    purify_secp_context* secp_context) {
    std::vector<purify::accountable::ConstructionParentSetupWitness>
        setup_witnesses;
    std::vector<purify::accountable::ConstructionParentAnchorWitness>
        anchor_witnesses;
    setup_witnesses.reserve(fixture.setup_leaves.size());
    anchor_witnesses.reserve(fixture.anchors.size());
    for (const auto& leaf : fixture.setup_leaves) {
        setup_witnesses.push_back(
            {leaf.contribution, leaf.reduction, leaf.parent_step});
    }
    for (const auto& anchor : fixture.anchors) {
        anchor_witnesses.push_back(
            {anchor.record, anchor.reduction, anchor.parent_step});
    }
    return purify::accountable::
        serialize_accepted_construction_parent_wit3(
            fixture.setup, verified_setup,
            fixture.payload, fixture.resolved_entries,
            setup_witnesses, anchor_witnesses,
            fixture.accumulator, secp_context);
}

Result<NondecidingParentProverFixture>
serialize_nondeciding_parent_prover_fixture(
    const CoalitionFixture& coalition,
    const NativeAccumulationReferenceFixture& fixture,
    purify_secp_context* secp_context) {
    if (fixture.setup_leaves.empty() || fixture.anchors.empty()) {
        return purify::unexpected_error(
            purify::ErrorCode::EmptyInput,
            "slashability_fixture:nondeciding_leaves");
    }
    const auto& basis = fixture.accumulator.leaves().basis();
    std::array<unsigned char,
               purify::accountable::ConstructionReceiptAccumulator::
                   kRootClaimSerializedSize>
        empty_root{};
    PURIFY_ASSIGN_OR_RETURN(
        auto current,
        purify::bppp::accumulation::parse_root_claim(
            basis, empty_root, secp_context),
        "slashability_fixture:nondeciding_empty_root");
    purify::bppp::ExperimentalCircuitCache shared_cache;

    for (std::size_t index = 0;
         index < fixture.setup_leaves.size(); ++index) {
        const auto& setup_leaf = fixture.setup_leaves[index];
        PURIFY_ASSIGN_OR_RETURN(
            auto prepared,
            fixture.accumulator.leaves().prepare(
                fixture.setup.roster(), fixture.setup.formation(), index,
                setup_leaf.contribution, secp_context, &shared_cache),
            "slashability_fixture:nondeciding_prepare_setup");
        PURIFY_ASSIGN_OR_RETURN(
            auto leaf,
            purify::bppp::accumulation::
                verify_algebraic_norm_reduction(
                    basis, prepared.norm(), setup_leaf.reduction,
                    secp_context),
            "slashability_fixture:nondeciding_verify_setup_reduction");
        const std::array claims{current, leaf};
        PURIFY_ASSIGN_OR_RETURN(
            current,
            purify::bppp::accumulation::verify_algebraic_step(
                basis, claims, setup_leaf.parent_step, secp_context),
            "slashability_fixture:nondeciding_verify_setup_step");
    }

    std::vector<ParentProverAnchorWitness> witnesses;
    witnesses.reserve(fixture.anchors.size());
    for (std::size_t index = 0;
         index + 1 < fixture.anchors.size(); ++index) {
        const auto& anchor = fixture.anchors[index];
        PURIFY_ASSIGN_OR_RETURN(
            auto prepared,
            fixture.accumulator.leaves().prepare(
                coalition.distributed_setup.roster(),
                anchor.recovery_key.public_key,
                anchor.punishment_key.public_key(), anchor.context,
                anchor.record, secp_context, &shared_cache),
            "slashability_fixture:nondeciding_prepare_prefix");
        PURIFY_ASSIGN_OR_RETURN(
            auto leaf,
            purify::bppp::accumulation::
                verify_algebraic_norm_reduction(
                    basis, prepared.norm(), anchor.reduction,
                    secp_context),
            "slashability_fixture:nondeciding_verify_reduction");
        const std::array claims{current, leaf};
        PURIFY_ASSIGN_OR_RETURN(
            current,
            purify::bppp::accumulation::verify_algebraic_step(
                basis, claims, anchor.parent_step, secp_context),
            "slashability_fixture:nondeciding_verify_step");
        witnesses.push_back(
            {&anchor.record, &anchor.reduction,
             &anchor.parent_step});
    }

    const auto& anchor = fixture.anchors.back();
    PURIFY_ASSIGN_OR_RETURN(
        auto changed_record_bytes,
        anchor.record.serialize(secp_context),
        "slashability_fixture:nondeciding_record_bytes");
    if (changed_record_bytes.size() < 64) {
        return purify::unexpected_error(
            purify::ErrorCode::InternalMismatch,
            "slashability_fixture:nondeciding_record_size");
    }
    std::array<unsigned char, 32> terminal_n_bytes{};
    std::copy_n(changed_record_bytes.end() - 64,
                terminal_n_bytes.size(), terminal_n_bytes.begin());
    PURIFY_ASSIGN_OR_RETURN(
        auto terminal_n,
        FieldElement::try_from_bytes32(terminal_n_bytes),
        "slashability_fixture:nondeciding_terminal");
    terminal_n_bytes =
        (terminal_n + FieldElement::one()).to_bytes_be();
    std::copy(terminal_n_bytes.begin(), terminal_n_bytes.end(),
              changed_record_bytes.end() - 64);
    PURIFY_ASSIGN_OR_RETURN(
        auto changed_record,
        purify::accountable::AnchorEscrowRecord::deserialize(
            changed_record_bytes, secp_context),
        "slashability_fixture:nondeciding_record");
    PURIFY_ASSIGN_OR_RETURN(
        const auto complete,
        purify::accountable::verify_anchor_escrow(
            coalition.distributed_setup.roster(),
            anchor.recovery_key.public_key,
            anchor.punishment_key.public_key(), anchor.context,
            changed_record, secp_context, &shared_cache),
        "slashability_fixture:nondeciding_verify_changed");
    if (complete) {
        return purify::unexpected_error(
            purify::ErrorCode::InternalMismatch,
            "slashability_fixture:nondeciding_record_decides");
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto prepared,
        fixture.accumulator.leaves().prepare(
            coalition.distributed_setup.roster(),
            anchor.recovery_key.public_key,
            anchor.punishment_key.public_key(), anchor.context,
            changed_record, secp_context, &shared_cache),
        "slashability_fixture:nondeciding_prepare");
    if (prepared.circuit_precommitment() !=
        anchor.circuit_precommitment) {
        return purify::unexpected_error(
            purify::ErrorCode::BindingMismatch,
            "slashability_fixture:nondeciding_precommitment");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto parent_constants,
        fixture.accumulator.leaves().derive_parent_constants(
            coalition.distributed_setup.roster(),
            anchor.recovery_key.public_key,
            anchor.punishment_key.public_key(), anchor.context,
            changed_record.ciphertext(),
            anchor.circuit_precommitment, secp_context),
        "slashability_fixture:nondeciding_parent_constants");
    if (parent_constants.circuit_binding_digest !=
            anchor.parent_constants.circuit_binding_digest ||
        parent_constants.raw_generator_digest !=
            anchor.parent_constants.raw_generator_digest ||
        parent_constants.coefficient_commitment !=
            anchor.parent_constants.coefficient_commitment ||
        parent_constants.anchored_offset !=
            anchor.parent_constants.anchored_offset) {
        return purify::unexpected_error(
            purify::ErrorCode::BindingMismatch,
            "slashability_fixture:nondeciding_descriptors");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto reduction,
        purify::bppp::accumulation::
            prove_algebraic_norm_reduction(
                basis, prepared.norm(), secp_context),
        "slashability_fixture:nondeciding_reduction");
    PURIFY_ASSIGN_OR_RETURN(
        auto leaf,
        purify::bppp::accumulation::
            verify_algebraic_norm_reduction(
                basis, prepared.norm(), reduction, secp_context),
        "slashability_fixture:nondeciding_verify_terminal_reduction");
    const std::array claims{current, leaf};
    PURIFY_ASSIGN_OR_RETURN(
        auto step,
        synthesize_adversarial_step(basis, claims, secp_context),
        "slashability_fixture:nondeciding_step");
    PURIFY_ASSIGN_OR_RETURN(
        current,
        purify::bppp::accumulation::verify_algebraic_step(
            basis, claims, step, secp_context),
        "slashability_fixture:nondeciding_verify_terminal_step");
    const auto decision = purify::bppp::accumulation::decide(
        basis, current, secp_context);
    if (decision) {
        return purify::unexpected_error(
            purify::ErrorCode::InternalMismatch,
            "slashability_fixture:nondeciding_root_decides");
    }
    if (decision.error().code !=
        purify::ErrorCode::EquationMismatch) {
        return purify::unexpected_error(
            decision.error(),
            "slashability_fixture:nondeciding_decision_error");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto final_root,
        purify::bppp::accumulation::serialize_root_claim(
            basis, current, secp_context),
        "slashability_fixture:nondeciding_root");
    witnesses.push_back(
        {&changed_record, &reduction, &step});

    std::vector<purify::accountable::ConstructionParentSetupWitness>
        setup_witnesses;
    std::vector<purify::accountable::ConstructionParentAnchorWitness>
        anchor_witnesses;
    setup_witnesses.reserve(fixture.setup_leaves.size());
    anchor_witnesses.reserve(witnesses.size());
    for (const auto& setup : fixture.setup_leaves) {
        setup_witnesses.push_back(
            {setup.contribution, setup.reduction, setup.parent_step});
    }
    for (const auto& witness : witnesses) {
        anchor_witnesses.push_back(
            {*witness.record, *witness.reduction, *witness.step});
    }
    auto production = purify::accountable::
        serialize_accepted_construction_parent_wit3(
            fixture.setup, coalition.distributed_setup,
            fixture.payload, fixture.resolved_entries,
            setup_witnesses, anchor_witnesses,
            fixture.accumulator, secp_context, &shared_cache);
    if (production) {
        return purify::unexpected_error(
            purify::ErrorCode::InternalMismatch,
            "slashability_fixture:nondeciding_accepted");
    }
    if (production.error().code !=
        purify::ErrorCode::EquationMismatch) {
        return purify::unexpected_error(
            production.error(),
            "slashability_fixture:nondeciding_rejection");
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto encoded,
        serialize_parent_prover_fixture_impl(
            fixture, witnesses, final_root, secp_context),
        "slashability_fixture:serialize_nondeciding");
    return NondecidingParentProverFixture{
        std::move(encoded), production.error().code};
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
