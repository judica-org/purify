// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/construction_parent_verifier.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

#include "../bridge/construction_parent_bridge.h"
#include "anchor_escrow_internal.hpp"
#include "purify/puresign/recovery_root.hpp"

namespace purify::accountable {
namespace {

static_assert(ConstructionReceiptAccumulator::kRootClaimSerializedSize ==
              PURIFY_CONSTRUCTION_PARENT_ROOT_SIZE);
static_assert(32 + 32 + 33 + 33 ==
              PURIFY_CONSTRUCTION_PARENT_DESCRIPTOR_SIZE);
static_assert(ConstructionReceiptEnvelope::kParentProofSize ==
              PURIFY_CONSTRUCTION_PARENT_PROOF_SIZE);

template <std::size_t N>
void append(std::vector<unsigned char>& output,
            const std::array<unsigned char, N>& bytes) {
    output.insert(output.end(), bytes.begin(), bytes.end());
}

Unexpected<Error> load_error(
    purify_construction_parent_status status) {
    switch (status) {
    case PURIFY_CONSTRUCTION_PARENT_MALFORMED:
        return unexpected_error(ErrorCode::RangeViolation,
                                "construction_parent:artifact_path");
    case PURIFY_CONSTRUCTION_PARENT_ARTIFACT_OPEN_FAILED:
        return unexpected_error(ErrorCode::IoOpenFailed,
                                "construction_parent:artifact_open");
    case PURIFY_CONSTRUCTION_PARENT_ARTIFACT_REJECTED:
        return unexpected_error(ErrorCode::InternalMismatch,
                                "construction_parent:artifact_identity");
    case PURIFY_CONSTRUCTION_PARENT_PROOF_REJECTED:
    case PURIFY_CONSTRUCTION_PARENT_BUFFER_TOO_SMALL:
    case PURIFY_CONSTRUCTION_PARENT_INTERNAL_ERROR:
    case PURIFY_CONSTRUCTION_PARENT_OK:
        return unexpected_error(ErrorCode::InternalMismatch,
                                "construction_parent:artifact_backend");
    }
    return unexpected_error(ErrorCode::InternalMismatch,
                            "construction_parent:artifact_status");
}

Unexpected<Error> verify_error(
    purify_construction_parent_status status) {
    switch (status) {
    case PURIFY_CONSTRUCTION_PARENT_MALFORMED:
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "construction_parent:malformed");
    case PURIFY_CONSTRUCTION_PARENT_PROOF_REJECTED:
        return unexpected_error(ErrorCode::BackendRejectedInput,
                                "construction_parent:proof");
    case PURIFY_CONSTRUCTION_PARENT_BUFFER_TOO_SMALL:
    case PURIFY_CONSTRUCTION_PARENT_ARTIFACT_OPEN_FAILED:
    case PURIFY_CONSTRUCTION_PARENT_ARTIFACT_REJECTED:
    case PURIFY_CONSTRUCTION_PARENT_INTERNAL_ERROR:
    case PURIFY_CONSTRUCTION_PARENT_OK:
        return unexpected_error(ErrorCode::InternalMismatch,
                                "construction_parent:backend");
    }
    return unexpected_error(ErrorCode::InternalMismatch,
                            "construction_parent:status");
}

}  // namespace

struct ConstructionParentVerifier::Impl {
    explicit Impl(purify_construction_parent_verifier* verifier_in)
        : verifier(verifier_in) {}

    ~Impl() {
        purify_construction_parent_verifier_destroy(verifier);
    }

    purify_construction_parent_verifier* verifier;
};

ConstructionParentVerifier::ConstructionParentVerifier(
    std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

ConstructionParentVerifier::ConstructionParentVerifier(
    ConstructionParentVerifier&&) noexcept = default;

ConstructionParentVerifier& ConstructionParentVerifier::operator=(
    ConstructionParentVerifier&&) noexcept = default;

ConstructionParentVerifier::~ConstructionParentVerifier() = default;

Result<AnchorPunishmentKey> VerifiedConstructionReceipt::recover_anchor(
    const FieldElement& exposed_signing_scalar,
    std::size_t anchor_index,
    purify_secp_context* secp_context) const {
    if (entries_.size() != resolved_entries_.size() ||
        entries_.size() != anchor_count_) {
        return unexpected_error(ErrorCode::InternalMismatch,
                                "construction_parent:receipt_entries");
    }
    if (anchor_index >= entries_.size()) {
        return unexpected_error(ErrorCode::IndexOutOfRange,
                                "construction_parent:anchor_index");
    }
    PURIFY_ASSIGN_OR_RETURN(
        const auto& recipient,
        recover_registered_root(roster_, exposed_signing_scalar,
                                secp_context),
        "construction_parent:recover_recipient");
    const auto& entry = entries_[anchor_index];
    const auto& resolved = resolved_entries_[anchor_index];
    return recover_authenticated_anchor_ciphertext(
        recipient, resolved.punishment_key, entry.ciphertext,
        secp_context);
}

Result<ConstructionParentVerifier> ConstructionParentVerifier::load(
    std::string_view artifact_path) {
    if (artifact_path.empty() ||
        artifact_path.find('\0') != std::string_view::npos) {
        return unexpected_error(ErrorCode::RangeViolation,
                                "construction_parent:artifact_path");
    }
    purify_construction_parent_verifier* verifier = nullptr;
    const auto status = purify_construction_parent_verifier_load(
        reinterpret_cast<const std::uint8_t*>(artifact_path.data()),
        artifact_path.size(), &verifier);
    if (status != PURIFY_CONSTRUCTION_PARENT_OK) {
        return load_error(status);
    }
    if (verifier == nullptr) {
        return unexpected_error(ErrorCode::InternalMismatch,
                                "construction_parent:artifact_owner");
    }
    return ConstructionParentVerifier(
        std::make_unique<Impl>(verifier));
}

Result<VerifiedConstructionReceipt> ConstructionParentVerifier::verify(
    const ResolvedConstructionSetup& setup,
    const ConstructionReceiptEnvelope& envelope,
    std::span<const ResolvedConstructionReceiptEntry> resolved_entries,
    const ConstructionLeafAccumulator& leaves,
    purify_secp_context* secp_context) const {
    if (!impl_ || impl_->verifier == nullptr) {
        return unexpected_error(ErrorCode::UninitializedState,
                                "construction_parent:verifier");
    }

    const ConstructionReceiptPayload& payload = envelope.payload();
    if (payload.recovery_root() != setup.roster().recovery_root()) {
        return unexpected_error(ErrorCode::BindingMismatch,
                                "construction_parent:recovery_root");
    }
    PURIFY_ASSIGN_OR_RETURN(
        auto statement_digest,
        construction_receipt_statement_digest(
            payload, setup.resolved_digest(), resolved_entries),
        "construction_parent:statement");

    const auto entries = payload.entries();
    const auto anchor_count = static_cast<std::uint32_t>(entries.size());
    if (entries.size() >
        std::numeric_limits<std::size_t>::max() /
            PURIFY_CONSTRUCTION_PARENT_DESCRIPTOR_SIZE) {
        return unexpected_error(ErrorCode::Overflow,
                                "construction_parent:descriptors");
    }
    std::vector<unsigned char> descriptors;
    descriptors.reserve(entries.size() *
                        PURIFY_CONSTRUCTION_PARENT_DESCRIPTOR_SIZE);

    std::array<unsigned char, 32> raw_generator_digest{};
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto& resolved = resolved_entries[index];
        const auto& entry = entries[index];
        PURIFY_ASSIGN_OR_RETURN(
            auto constants,
            leaves.derive_parent_constants(
                setup.roster(), resolved.anchor_root,
                resolved.punishment_key, resolved.context_digest,
                entry.ciphertext, entry.circuit_precommitment,
                secp_context),
            "construction_parent:anchor_constants");
        if (index != 0 &&
            raw_generator_digest != constants.raw_generator_digest) {
            return unexpected_error(
                ErrorCode::BindingMismatch,
                "construction_parent:raw_generator_digest");
        }
        raw_generator_digest = constants.raw_generator_digest;
        append(descriptors, constants.circuit_binding_digest);
        append(descriptors, entry.circuit_precommitment);
        append(descriptors, constants.coefficient_commitment);
        append(descriptors, constants.anchored_offset);
    }
    std::array<unsigned char,
               ConstructionReceiptAccumulator::kRootClaimSerializedSize>
        pending_root{};
    const auto& basis_digest = leaves.basis().digest();
    const Bytes& proof = envelope.parent_proof();
    const auto status = purify_construction_parent_verify(
        impl_->verifier, statement_digest.data(),
        setup.resolved_digest().bytes().data(), setup.seed_root().data(),
        setup.seed_root().size(), basis_digest.data(),
        raw_generator_digest.data(), anchor_count, descriptors.data(),
        descriptors.size(), proof.data(), proof.size(), pending_root.data(),
        pending_root.size());
    if (status != PURIFY_CONSTRUCTION_PARENT_OK) {
        return verify_error(status);
    }

    PURIFY_ASSIGN_OR_RETURN(
        auto final_claim,
        bppp::accumulation::parse_root_claim(
            leaves.basis(), pending_root, secp_context),
        "construction_parent:parse_root");
    PURIFY_RETURN_IF_ERROR(
        bppp::accumulation::decide(
            leaves.basis(), final_claim, secp_context),
        "construction_parent:decide");
    return VerifiedConstructionReceipt(
        statement_digest, setup.roster(),
        std::vector<ConstructionReceiptEntry>(entries.begin(), entries.end()),
        std::vector<ResolvedConstructionReceiptEntry>(
            resolved_entries.begin(), resolved_entries.end()));
}

}  // namespace purify::accountable
