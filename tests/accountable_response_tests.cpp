// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <span>
#include <utility>
#include <vector>

#include "purify/puresign/accountable_responses.hpp"
#include "purify/puresign/slash_adaptor.hpp"
#include "purify_test_helpers.hpp"

namespace {

using purify::FieldElement;
using purify::Result;
using purify::accountable::CoalitionCoreDigest;
using purify::accountable::ConflictContext;
using purify::accountable::NonceHostCommitment;
using purify::accountable::NonceHostBoundSigningRoster;
using purify::accountable::PartialResponse;
using purify::accountable::ScalarSignature;
using purify::accountable::SigningRoster;
using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;

using Point = std::array<unsigned char, 33>;

// Test-only centralized algebra using public toy scalars. Restore the original
// point sign after the BIP340 helper canonicalizes its scalar copy.
Result<Point> public_point(FieldElement scalar,
                           purify_secp_context* secp_context) {
    const auto original = scalar.to_bytes_be();
    auto normalized = original;
    std::array<unsigned char, 32> x{};
    if (purify_bip340_key_from_seckey(
            secp_context, normalized.data(), x.data()) == 0) {
        return purify::unexpected_error(purify::ErrorCode::RangeViolation,
                                        "response_test:point");
    }
    Point out{};
    out[0] = normalized == original ? 0x02 : 0x03;
    std::copy(x.begin(), x.end(), out.begin() + 1);
    return out;
}

Result<std::pair<FieldElement, Point>> even_secret_and_point(
    FieldElement scalar, purify_secp_context* secp_context) {
    PURIFY_ASSIGN_OR_RETURN(auto point, public_point(scalar, secp_context),
                            "response_test:even_point");
    if (point[0] == 0x03) {
        scalar = scalar.negate();
        point[0] = 0x02;
    }
    return std::pair{scalar, point};
}

Result<std::vector<PartialResponse>> toy_partials(
    const NonceHostBoundSigningRoster& roster,
    std::span<const FieldElement> secrets,
    std::span<const FieldElement> raw_nonces,
    const FieldElement& challenge) {
    if (secrets.size() != roster.members().size() ||
        raw_nonces.size() != secrets.size()) {
        return purify::unexpected_error(purify::ErrorCode::SizeMismatch,
                                        "response_test:partial_count");
    }
    std::vector<PartialResponse> out;
    out.reserve(secrets.size());
    for (std::size_t i = 0; i < secrets.size(); ++i) {
        const auto value =
            raw_nonces[i] + challenge * roster.members()[i].coefficient *
                                secrets[i];
        PURIFY_ASSIGN_OR_RETURN(
            auto response,
            ScalarSignature::deserialize(value.to_bytes_be()),
            "response_test:response_scalar");
        out.push_back({response});
    }
    return out;
}

Result<ScalarSignature> toy_aggregate_response(
    const NonceHostBoundSigningRoster& roster,
    std::span<const FieldElement> secrets,
    std::span<const FieldElement> raw_nonces,
    const FieldElement& challenge) {
    PURIFY_ASSIGN_OR_RETURN(
        const auto& partials,
        toy_partials(roster, secrets, raw_nonces, challenge),
        "response_test:aggregate_partials");
    auto aggregate = FieldElement::zero();
    for (const auto& partial : partials) {
        aggregate = aggregate +
                    FieldElement::from_bytes32(partial.response.serialize());
    }
    return ScalarSignature::deserialize(aggregate.to_bytes_be());
}

} // namespace

void run_accountable_response_tests(TestContext& ctx) {
    auto secp = purify::make_secp_context();
    ctx.expect(secp != nullptr, "response context creates");
    if (!secp) return;

    const std::array candidate_secrets{
        FieldElement::from_u64(3), FieldElement::from_u64(6),
        FieldElement::from_u64(8)};
    std::array<FieldElement, 3> secrets{};
    std::array<Point, 3> keys{};
    for (std::size_t i = 0; i < keys.size(); ++i) {
        auto member = even_secret_and_point(candidate_secrets[i], secp.get());
        expect_ok(ctx, member, "even member signing point derives");
        if (!member) return;
        secrets[i] = member->first;
        keys[i] = member->second;
    }

    const auto slot =
        purify::bytes_from_ascii("responses/domain=4/epoch=8/slot=3");
    const auto other_slot =
        purify::bytes_from_ascii("responses/domain=4/epoch=8/slot=4");
    const auto body = purify::bytes_from_ascii("decision:root-a");
    const auto other_body = purify::bytes_from_ascii("decision:root-b");
    CoalitionCoreDigest coalition_core_digest{};
    coalition_core_digest.fill(0x73);
    bool saw_odd_raw_nonce = false;

    for (const std::size_t count : {std::size_t{1}, keys.size()}) {
        auto raw_roster = SigningRoster::aggregate(
            std::span(keys).first(count), secp.get());
        expect_ok(ctx, raw_roster, "response roster aggregates");
        if (!raw_roster) return;

        std::vector<purify::puresign_plusplus::KeyPair> nonce_signers;
        std::vector<purify::puresign_plusplus::PublicKey> hosts;
        nonce_signers.reserve(count);
        hosts.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            std::array<unsigned char, 32> seed{};
            seed[0] = 0xd1;
            seed[1] = static_cast<unsigned char>(count);
            seed[2] = static_cast<unsigned char>(i);
            auto generated = purify::generate_key(seed);
            expect_ok(ctx, generated, "nonce host secret derives");
            if (!generated) return;
            auto signer = purify::puresign_plusplus::KeyPair::from_secret(
                generated->secret, secp.get());
            expect_ok(ctx, signer, "nonce host key pair derives");
            if (!signer) return;
            auto host = signer->public_key();
            std::copy(keys[i].begin() + 1, keys[i].end(),
                      host.bip340_pubkey.begin());
            hosts.push_back(host);
            nonce_signers.push_back(std::move(*signer));
        }

        auto host_commitment = purify::accountable::nonce_host_commitment(
            *raw_roster, hosts, secp.get());
        expect_ok(ctx, host_commitment,
                  "exact ordered nonce hosts commit to the roster");
        if (!host_commitment) return;
        auto roster = purify::accountable::bind_nonce_hosts(
            *raw_roster, coalition_core_digest, hosts, secp.get());
        expect_ok(ctx, roster, "response nonce hosts bind");
        if (!roster) return;
        ctx.expect(roster->nonce_host_commitment() == *host_commitment,
                   "bound roster retains the validated host commitment");
        ConflictContext context{
            roster->signing_key(), roster->nonce_host_commitment(),
            roster->coalition_core_digest(), slot};
        auto topic = purify::accountable::nonce_evaluation_input(
            context, secp.get());
        expect_ok(ctx, topic, "response nonce topic derives");
        if (!topic) return;
        auto proof_cache =
            purify::puresign_plusplus::TopicProofCache::build(*topic);
        expect_ok(ctx, proof_cache, "response nonce proof cache builds");
        if (!proof_cache) return;
        purify::bppp::ExperimentalCircuitCache shared_cache;
        std::vector<purify::puresign_plusplus::NonceProof> proofs;
        std::vector<FieldElement> raw_nonces;
        std::vector<FieldElement> normalized_nonces;
        proofs.reserve(count);
        raw_nonces.reserve(count);
        normalized_nonces.reserve(count);
        for (std::size_t i = 0; i < count; ++i) {
            auto prepared = nonce_signers[i].prepare_topic_nonce_with_proof(
                *proof_cache, secp.get(), &shared_cache);
            expect_ok(ctx, prepared, "member proves its deterministic nonce");
            if (!prepared) return;
            auto raw_scalar = prepared->raw_scalar();
            expect_ok(ctx, raw_scalar,
                      "raw scalar for the full proved point exports");
            if (!raw_scalar) return;
            auto normalized_scalar = prepared->scalar();
            expect_ok(ctx, normalized_scalar,
                      "normalized nonce scalar exports");
            if (!normalized_scalar) return;
            if (prepared->proof().commitment_point[0] == 0x03) {
                saw_odd_raw_nonce = true;
                ctx.expect(*raw_scalar != *normalized_scalar,
                           "odd raw point reverses BIP340 normalization");
            } else {
                ctx.expect(*raw_scalar == *normalized_scalar,
                           "even raw point retains the normalized scalar");
            }
            raw_nonces.push_back(FieldElement::from_bytes32(*raw_scalar));
            normalized_nonces.push_back(
                FieldElement::from_bytes32(*normalized_scalar));
            proofs.push_back(prepared->proof());
        }

        auto nonce_set = purify::accountable::verify_coalition_nonce_set(
            *roster, context, hosts, proofs, secp.get(), &shared_cache);
        expect_ok(ctx, nonce_set,
                  "all member proofs authorize one exact full nonce set");
        if (!nonce_set) return;
        ctx.expect(nonce_set->member_nonces().size() == count,
                   "verified nonce set retains every ordered full point");

        auto challenge = purify::accountable::signature_challenge(
            context, body, secp.get());
        expect_ok(ctx, challenge, "response challenge derives");
        if (!challenge) return;
        auto partials = toy_partials(
            *roster, std::span(secrets).first(count), raw_nonces,
            *challenge);
        expect_ok(ctx, partials, "raw-point response fixtures construct");
        if (!partials) return;
        for (std::size_t i = 0; i < count; ++i) {
            expect_ok(ctx,
                      purify::accountable::verify_partial_response(
                          *roster, *nonce_set, i, context, body,
                          (*partials)[i], secp.get()),
                      "each scalar-only partial matches its proved full point");
        }
        if (count == 1) {
            auto alternate_core_digest = coalition_core_digest;
            alternate_core_digest[0] ^= 1;
            auto alternate_roster = purify::accountable::bind_nonce_hosts(
                *raw_roster, alternate_core_digest, hosts, secp.get());
            expect_ok(ctx, alternate_roster,
                      "same key and hosts bind to a second coalition core");
            if (!alternate_roster) return;
            ctx.expect(alternate_roster->signing_key() ==
                           roster->signing_key() &&
                           alternate_roster->nonce_host_commitment() ==
                               roster->nonce_host_commitment(),
                       "cross-core fixture preserves Q and U");
            auto alternate_context = context;
            alternate_context.coalition_core_digest =
                alternate_core_digest;
            ctx.expect(!purify::accountable::verify_coalition_nonce_set(
                           *alternate_roster, alternate_context, hosts,
                           proofs, secp.get(), &shared_cache),
                       "nonce proofs cannot replay into another coalition core");
            expect_error(ctx,
                         purify::accountable::verify_partial_response(
                             *alternate_roster, *nonce_set, 0,
                             alternate_context, body, partials->front(),
                             secp.get()),
                         purify::ErrorCode::BindingMismatch,
                         "accepted nonce capability cannot cross cores");
        }
        auto aggregate = purify::accountable::aggregate_responses(
            *roster, *nonce_set, context, body, *partials, secp.get());
        expect_ok(ctx, aggregate,
                  "honest scalar-only partials produce a typed response");
        if (!aggregate) return;
        ctx.expect(aggregate->response().serialize().size() == 32,
                   "accepted response carries only one scalar on wire");

        auto other_challenge = purify::accountable::signature_challenge(
            context, other_body, secp.get());
        expect_ok(ctx, other_challenge,
                  "conflicting body derives a distinct challenge");
        if (!other_challenge) return;
        auto other_partials = toy_partials(
            *roster, std::span(secrets).first(count), raw_nonces,
            *other_challenge);
        expect_ok(ctx, other_partials,
                  "same proved nonces sign the conflicting body");
        if (!other_partials) return;
        auto other_aggregate = purify::accountable::aggregate_responses(
            *roster, *nonce_set, context, other_body, *other_partials,
            secp.get());
        expect_ok(ctx, other_aggregate,
                  "second conflict produces a typed response");
        if (!other_aggregate) return;
        auto recovered = purify::accountable::recover_verified_same_slot_key(
            *aggregate, *other_aggregate, secp.get());
        expect_ok(ctx, recovered,
                  "two accepted conflicts expose a typed coalition key");
        if (!recovered) return;
        auto expected_key = FieldElement::zero();
        for (std::size_t i = 0; i < count; ++i) {
            expected_key = expected_key +
                           roster->members()[i].coefficient * secrets[i];
        }
        ctx.expect(recovered->scalar() == expected_key,
                   "typed extraction returns the exact aggregate scalar");

        std::array<unsigned char, 32> anchor_seed{};
        anchor_seed[0] = 0xa7;
        anchor_seed[1] = static_cast<unsigned char>(count);
        auto anchor_secret = purify::generate_key(anchor_seed);
        expect_ok(ctx, anchor_secret, "slash anchor secret derives");
        if (!anchor_secret) return;
        auto anchor_key = purify::derive_bip340_key(
            anchor_secret->secret, secp.get());
        expect_ok(ctx, anchor_key, "slash anchor key derives");
        if (!anchor_key) return;
        purify::puresign::SecpPoint coalition_point{};
        coalition_point[0] = 0x02;
        std::copy(roster->signing_key().begin(),
                  roster->signing_key().end(),
                  coalition_point.begin() + 1);
        auto coalition_key = purify::puresign::EvenCoalitionKey::parse(
            coalition_point, secp.get());
        expect_ok(ctx, coalition_key,
                  "bound roster yields an exact even coalition key");
        if (!coalition_key) return;
        purify::puresign::SlashMessageDigest slash_digest{};
        slash_digest.fill(static_cast<unsigned char>(0x40 + count));
        auto receipt = purify::puresign::create_slash_adaptor_receipt(
            *anchor_key, *coalition_key, slash_digest, secp.get());
        expect_ok(ctx, receipt,
                  "anchor creates a receipt for the bound coalition");
        if (!receipt) return;
        auto slash_signature =
            purify::puresign::complete_slash_adaptor_receipt(
                *receipt, anchor_key->xonly_pubkey, slash_digest,
                *roster, *recovered, secp.get());
        expect_ok(ctx, slash_signature,
                  "proof-produced exposure completes the slash receipt");
        if (!slash_signature) return;
        ctx.expect(
            purify_bip340_verify(
                secp.get(), slash_signature->data(), slash_digest.data(),
                slash_digest.size(), anchor_key->xonly_pubkey.data()) != 0,
            "typed completion returns the exact slash signature");
        auto extracted = purify::puresign::extract_slash_adaptor_secret(
            *receipt, *slash_signature, anchor_key->xonly_pubkey,
            *coalition_key, slash_digest, secp.get());
        expect_ok(ctx, extracted,
                  "completed signature extracts the coalition scalar");
        if (extracted) {
            ctx.expect(*extracted == recovered->scalar().to_bytes_be(),
                       "receipt extracts the proof-produced exact scalar");
        }

        auto other_core = coalition_core_digest;
        other_core[0] ^= 1;
        auto other_core_roster = purify::accountable::bind_nonce_hosts(
            *raw_roster, other_core, hosts, secp.get());
        expect_ok(ctx, other_core_roster,
                  "same key and hosts can register under another core");
        if (!other_core_roster) return;
        expect_error(ctx,
                     purify::puresign::complete_slash_adaptor_receipt(
                         *receipt, anchor_key->xonly_pubkey, slash_digest,
                         *other_core_roster, *recovered, secp.get()),
                     purify::ErrorCode::BindingMismatch,
                     "exposure cannot complete a receipt for another core");

        auto changed_response = partials->front();
        auto plus_one =
            FieldElement::from_bytes32(changed_response.response.serialize()) +
            FieldElement::one();
        auto changed_scalar =
            ScalarSignature::deserialize(plus_one.to_bytes_be());
        expect_ok(ctx, changed_scalar, "changed partial remains canonical");
        if (!changed_scalar) return;
        changed_response.response = *changed_scalar;
        expect_error(ctx,
                     purify::accountable::verify_partial_response(
                         *roster, *nonce_set, 0, context, body,
                         changed_response, secp.get()),
                     purify::ErrorCode::EquationMismatch,
                     "changed scalar partial rejects");

        const auto odd = std::find_if(
            proofs.begin(), proofs.end(), [](const auto& proof) {
                return proof.commitment_point[0] == 0x03;
            });
        if (odd != proofs.end()) {
            const auto odd_index =
                static_cast<std::size_t>(odd - proofs.begin());
            auto normalized_partials = toy_partials(
                *roster, std::span(secrets).first(count),
                normalized_nonces, *challenge);
            expect_ok(ctx, normalized_partials,
                      "normalized nonce response fixture constructs");
            if (!normalized_partials) return;
            expect_error(ctx,
                         purify::accountable::verify_partial_response(
                             *roster, *nonce_set, odd_index, context, body,
                             (*normalized_partials)[odd_index], secp.get()),
                         purify::ErrorCode::EquationMismatch,
                         "BIP340-normalized scalar cannot answer for odd raw R");
        }

        auto varied_nonces = raw_nonces;
        varied_nonces[0] = varied_nonces[0] + FieldElement::one();
        auto varied_scalar = toy_aggregate_response(
            *roster, std::span(secrets).first(count), varied_nonces,
            *other_challenge);
        expect_ok(ctx, varied_scalar,
                  "all-evil varying-nonce scalar is algebraically formable");
        if (!varied_scalar) return;
        expect_error(ctx,
                     purify::accountable::verify_scalar_response(
                         *roster, *nonce_set, context, other_body,
                         *varied_scalar, secp.get()),
                     purify::ErrorCode::EquationMismatch,
                     "fixed proof set rejects an all-evil fresh nonce");

        auto changed_context = context;
        changed_context.host_commitment[0] ^= 1;
        expect_error(ctx,
                     purify::accountable::verify_partial_response(
                         *roster, *nonce_set, 0, changed_context, body,
                         partials->front(), secp.get()),
                     purify::ErrorCode::BindingMismatch,
                     "nonce capability cannot move to another host set");
        changed_context = context;
        changed_context.signing_key[0] ^= 1;
        expect_error(ctx,
                     purify::accountable::verify_partial_response(
                         *roster, *nonce_set, 0, changed_context, body,
                         partials->front(), secp.get()),
                     purify::ErrorCode::BindingMismatch,
                     "nonce capability cannot move to another coalition key");
        changed_context = context;
        changed_context.coalition_core_digest[0] ^= 1;
        expect_error(ctx,
                     purify::accountable::verify_partial_response(
                         *roster, *nonce_set, 0, changed_context, body,
                         partials->front(), secp.get()),
                     purify::ErrorCode::BindingMismatch,
                     "nonce capability cannot move to another coalition core");
        changed_context = context;
        changed_context.slot = other_slot;
        expect_error(ctx,
                     purify::accountable::verify_partial_response(
                         *roster, *nonce_set, 0, changed_context, body,
                         partials->front(), secp.get()),
                     purify::ErrorCode::BindingMismatch,
                     "nonce capability cannot move to another slot");
        ctx.expect(!purify::accountable::verify_coalition_nonce_set(
                       *roster, changed_context, hosts, proofs, secp.get(),
                       &shared_cache),
                   "proofs cannot be reverified for another slot");

        expect_error(ctx,
                     purify::accountable::verify_partial_response(
                         *roster, *nonce_set, count, context, body,
                         partials->front(), secp.get()),
                     purify::ErrorCode::IndexOutOfRange,
                     "out-of-range member response rejects");
        expect_error(ctx,
                     purify::accountable::aggregate_responses(
                         *roster, *nonce_set, context, body,
                         std::span(*partials).first(count - 1), secp.get()),
                     purify::ErrorCode::SizeMismatch,
                     "missing scalar response rejects");
        if (count > 1) {
            auto reordered_partials = *partials;
            std::swap(reordered_partials[0], reordered_partials[1]);
            expect_error(ctx,
                         purify::accountable::aggregate_responses(
                             *roster, *nonce_set, context, body,
                             reordered_partials, secp.get()),
                         purify::ErrorCode::EquationMismatch,
                         "reordered scalar responses reject");

            auto swapped_proofs = proofs;
            std::swap(swapped_proofs[0], swapped_proofs[1]);
            ctx.expect(!purify::accountable::verify_coalition_nonce_set(
                           *roster, context, hosts, swapped_proofs,
                           secp.get(), &shared_cache),
                       "swapped member nonce proofs reject");
            auto reordered_hosts = hosts;
            std::swap(reordered_hosts[0], reordered_hosts[1]);
            ctx.expect(!purify::accountable::verify_coalition_nonce_set(
                           *roster, context, reordered_hosts, proofs,
                           secp.get(), &shared_cache),
                       "reordered nonce hosts reject");
            auto duplicate_hosts = hosts;
            duplicate_hosts[1].purify_pubkey =
                duplicate_hosts[0].purify_pubkey;
            expect_error(ctx,
                         purify::accountable::nonce_host_commitment(
                             *roster, duplicate_hosts, secp.get()),
                         purify::ErrorCode::BindingMismatch,
                         "duplicate Purify nonce roots reject");
        }

        expect_error(ctx,
                     purify::accountable::verify_coalition_nonce_set(
                         *roster, context, hosts,
                         std::span(proofs).first(count - 1), secp.get(),
                         &shared_cache),
                     purify::ErrorCode::SizeMismatch,
                     "missing nonce proof rejects");
        expect_error(ctx,
                     purify::accountable::nonce_host_commitment(
                         *roster, std::span(hosts).first(count - 1),
                         secp.get()),
                     purify::ErrorCode::SizeMismatch,
                     "missing nonce host rejects");
        auto opposite_parity = proofs;
        opposite_parity[0].commitment_point[0] ^= 1;
        ctx.expect(!purify::accountable::verify_coalition_nonce_set(
                       *roster, context, hosts, opposite_parity, secp.get(),
                       &shared_cache),
                   "x-only-equal opposite full-point parity rejects");

        changed_context = context;
        changed_context.coalition_core_digest[0] ^= 1;
        ctx.expect(!purify::accountable::verify_coalition_nonce_set(
                       *roster, changed_context, hosts, proofs, secp.get(),
                       &shared_cache),
                   "proof set rejects a changed coalition core");
        changed_context = context;
        changed_context.signing_key[0] ^= 1;
        ctx.expect(!purify::accountable::verify_coalition_nonce_set(
                       *roster, changed_context, hosts, proofs, secp.get(),
                       &shared_cache),
                   "proof set rejects a changed coalition key");
        changed_context = context;
        changed_context.host_commitment[0] ^= 1;
        ctx.expect(!purify::accountable::verify_coalition_nonce_set(
                       *roster, changed_context, hosts, proofs, secp.get(),
                       &shared_cache),
                   "proof set rejects a changed host commitment");
    }
    ctx.expect(saw_odd_raw_nonce,
               "deterministic fixtures exercise an odd full nonce point");
}
