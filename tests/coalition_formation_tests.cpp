// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "purify/puresign/coalition_formation.hpp"
#include "test_harness.hpp"

#include <algorithm>
#include <limits>

namespace {

using purify::accountable::BitcoinGenesisHash;
using purify::accountable::BitcoinOutpoint;
using purify::accountable::BitcoinTransactionId;
using purify::accountable::CoalitionDeploymentId;
using purify::accountable::CoalitionFormation;
using purify::accountable::CoalitionManifestDigest;
using purify_test::TestContext;
using purify_test::expect_error;
using purify_test::expect_ok;

template <typename Bytes>
Bytes sequential(unsigned char first) {
    Bytes out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<unsigned char>(first + i);
    }
    return out;
}

} // namespace

void run_coalition_formation_tests(TestContext& ctx) {
    const auto genesis = sequential<BitcoinGenesisHash>(0x00);
    const auto deployment = sequential<CoalitionDeploymentId>(0x20);
    const auto transaction_id = sequential<BitcoinTransactionId>(0x40);
    const auto manifest = sequential<CoalitionManifestDigest>(0x60);
    const BitcoinOutpoint permit{transaction_id, 0x78563412U};

    auto formation = CoalitionFormation::create({
        .genesis_hash = genesis,
        .deployment_id = deployment,
        .permit = permit,
        .manifest_digest = manifest,
    });
    expect_ok(ctx, formation, "formation vector creates");
    if (!formation) return;

    const auto expected_permit = purify::UInt256::from_hex(
        "823958198a32486bdb6778453458e73e"
        "f2e29f8b27723c0609976c3f9369d9b1")
                                     .to_bytes_be();
    const auto expected_core = purify::UInt256::from_hex(
        "5cf18b61cb0320f98eb6f8189e5ad6e4"
        "bb1d17c619048ca40163c4e385245da5")
                                   .to_bytes_be();
    ctx.expect(formation->permit_id() == expected_permit,
               "permit ID matches independent SHA-256 vector");
    ctx.expect(formation->core_digest() == expected_core,
               "coalition core matches independent SHA-256 vector");
    ctx.expect(formation->genesis_hash() == genesis &&
                   formation->deployment_id() == deployment &&
                   formation->permit() == permit &&
                   formation->manifest_digest() == manifest,
               "formation retains its exact public inputs");

    auto changed_genesis = genesis;
    changed_genesis[0] ^= 1;
    auto changed_deployment = deployment;
    changed_deployment[0] ^= 1;
    auto changed_transaction_id = transaction_id;
    changed_transaction_id[0] ^= 1;
    auto changed_manifest = manifest;
    changed_manifest[0] ^= 1;

    const auto changed_network = CoalitionFormation::create({
        .genesis_hash = changed_genesis,
        .deployment_id = deployment,
        .permit = permit,
        .manifest_digest = manifest,
    });
    const auto changed_domain = CoalitionFormation::create({
        .genesis_hash = genesis,
        .deployment_id = changed_deployment,
        .permit = permit,
        .manifest_digest = manifest,
    });
    const auto changed_transaction = CoalitionFormation::create({
        .genesis_hash = genesis,
        .deployment_id = deployment,
        .permit = {changed_transaction_id, permit.output_index},
        .manifest_digest = manifest,
    });
    const auto changed_output = CoalitionFormation::create({
        .genesis_hash = genesis,
        .deployment_id = deployment,
        .permit = {transaction_id, permit.output_index + 1},
        .manifest_digest = manifest,
    });
    const auto changed_body = CoalitionFormation::create({
        .genesis_hash = genesis,
        .deployment_id = deployment,
        .permit = permit,
        .manifest_digest = changed_manifest,
    });
    expect_ok(ctx, changed_network, "changed network formation creates");
    expect_ok(ctx, changed_domain, "changed deployment formation creates");
    expect_ok(ctx, changed_transaction,
              "changed transaction formation creates");
    expect_ok(ctx, changed_output, "changed output formation creates");
    expect_ok(ctx, changed_body, "changed manifest formation creates");
    if (changed_network && changed_domain && changed_transaction &&
        changed_output && changed_body) {
        ctx.expect(changed_network->core_digest() !=
                           formation->core_digest() &&
                       changed_domain->core_digest() !=
                           formation->core_digest() &&
                       changed_transaction->core_digest() !=
                           formation->core_digest() &&
                       changed_output->core_digest() !=
                           formation->core_digest() &&
                       changed_body->core_digest() !=
                           formation->core_digest(),
                   "every replay boundary changes the coalition core");
        ctx.expect(changed_body->permit_id() == formation->permit_id(),
                   "manifest changes retain the one-shot permit key");
        ctx.expect(changed_network->permit_id() !=
                           formation->permit_id() &&
                       changed_domain->permit_id() !=
                           formation->permit_id() &&
                       changed_transaction->permit_id() !=
                           formation->permit_id() &&
                       changed_output->permit_id() !=
                           formation->permit_id(),
                   "permit boundaries change the registry key");
    }

    BitcoinTransactionId null_transaction{};
    expect_error(
        ctx,
        CoalitionFormation::create({
            .genesis_hash = genesis,
            .deployment_id = deployment,
            .permit = {
                null_transaction,
                std::numeric_limits<std::uint32_t>::max()},
            .manifest_digest = manifest,
        }),
        purify::ErrorCode::RangeViolation,
        "Bitcoin null outpoint cannot become a formation permit");
}
