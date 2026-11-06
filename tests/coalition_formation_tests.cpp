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

    auto formation = CoalitionFormation::create(
        genesis, deployment, permit, manifest);
    expect_ok(ctx, formation, "formation vector creates");
    if (!formation) return;

    const auto expected = purify::UInt256::from_hex(
        "49139d60ea327e52b9f3a47febf5eade"
        "81a9d9f86a1a591e967721c46fd70fe9")
                              .to_bytes_be();
    ctx.expect(formation->id() == expected,
               "formation ID matches independent SHA-256 vector");
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

    const auto changed_network = CoalitionFormation::create(
        changed_genesis, deployment, permit, manifest);
    const auto changed_domain = CoalitionFormation::create(
        genesis, changed_deployment, permit, manifest);
    const auto changed_transaction = CoalitionFormation::create(
        genesis, deployment,
        BitcoinOutpoint{changed_transaction_id, permit.output_index},
        manifest);
    const auto changed_output = CoalitionFormation::create(
        genesis, deployment,
        BitcoinOutpoint{transaction_id, permit.output_index + 1},
        manifest);
    const auto changed_body = CoalitionFormation::create(
        genesis, deployment, permit, changed_manifest);
    expect_ok(ctx, changed_network, "changed network formation creates");
    expect_ok(ctx, changed_domain, "changed deployment formation creates");
    expect_ok(ctx, changed_transaction,
              "changed transaction formation creates");
    expect_ok(ctx, changed_output, "changed output formation creates");
    expect_ok(ctx, changed_body, "changed manifest formation creates");
    if (changed_network && changed_domain && changed_transaction &&
        changed_output && changed_body) {
        ctx.expect(changed_network->id() != formation->id() &&
                       changed_domain->id() != formation->id() &&
                       changed_transaction->id() != formation->id() &&
                       changed_output->id() != formation->id() &&
                       changed_body->id() != formation->id(),
                   "every replay boundary changes the formation ID");
    }

    BitcoinTransactionId null_transaction{};
    expect_error(
        ctx,
        CoalitionFormation::create(
            genesis, deployment,
            BitcoinOutpoint{
                null_transaction,
                std::numeric_limits<std::uint32_t>::max()},
            manifest),
        purify::ErrorCode::RangeViolation,
        "Bitcoin null outpoint cannot become a formation permit");
}
