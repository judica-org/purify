// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Centralized arithmetic/proof baseline. This process holds every witness;
// it implements no MPC protocol, distributed signing, or network transport.

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "purify/bppp.hpp"

namespace {

using Clock = std::chrono::steady_clock;

double elapsed_ms(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

void usage(std::ostream& output, std::string_view executable) {
    output << "Usage: " << executable << " --members N\n"
           << "  N must be between 1 and 100. Each run creates one proof.\n"
           << "  Centralized imported arithmetic-proof baseline, not MPC.\n";
}

bool parse_members(std::string_view text, std::size_t& members) {
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), members);
    return parsed.ec == std::errc() && parsed.ptr == text.data() + text.size()
        && members >= 1 && members <= 100;
}

template <typename T>
bool succeeded(const purify::Result<T>& result, std::string_view stage) {
    if (result.has_value()) return true;
    std::cerr << "Failed at " << stage << ": " << result.error().name() << '\n';
    return false;
}

struct ProverNonce {
    purify::BulletproofScalarBytes bytes{};

    ~ProverNonce() {
        purify::detail::secure_clear_bytes(bytes.data(), bytes.size());
    }
};

int benchmark(std::size_t members) {
    std::cerr << "CENTRALIZED BASELINE: all witnesses are held by one process; no MPC.\n"
              << "Backend: imported legacy Bulletproof arithmetic circuit; members="
              << members << '\n';

    const auto start = Clock::now();
    auto context = purify::make_secp_context();
    if (context == nullptr) {
        std::cerr << "Failed to create secp context\n";
        return 1;
    }

    const auto topic = purify::bytes_from_ascii("purify.aggregate-nonce.benchmark.v1");
    auto stage = Clock::now();
    auto topic_cache = purify::puresign::TopicProofCache::build(topic);
    if (!succeeded(topic_cache, "topic template")) return 1;
    const double template_ms = elapsed_ms(stage);

    std::vector<purify::GeneratedKey> keys;
    keys.reserve(members);
    stage = Clock::now();
    for (std::size_t i = 0; i < members; ++i) {
        auto key = purify::generate_key();
        if (!succeeded(key, "member key generation")) return 1;
        keys.push_back(std::move(*key));
    }
    const double keygen_ms = elapsed_ms(stage);

    std::vector<purify::UInt512> hosts;
    std::vector<purify::BulletproofAssignmentData> assignments;
    hosts.reserve(members);
    assignments.reserve(members);
    stage = Clock::now();
    for (const auto& key : keys) {
        auto witness = purify::prove_assignment_data(topic_cache->eval_input, key.secret);
        if (!succeeded(witness, "member witness generation")) return 1;
        hosts.push_back(witness->public_key);
        assignments.push_back(std::move(witness->assignment));
    }
    const double witness_ms = elapsed_ms(stage);
    keys.clear();

    stage = Clock::now();
    auto circuit = topic_cache->circuit_template.instantiate_sum(hosts);
    if (!succeeded(circuit, "aggregate circuit construction")) return 1;
    const double circuit_ms = elapsed_ms(stage);

    stage = Clock::now();
    auto assignment = topic_cache->circuit_template.sum_assignments(hosts, assignments);
    if (!succeeded(assignment, "aggregate witness validation and composition")) return 1;
    const double composition_ms = elapsed_ms(stage);
    // Composition has copied the local witnesses. Release those duplicate
    // columns before measuring proof generation at the target circuit size.
    assignments.clear();

    const auto value_generator = purify::bppp::base_generator(context.get());
    const auto binding = purify::bytes_from_ascii("Purify/AggregateNonce/Benchmark/Arithmetic/V1");
    ProverNonce nonce;
    const auto entropy = purify::fill_secure_random(nonce.bytes);
    if (!succeeded(entropy, "private prover randomness")) return 1;

    purify::ExperimentalBulletproofBackendCache prover_cache;
    std::cerr << "Generating aggregate proof\n";
    stage = Clock::now();
    auto proof = purify::prove_experimental_circuit(
        *circuit, *assignment, nonce.bytes, value_generator, context.get(),
        binding, {}, &prover_cache);
    if (!succeeded(proof, "aggregate proof generation")) return 1;
    const double prove_ms = elapsed_ms(stage);
    prover_cache.clear();

    stage = Clock::now();
    auto serialized = proof->serialize();
    if (!succeeded(serialized, "proof serialization")) return 1;
    auto parsed = purify::ExperimentalBulletproofProof::deserialize(*serialized);
    if (!succeeded(parsed, "proof deserialization")) return 1;
    const double serialization_ms = elapsed_ms(stage);

    // A distinct cache makes verification include cold verifier-resource setup.
    purify::ExperimentalBulletproofBackendCache verifier_cache;
    std::cerr << "Verifying serialized aggregate proof\n";
    stage = Clock::now();
    auto verified = purify::verify_experimental_circuit(
        *circuit, *parsed, value_generator, context.get(), binding, &verifier_cache);
    if (!succeeded(verified, "aggregate proof verification")) return 1;
    if (!*verified) {
        std::cerr << "Aggregate proof verification rejected the generated proof\n";
        return 1;
    }
    const double verify_ms = elapsed_ms(stage);

    std::cout << std::fixed << std::setprecision(3)
              << "{\n"
              << "  \"backend\": \"imported_legacy_arithmetic\",\n"
              << "  \"centralized\": true,\n"
              << "  \"mpc\": false,\n"
              << "  \"cold_prover_and_verifier_resources\": true,\n"
              << "  \"members\": " << members << ",\n"
              << "  \"gates\": " << circuit->n_gates << ",\n"
              << "  \"constraints\": " << circuit->c.size() << ",\n"
              << "  \"public_commitments\": " << circuit->n_commitments << ",\n"
              << "  \"raw_proof_bytes\": " << proof->proof.size() << ",\n"
              << "  \"commitment_bytes\": " << (proof->commitments.size() * 33) << ",\n"
              << "  \"framed_proof_bytes\": " << serialized->size() << ",\n"
              << "  \"template_ms\": " << template_ms << ",\n"
              << "  \"keygen_ms\": " << keygen_ms << ",\n"
              << "  \"witness_ms\": " << witness_ms << ",\n"
              << "  \"circuit_ms\": " << circuit_ms << ",\n"
              << "  \"composition_ms\": " << composition_ms << ",\n"
              << "  \"prove_ms\": " << prove_ms << ",\n"
              << "  \"serialization_ms\": " << serialization_ms << ",\n"
              << "  \"verify_ms\": " << verify_ms << ",\n"
              << "  \"total_ms\": " << elapsed_ms(start) << ",\n"
              << "  \"verified\": true\n"
              << "}\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        usage(std::cout, argv[0]);
        return 0;
    }
    std::size_t members = 0;
    if (argc != 3 || std::string_view(argv[1]) != "--members" || !parse_members(argv[2], members)) {
        usage(std::cerr, argv[0]);
        return 1;
    }
    return benchmark(members);
}
