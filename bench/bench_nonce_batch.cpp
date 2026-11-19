// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Coalition proving is centralized. Certificate preparation receives only
// public packets; it verifies existing proofs without compressing them.

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "purify.hpp"
#include "purify/bppp.hpp"
#include "purify/nonce_batch.hpp"

namespace {

using Clock = std::chrono::steady_clock;

struct Dimensions {
    std::size_t coalitions = 0;
    std::size_t members = 0;
    std::size_t topics = 0;
    std::size_t domains = 0;
};

struct PublicCoalitionPacket {
    std::vector<purify::NonceBatchGroup> groups;
    purify::Bytes serialized_proof;
};

struct Measurements {
    double preparation_ms = 0;
    double proving_ms = 0;
    double serialization_ms = 0;
    double public_statement_reconstruction_ms = 0;
    double public_verification_ms = 0;
    std::size_t raw_proof_bytes = 0;
    std::size_t commitment_bytes = 0;
    std::size_t proof_payload_bytes = 0;
    std::vector<std::size_t> coalition_gates;
};

struct ProverNonce {
    purify::BulletproofScalarBytes bytes{};

    ~ProverNonce() {
        purify::detail::secure_clear_bytes(bytes.data(), bytes.size());
    }
};

double elapsed_ms(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

template <typename T>
bool succeeded(const purify::Result<T>& result, std::string_view stage) {
    if (result.has_value()) return true;
    std::cerr << "Failed at " << stage << ": " << result.error().name() << '\n';
    return false;
}

void usage(std::ostream& output, std::string_view executable) {
    output << "Usage: " << executable
           << " --coalitions N --members M --topics P --domains K\n"
           << "  Each dimension must be 1..100; N*M*P*K must be <=400.\n"
           << "  One centralized proof per coalition; public-only certificate preparation.\n"
           << "  Imported arithmetic backend; no MPC or succinct public aggregation.\n";
}

bool parse_dimensions(int argc, char** argv, Dimensions& dimensions) {
    if (argc != 9) return false;
    for (int i = 1; i < argc; i += 2) {
        std::size_t* destination = nullptr;
        const std::string_view option(argv[i]);
        if (option == "--coalitions") destination = &dimensions.coalitions;
        else if (option == "--members") destination = &dimensions.members;
        else if (option == "--topics") destination = &dimensions.topics;
        else if (option == "--domains") destination = &dimensions.domains;
        if (destination == nullptr || *destination != 0) return false;
        const std::string_view argument(argv[i + 1]);
        const auto parsed = std::from_chars(argument.data(), argument.data() + argument.size(), *destination);
        if (parsed.ec != std::errc() || parsed.ptr != argument.data() + argument.size()
            || *destination < 1 || *destination > 100) return false;
    }
    // Bounding each multiplication also makes the check safe on narrow size_t.
    std::size_t evaluations = 1;
    for (const auto count : {dimensions.coalitions, dimensions.members, dimensions.topics, dimensions.domains}) {
        if (count == 0 || count > 400 / evaluations) return false;
        evaluations *= count;
    }
    return true;
}

purify::Bytes topic_bytes(std::size_t coalition, std::size_t domain, std::size_t slot) {
    auto topic = purify::bytes_from_ascii("Purify/NonceBatch/Benchmark/Topic/V1");
    for (const auto index : {coalition, domain, slot}) {
        const auto value = static_cast<std::uint64_t>(index);
        for (unsigned shift = 0; shift < 64; shift += 8) {
            topic.push_back(static_cast<unsigned char>(value >> shift));
        }
    }
    return topic;
}

const purify::Bytes& statement_binding() {
    static const auto binding = purify::bytes_from_ascii("Purify/NonceBatch/Benchmark/Arithmetic/V1");
    return binding;
}

bool build_coalition_packet(std::size_t coalition,
                            const Dimensions& dimensions,
                            purify_secp_context* context,
                            PublicCoalitionPacket& packet,
                            Measurements& measurements) {
    auto stage = Clock::now();
    std::vector<purify::GeneratedKey> keys;
    keys.reserve(dimensions.members);
    for (std::size_t member = 0; member < dimensions.members; ++member) {
        auto key = purify::generate_key();
        if (!succeeded(key, "member key generation")) return false;
        keys.push_back(std::move(*key));
    }

    std::vector<std::vector<purify::BulletproofAssignmentData>> assignments;
    const auto output_count = dimensions.topics * dimensions.domains;
    packet.groups.reserve(output_count);
    assignments.reserve(output_count);
    for (std::size_t domain = 0; domain < dimensions.domains; ++domain) {
        for (std::size_t slot = 0; slot < dimensions.topics; ++slot) {
            auto topic = purify::puresign::TopicProofCache::build(topic_bytes(coalition, domain, slot));
            if (!succeeded(topic, "topic preparation")) return false;
            purify::NonceBatchGroup group;
            group.evaluation_input = topic->eval_input;
            group.hosts.reserve(dimensions.members);
            std::vector<purify::BulletproofAssignmentData> member_assignments;
            member_assignments.reserve(dimensions.members);
            for (const auto& key : keys) {
                auto witness = purify::prove_assignment_data(group.evaluation_input, key.secret);
                if (!succeeded(witness, "member witness generation")) return false;
                group.hosts.push_back(witness->public_key);
                member_assignments.push_back(std::move(witness->assignment));
            }
            packet.groups.push_back(std::move(group));
            assignments.push_back(std::move(member_assignments));
        }
    }

    auto circuit = purify::nonce_batch_circuit(packet.groups);
    if (!succeeded(circuit, "coalition batch circuit")) return false;
    auto assignment = purify::nonce_batch_assignments(packet.groups, assignments);
    if (!succeeded(assignment, "coalition batch assignment")) return false;
    assignments.clear();
    keys.clear();
    measurements.preparation_ms += elapsed_ms(stage);

    ProverNonce nonce;
    const auto entropy = purify::fill_secure_random(nonce.bytes);
    if (!succeeded(entropy, "private prover randomness")) return false;
    purify::ExperimentalBulletproofBackendCache cache;
    stage = Clock::now();
    auto proof = purify::prove_experimental_circuit(
        *circuit, *assignment, nonce.bytes, purify::bppp::base_generator(context), context,
        statement_binding(), {}, &cache);
    if (!succeeded(proof, "coalition proof generation")) return false;
    measurements.proving_ms += elapsed_ms(stage);

    stage = Clock::now();
    auto serialized = proof->serialize();
    if (!succeeded(serialized, "coalition proof serialization")) return false;
    packet.serialized_proof = std::move(*serialized);
    measurements.serialization_ms += elapsed_ms(stage);
    return true;
}

// No assignment, secret key, or nonce scalar crosses this API. This diagnostic
// verifies the immutable packets; it defines no certificate wire format.
bool prepare_certificate(std::span<const PublicCoalitionPacket> packets,
                         purify_secp_context* context,
                         Measurements& measurements) {
    for (const auto& packet : packets) {
        auto stage = Clock::now();
        auto circuit = purify::nonce_batch_circuit(packet.groups);
        if (!succeeded(circuit, "public statement reconstruction")) return false;
        auto proof = purify::ExperimentalBulletproofProof::deserialize(packet.serialized_proof);
        if (!succeeded(proof, "public proof parsing")) return false;
        measurements.public_statement_reconstruction_ms += elapsed_ms(stage);

        // Each coalition starts with cold verifier resources.
        purify::ExperimentalBulletproofBackendCache cache;
        stage = Clock::now();
        auto verified = purify::verify_experimental_circuit(
            *circuit, *proof, purify::bppp::base_generator(context), context,
            statement_binding(), &cache);
        if (!succeeded(verified, "public proof verification")) return false;
        if (!*verified) {
            std::cerr << "Public certificate preparation rejected a coalition proof\n";
            return false;
        }
        measurements.public_verification_ms += elapsed_ms(stage);
        measurements.coalition_gates.push_back(circuit->n_gates);
        measurements.raw_proof_bytes += proof->proof.size();
        measurements.commitment_bytes += proof->commitments.size() * sizeof(purify::BulletproofPointBytes);
        measurements.proof_payload_bytes += packet.serialized_proof.size();
    }
    return true;
}

int benchmark(const Dimensions& dimensions) {
    std::cerr << "Centralized coalition proofs; public-only verification and packing, no succinct merge.\n";
    const auto start = Clock::now();
    auto context = purify::make_secp_context();
    if (context == nullptr) {
        std::cerr << "Failed to create secp context\n";
        return 1;
    }
    Measurements measurements;
    std::vector<PublicCoalitionPacket> packets(dimensions.coalitions);
    for (std::size_t coalition = 0; coalition < dimensions.coalitions; ++coalition) {
        std::cerr << "Proving coalition " << coalition + 1 << '/' << dimensions.coalitions << '\n';
        if (!build_coalition_packet(coalition, dimensions, context.get(), packets[coalition], measurements)) return 1;
    }
    std::cerr << "Preparing certificate from public packets\n";
    if (!prepare_certificate(packets, context.get(), measurements)) return 1;

    std::cout << std::fixed << std::setprecision(3)
              << "{\n"
              << "  \"backend\": \"imported_legacy_arithmetic\",\n"
              << "  \"centralized_within_coalition\": true,\n"
              << "  \"mpc\": false,\n"
              << "  \"public_only_preparation\": true,\n"
              << "  \"succinct_post_coalition_aggregation\": false,\n"
              << "  \"coalitions\": " << dimensions.coalitions << ",\n"
              << "  \"members\": " << dimensions.members << ",\n"
              << "  \"topics\": " << dimensions.topics << ",\n"
              << "  \"domains\": " << dimensions.domains << ",\n"
              << "  \"member_evaluations\": " << dimensions.coalitions * dimensions.members * dimensions.topics * dimensions.domains << ",\n"
              << "  \"public_commitments\": " << dimensions.coalitions * dimensions.topics * dimensions.domains << ",\n"
              << "  \"coalition_gates\": [";
    for (std::size_t i = 0; i < measurements.coalition_gates.size(); ++i) {
        if (i != 0) std::cout << ", ";
        std::cout << measurements.coalition_gates[i];
    }
    std::cout << "],\n"
              << "  \"raw_proof_bytes\": " << measurements.raw_proof_bytes << ",\n"
              << "  \"commitment_bytes\": " << measurements.commitment_bytes << ",\n"
              << "  \"proof_payload_bytes\": " << measurements.proof_payload_bytes << ",\n"
              << "  \"payload_excludes_manifest_bitcoin_and_signatures\": true,\n"
              << "  \"preparation_ms\": " << measurements.preparation_ms << ",\n"
              << "  \"proving_ms\": " << measurements.proving_ms << ",\n"
              << "  \"serialization_ms\": " << measurements.serialization_ms << ",\n"
              << "  \"public_statement_reconstruction_ms\": " << measurements.public_statement_reconstruction_ms << ",\n"
              << "  \"public_verification_ms\": " << measurements.public_verification_ms << ",\n"
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
    Dimensions dimensions;
    if (!parse_dimensions(argc, argv, dimensions)) {
        usage(std::cerr, argv[0]);
        return 1;
    }
    return benchmark(dimensions);
}
