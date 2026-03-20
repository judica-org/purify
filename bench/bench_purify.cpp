// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bench_purify.cpp
 * @brief Nanobench-based performance harness for circuit construction and BPPP operations.
 */

#include <nanobench.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string_view>

#include "purify.hpp"
#include "purify_bppp.hpp"
#include "../src/purify_bppp_bridge.h"

namespace {

using namespace std::chrono_literals;

using purify::BulletproofWitnessData;
using purify::Bytes;
using purify::ExperimentalBulletproofProof;
using purify::FieldElement;
using purify::NativeBulletproofCircuit;
using purify::NativeBulletproofCircuitRow;
using purify::NativeBulletproofCircuitTemplate;
using purify::UInt512;

constexpr std::string_view kSecretHex =
    "11427c7268288dddf0cd24af3d30524fd817a91e103e7e02eb28b78db81cb350"
    "b3d2562f45fa8ecd711d1becc02fa348cf2187429228e7aac6644a3da2824e93";

#ifndef PURIFY_BENCH_BUILD_CONFIG
#define PURIFY_BENCH_BUILD_CONFIG "unspecified"
#endif

#ifndef PURIFY_BENCH_IS_RELEASE
#define PURIFY_BENCH_IS_RELEASE 0
#endif

/** @brief Runtime tuning parameters for the nanobench harness. */
struct BenchConfig {
    std::size_t epochs = 5;
    std::chrono::milliseconds min_epoch_time = 10ms;
};

/** @brief Precomputed benchmark fixture shared across benchmark cases. */
struct PurifyBenchCase {
    Bytes message;
    UInt512 secret;
    BulletproofWitnessData witness;
    NativeBulletproofCircuitTemplate circuit_template;
    NativeBulletproofCircuit circuit;
    ExperimentalBulletproofProof experimental_proof;
    purify::ExperimentalBulletproofBackendCache experimental_bulletproof_cache;
    purify::bppp::ExperimentalCircuitZkNormArgProof experimental_bppp_proof;
    purify::bppp::ExperimentalCircuitCache experimental_bppp_cache;
    purify::puresign::MessageProofCache message_proof_cache;
    purify::bppp::ExperimentalCircuitCache puresign_plusplus_cache;
    std::optional<purify::puresign::KeyPair> key_pair;
    purify::puresign::PublicKey public_key;
    std::optional<purify::puresign_plusplus::KeyPair> key_pair_plusplus;
    purify::puresign_plusplus::PublicKey public_key_plusplus;
    purify::puresign::Signature signature;
    purify::puresign::ProvenSignature proven_signature;
    purify::puresign_plusplus::ProvenSignature proven_signature_plusplus;
    purify::bppp::NormArgInputs norm_arg_inputs;
    purify::bppp::NormArgProof norm_arg_proof;
};

/** @brief Estimates heap usage for one row in the native circuit matrix. */
std::size_t estimate_bytes(const NativeBulletproofCircuitRow& row) {
    return row.entries.capacity() * sizeof(purify::NativeBulletproofCircuitTerm);
}

/** @brief Estimates heap usage for a vector of native circuit rows. */
std::size_t estimate_bytes(const std::vector<NativeBulletproofCircuitRow>& rows) {
    std::size_t total = rows.capacity() * sizeof(NativeBulletproofCircuitRow);
    for (const NativeBulletproofCircuitRow& row : rows) {
        total += estimate_bytes(row);
    }
    return total;
}

/** @brief Estimates heap usage for a vector of field elements. */
std::size_t estimate_bytes(const std::vector<FieldElement>& scalars) {
    return scalars.capacity() * sizeof(FieldElement);
}

/** @brief Estimates the aggregate in-memory footprint of a native circuit object. */
std::size_t estimate_bytes(const NativeBulletproofCircuit& circuit) {
    return sizeof(circuit)
        + estimate_bytes(circuit.wl)
        + estimate_bytes(circuit.wr)
        + estimate_bytes(circuit.wo)
        + estimate_bytes(circuit.wv)
        + estimate_bytes(circuit.c);
}

/**
 * @brief Parses benchmark-specific command-line arguments.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Parsed benchmark configuration.
 */
std::optional<BenchConfig> parse_args(int argc, char** argv, int& exit_code) {
    exit_code = -1;
    BenchConfig config;
    auto parse_u64 = [](std::string_view text, std::uint64_t& out) {
        auto result = std::from_chars(text.data(), text.data() + text.size(), out);
        return result.ec == std::errc() && result.ptr == text.data() + text.size();
    };
    auto parse_i64 = [](std::string_view text, std::int64_t& out) {
        auto result = std::from_chars(text.data(), text.data() + text.size(), out);
        return result.ec == std::errc() && result.ptr == text.data() + text.size();
    };
    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        auto consume_value = [&](const char* name, std::string_view& value) {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << name << "\n";
                exit_code = 1;
                return false;
            }
            value = argv[++i];
            return true;
        };
        if (arg == "--epochs") {
            std::string_view value;
            if (!consume_value("--epochs", value)) {
                return std::nullopt;
            }
            std::uint64_t parsed = 0;
            if (!parse_u64(value, parsed)) {
                std::cerr << "Invalid value for --epochs\n";
                exit_code = 1;
                return std::nullopt;
            }
            config.epochs = static_cast<std::size_t>(parsed);
        } else if (arg == "--min-epoch-ms") {
            std::string_view value;
            if (!consume_value("--min-epoch-ms", value)) {
                return std::nullopt;
            }
            std::int64_t parsed = 0;
            if (!parse_i64(value, parsed)) {
                std::cerr << "Invalid value for --min-epoch-ms\n";
                exit_code = 1;
                return std::nullopt;
            }
            config.min_epoch_time = std::chrono::milliseconds(parsed);
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [--epochs N] [--min-epoch-ms MS]\n";
            exit_code = 0;
            return std::nullopt;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            exit_code = 1;
            return std::nullopt;
        }
    }
    return config;
}

/** @brief Builds the shared benchmark fixture and validates the initial proof instance. */
std::optional<PurifyBenchCase> make_case() {
    PurifyBenchCase out;
    out.message = Bytes{0x01, 0x23, 0x45, 0x67};
    out.secret = UInt512::from_hex(kSecretHex);
    purify::Result<BulletproofWitnessData> witness = purify::prove_assignment_data(out.message, out.secret);
    if (!witness.has_value()) {
        std::cerr << witness.error().message() << "\n";
        return std::nullopt;
    }
    out.witness = std::move(*witness);

    purify::Result<NativeBulletproofCircuitTemplate> circuit_template = purify::verifier_circuit_template(out.message);
    if (!circuit_template.has_value()) {
        std::cerr << circuit_template.error().message() << "\n";
        return std::nullopt;
    }
    out.circuit_template = std::move(*circuit_template);

    purify::Result<NativeBulletproofCircuit> circuit = purify::verifier_circuit(out.message, out.witness.public_key);
    if (!circuit.has_value()) {
        std::cerr << circuit.error().message() << "\n";
        return std::nullopt;
    }
    out.circuit = std::move(*circuit);

    std::array<unsigned char, 32> proof_nonce{};
    for (std::size_t i = 0; i < proof_nonce.size(); ++i) {
        proof_nonce[i] = static_cast<unsigned char>(i + 17);
    }
    purify::Result<ExperimentalBulletproofProof> experimental_proof =
        purify::prove_experimental_circuit(out.circuit, out.witness.assignment, proof_nonce,
                                           purify::bppp::base_generator(),
                                           purify::bytes_from_ascii("bench-experimental-proof"),
                                           std::nullopt, &out.experimental_bulletproof_cache);
    if (!experimental_proof.has_value()) {
        std::cerr << experimental_proof.error().message() << "\n";
        return std::nullopt;
    }
    out.experimental_proof = std::move(*experimental_proof);

    purify::Result<purify::bppp::ExperimentalCircuitZkNormArgProof> experimental_bppp_proof =
        purify::bppp::prove_experimental_circuit_zk_norm_arg(
            out.circuit, out.witness.assignment, proof_nonce,
            purify::bytes_from_ascii("bench-experimental-bppp-proof"), &out.experimental_bppp_cache);
    if (!experimental_bppp_proof.has_value()) {
        std::cerr << experimental_bppp_proof.error().message() << "\n";
        return std::nullopt;
    }
    out.experimental_bppp_proof = std::move(*experimental_bppp_proof);

    purify::Result<purify::puresign::MessageProofCache> message_proof_cache =
        purify::puresign::MessageProofCache::build(out.message);
    if (!message_proof_cache.has_value()) {
        std::cerr << message_proof_cache.error().message() << "\n";
        return std::nullopt;
    }
    out.message_proof_cache = std::move(*message_proof_cache);

    purify::Result<purify::puresign::KeyPair> key_pair = purify::puresign::KeyPair::from_secret(out.secret);
    if (!key_pair.has_value()) {
        std::cerr << key_pair.error().message() << "\n";
        return std::nullopt;
    }
    out.key_pair = std::move(*key_pair);
    out.public_key = out.key_pair->public_key();

    purify::Result<purify::puresign::Signature> signature = out.key_pair->sign_message(out.message);
    if (!signature.has_value()) {
        std::cerr << signature.error().message() << "\n";
        return std::nullopt;
    }
    out.signature = std::move(*signature);

    purify::Result<purify::puresign::ProvenSignature> proven_signature = out.key_pair->sign_message_with_proof(out.message);
    if (!proven_signature.has_value()) {
        std::cerr << proven_signature.error().message() << "\n";
        return std::nullopt;
    }
    out.proven_signature = std::move(*proven_signature);

    purify::Result<purify::puresign_plusplus::KeyPair> key_pair_plusplus =
        purify::puresign_plusplus::KeyPair::from_secret(out.secret);
    if (!key_pair_plusplus.has_value()) {
        std::cerr << key_pair_plusplus.error().message() << "\n";
        return std::nullopt;
    }
    out.key_pair_plusplus = std::move(*key_pair_plusplus);
    out.public_key_plusplus = out.key_pair_plusplus->public_key();

    purify::Result<purify::puresign_plusplus::ProvenSignature> proven_signature_plusplus =
        out.key_pair_plusplus->sign_message_with_proof(out.message, &out.puresign_plusplus_cache);
    if (!proven_signature_plusplus.has_value()) {
        std::cerr << proven_signature_plusplus.error().message() << "\n";
        return std::nullopt;
    }
    out.proven_signature_plusplus = std::move(*proven_signature_plusplus);

    out.norm_arg_inputs.rho[31] = 1;
    purify::Result<std::vector<purify::bppp::PointBytes>> generators = purify::bppp::create_generators(
        out.witness.assignment.left.size() + out.witness.assignment.right.size());
    if (!generators.has_value()) {
        std::cerr << generators.error().message() << "\n";
        return std::nullopt;
    }
    out.norm_arg_inputs.generators = std::move(*generators);
    out.norm_arg_inputs.n_vec = purify::bppp::scalar_bytes(out.witness.assignment.left);
    out.norm_arg_inputs.l_vec = purify::bppp::scalar_bytes(out.witness.assignment.right);
    out.norm_arg_inputs.c_vec = purify::bppp::scalar_bytes(out.witness.assignment.output);
    purify::Result<purify::bppp::NormArgProof> proof = purify::bppp::prove_norm_arg(out.norm_arg_inputs);
    if (!proof.has_value()) {
        std::cerr << proof.error().message() << "\n";
        return std::nullopt;
    }
    out.norm_arg_proof = std::move(*proof);
    if (!purify::bppp::verify_norm_arg(out.norm_arg_proof)) {
        std::cerr << "Initial BPPP proof verification failed\n";
        return std::nullopt;
    }
    return out;
}

/** @brief Creates a consistently configured nanobench runner. */
ankerl::nanobench::Bench make_bench(const BenchConfig& config, std::string_view unit) {
    ankerl::nanobench::Bench bench;
    bench.title("purify")
        .unit(std::string(unit))
        .epochs(config.epochs)
        .minEpochTime(config.min_epoch_time)
        .warmup(1)
        .performanceCounters(false);
    return bench;
}

/** @brief Warns when the benchmark is not being run from a Release CMake configuration. */
void warn_if_not_release() {
#if !PURIFY_BENCH_IS_RELEASE
    std::cerr << "warning: bench_purify should be run from a Release CMake configuration; current configuration is "
              << PURIFY_BENCH_BUILD_CONFIG
              << ". This target forces release optimization flags, but non-Release build settings can still skew timings.\n";
#endif
}

}  // namespace

/**
 * @brief Runs the Purify benchmark suite.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Process exit status.
 */
int main(int argc, char** argv) {
    int parse_exit_code = -1;
    std::optional<BenchConfig> config = parse_args(argc, argv, parse_exit_code);
    if (!config.has_value()) {
        return parse_exit_code < 0 ? 1 : parse_exit_code;
    }

    warn_if_not_release();

    std::optional<PurifyBenchCase> bench_case = make_case();
    if (!bench_case.has_value()) {
        return 1;
    }
    std::array<unsigned char, 32> experimental_nonce{};
    for (std::size_t i = 0; i < experimental_nonce.size(); ++i) {
        experimental_nonce[i] = static_cast<unsigned char>(i + 17);
    }
    Bytes experimental_binding = purify::bytes_from_ascii("bench-experimental-proof");
    Bytes experimental_bppp_binding = purify::bytes_from_ascii("bench-experimental-bppp-proof");
    std::size_t circuit_bytes = estimate_bytes(bench_case->circuit);
    purify::Result<Bytes> proven_signature_bytes = bench_case->proven_signature.serialize();
    if (!proven_signature_bytes.has_value()) {
        std::cerr << proven_signature_bytes.error().message() << "\n";
        return 1;
    }
    purify::Result<Bytes> proven_signature_plusplus_bytes = bench_case->proven_signature_plusplus.serialize();
    if (!proven_signature_plusplus_bytes.has_value()) {
        std::cerr << proven_signature_plusplus_bytes.error().message() << "\n";
        return 1;
    }

    std::cout << "purify benchmark setup\n";
    std::cout << "proof_system=legacy_bp_and_bppp_with_puresign_legacy_and_plusplus\n";
    std::cout << "message_bytes=" << bench_case->message.size() << "\n";
    std::cout << "gates=" << bench_case->circuit.n_gates << "\n";
    std::cout << "constraints=" << bench_case->circuit.c.size() << "\n";
    std::cout << "commitments=" << bench_case->circuit.n_commitments << "\n";
    std::cout << "circuit_size_bytes=" << circuit_bytes << "\n";
    std::cout << "cache_eval_input_bytes=" << bench_case->message_proof_cache.eval_input.size() << "\n";
    std::cout << "experimental_proof_size_bytes=" << bench_case->experimental_proof.proof.size() << "\n";
    std::cout << "experimental_bppp_proof_size_bytes=" << bench_case->experimental_bppp_proof.proof.size() << "\n";
    std::cout << "norm_arg_n_vec_len=" << bench_case->norm_arg_inputs.n_vec.size() << "\n";
    std::cout << "norm_arg_l_vec_len=" << bench_case->norm_arg_inputs.l_vec.size() << "\n";
    std::cout << "norm_arg_c_vec_len=" << bench_case->norm_arg_inputs.c_vec.size() << "\n";
    std::cout << "norm_arg_proof_size_bytes=" << bench_case->norm_arg_proof.proof.size() << "\n";
    std::cout << "puresign_signature_size_bytes=" << bench_case->signature.bytes.size() << "\n";
    std::cout << "puresign_legacy_proven_signature_size_bytes=" << proven_signature_bytes->size() << "\n";
    std::cout << "puresign_plusplus_proven_signature_size_bytes=" << proven_signature_plusplus_bytes->size() << "\n";

    auto build_bench = make_bench(*config, "circuit");
    build_bench.run("verifier_circuit.native.build", [&] {
        purify::Result<NativeBulletproofCircuit> built =
            purify::verifier_circuit(bench_case->message, bench_case->witness.public_key);
        assert(built.has_value() && "benchmark verifier circuit build should succeed");
        ankerl::nanobench::doNotOptimizeAway(built->c.size());
    });

    auto instantiate_bench = make_bench(*config, "circuit");
    instantiate_bench.run("verifier_circuit.template.instantiate_native", [&] {
        purify::Result<NativeBulletproofCircuit> built =
            bench_case->circuit_template.instantiate(bench_case->witness.public_key);
        assert(built.has_value() && "benchmark verifier circuit template instantiation should succeed");
        ankerl::nanobench::doNotOptimizeAway(built->c.size());
    });

    auto instantiate_packed_bench = make_bench(*config, "circuit");
    instantiate_packed_bench.run("verifier_circuit.template.instantiate_packed", [&] {
        purify::Result<NativeBulletproofCircuit::PackedWithSlack> built =
            bench_case->circuit_template.instantiate_packed(bench_case->witness.public_key);
        assert(built.has_value() && "benchmark packed verifier circuit template instantiation should succeed");
        ankerl::nanobench::doNotOptimizeAway(built->constraint_count());
    });

    auto template_build_bench = make_bench(*config, "template");
    template_build_bench.run("verifier_circuit.template.build", [&] {
        purify::Result<NativeBulletproofCircuitTemplate> built =
            purify::verifier_circuit_template(bench_case->message);
        assert(built.has_value() && "benchmark verifier circuit template build should succeed");
        ankerl::nanobench::doNotOptimizeAway(&*built);
    });

    auto partial_eval_bench = make_bench(*config, "evaluation");
    partial_eval_bench.run("verifier_circuit.template.evaluate_partial", [&] {
        purify::Result<bool> ok = bench_case->circuit_template.partial_evaluate(bench_case->witness.assignment);
        assert(ok.has_value() && *ok && "benchmark circuit template partial evaluation should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto final_eval_bench = make_bench(*config, "evaluation");
    final_eval_bench.run("verifier_circuit.template.evaluate_final", [&] {
        purify::Result<bool> ok =
            bench_case->circuit_template.final_evaluate(bench_case->witness.assignment, bench_case->witness.public_key);
        assert(ok.has_value() && *ok && "benchmark circuit template final evaluation should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto proof_cache_build_bench = make_bench(*config, "cache");
    proof_cache_build_bench.run("puresign_legacy.message_proof_cache.build", [&] {
        purify::Result<purify::puresign::MessageProofCache> built =
            purify::puresign::MessageProofCache::build(bench_case->message);
        assert(built.has_value() && "benchmark message proof cache build should succeed");
        ankerl::nanobench::doNotOptimizeAway(built->eval_input.data());
    });

    auto experimental_prove_bench = make_bench(*config, "proof");
    experimental_prove_bench.run("experimental_circuit.legacy_bp.prove", [&] {
        purify::Result<ExperimentalBulletproofProof> proof =
            purify::prove_experimental_circuit(bench_case->circuit, bench_case->witness.assignment,
                                               experimental_nonce, purify::bppp::base_generator(),
                                               experimental_binding, std::nullopt,
                                               &bench_case->experimental_bulletproof_cache);
        assert(proof.has_value() && "benchmark experimental circuit proof should succeed");
        ankerl::nanobench::doNotOptimizeAway(proof->proof.data());
        ankerl::nanobench::doNotOptimizeAway(proof->proof.size());
    });

    auto experimental_verify_bench = make_bench(*config, "proof");
    experimental_verify_bench.run("experimental_circuit.legacy_bp.verify", [&] {
        purify::Result<bool> ok =
            purify::verify_experimental_circuit(bench_case->circuit, bench_case->experimental_proof,
                                                purify::bppp::base_generator(), experimental_binding,
                                                &bench_case->experimental_bulletproof_cache);
        assert(ok.has_value() && *ok && "benchmark experimental circuit verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto experimental_bppp_prove_bench = make_bench(*config, "proof");
    experimental_bppp_prove_bench.run("experimental_circuit.bppp_zk_norm_arg.prove", [&] {
        purify::Result<purify::bppp::ExperimentalCircuitZkNormArgProof> proof =
            purify::bppp::prove_experimental_circuit_zk_norm_arg(
                bench_case->circuit, bench_case->witness.assignment, experimental_nonce,
                experimental_bppp_binding, &bench_case->experimental_bppp_cache);
        assert(proof.has_value() && "benchmark experimental zk BPPP circuit proof should succeed");
        ankerl::nanobench::doNotOptimizeAway(proof->proof.data());
        ankerl::nanobench::doNotOptimizeAway(proof->proof.size());
    });

    auto experimental_bppp_verify_bench = make_bench(*config, "proof");
    experimental_bppp_verify_bench.run("experimental_circuit.bppp_zk_norm_arg.verify", [&] {
        purify::Result<bool> ok =
            purify::bppp::verify_experimental_circuit_zk_norm_arg(
                bench_case->circuit, bench_case->experimental_bppp_proof, experimental_bppp_binding,
                &bench_case->experimental_bppp_cache);
        assert(ok.has_value() && *ok && "benchmark experimental zk BPPP circuit verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto prove_bench = make_bench(*config, "proof");
    prove_bench.run("bppp.norm_arg.prove", [&] {
        purify::Result<purify::bppp::NormArgProof> proof = purify::bppp::prove_norm_arg(bench_case->norm_arg_inputs);
        assert(proof.has_value() && "benchmark norm-arg prove should succeed");
        ankerl::nanobench::doNotOptimizeAway(proof->proof.data());
        ankerl::nanobench::doNotOptimizeAway(proof->proof.size());
    });

    auto verify_bench = make_bench(*config, "proof");
    verify_bench.run("bppp.norm_arg.verify", [&] {
        bool ok = purify::bppp::verify_norm_arg(bench_case->norm_arg_proof);
        assert(ok && "benchmark verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(ok);
    });

    auto experimental_backend_bench = make_bench(*config, "resource_set");
    experimental_backend_bench.run("experimental_circuit.legacy_bp_backend_resources.create", [&] {
        purify_bulletproof_backend_resources* resources =
            purify_bulletproof_backend_resources_create(bench_case->circuit.n_gates);
        assert(resources != nullptr && "benchmark experimental backend resource creation should succeed");
        ankerl::nanobench::doNotOptimizeAway(resources);
        purify_bulletproof_backend_resources_destroy(resources);
    });

    auto prepare_nonce_bench = make_bench(*config, "nonce");
    prepare_nonce_bench.run("puresign_legacy.nonce.prepare", [&] {
        purify::Result<purify::puresign::PreparedNonce> prepared =
            bench_case->key_pair->prepare_message_nonce(bench_case->message);
        assert(prepared.has_value() && "benchmark PureSign nonce preparation should succeed");
        ankerl::nanobench::doNotOptimizeAway(prepared->public_nonce().xonly.data());
    });

    auto prepare_nonce_with_proof_bench = make_bench(*config, "nonce");
    prepare_nonce_with_proof_bench.run("puresign_legacy.nonce.prepare_with_proof", [&] {
        purify::Result<purify::puresign::PreparedNonceWithProof> prepared =
            bench_case->key_pair->prepare_message_nonce_with_proof(bench_case->message);
        assert(prepared.has_value() && "benchmark PureSign nonce proof preparation should succeed");
        ankerl::nanobench::doNotOptimizeAway(prepared->proof().proof.proof.data());
    });

    auto prepare_nonce_with_cached_proof_bench = make_bench(*config, "nonce");
    prepare_nonce_with_cached_proof_bench.run("puresign_legacy.nonce.prepare_with_proof_cached_template", [&] {
        purify::Result<purify::puresign::PreparedNonceWithProof> prepared =
            bench_case->key_pair->prepare_message_nonce_with_proof(bench_case->message_proof_cache);
        assert(prepared.has_value() && "benchmark cached PureSign nonce proof preparation should succeed");
        ankerl::nanobench::doNotOptimizeAway(prepared->proof().proof.proof.data());
    });

    auto prepare_nonce_with_proof_plusplus_bench = make_bench(*config, "nonce");
    prepare_nonce_with_proof_plusplus_bench.run("puresign_plusplus.nonce.prepare_with_proof", [&] {
        purify::Result<purify::puresign_plusplus::PreparedNonceWithProof> prepared =
            bench_case->key_pair_plusplus->prepare_message_nonce_with_proof(
                bench_case->message, &bench_case->puresign_plusplus_cache);
        assert(prepared.has_value() && "benchmark PureSign++ nonce proof preparation should succeed");
        ankerl::nanobench::doNotOptimizeAway(prepared->proof().proof.proof.data());
    });

    auto prepare_nonce_with_cached_proof_plusplus_bench = make_bench(*config, "nonce");
    prepare_nonce_with_cached_proof_plusplus_bench.run(
        "puresign_plusplus.nonce.prepare_with_proof_cached_template", [&] {
            purify::Result<purify::puresign_plusplus::PreparedNonceWithProof> prepared =
                bench_case->key_pair_plusplus->prepare_message_nonce_with_proof(
                    bench_case->message_proof_cache, &bench_case->puresign_plusplus_cache);
            assert(prepared.has_value() && "benchmark cached PureSign++ nonce proof preparation should succeed");
            ankerl::nanobench::doNotOptimizeAway(prepared->proof().proof.proof.data());
        });

    auto verify_nonce_with_proof_bench = make_bench(*config, "nonce");
    verify_nonce_with_proof_bench.run("puresign_legacy.nonce.verify_proof", [&] {
        purify::Result<bool> ok =
            bench_case->public_key.verify_message_nonce_proof(bench_case->message,
                                                              bench_case->proven_signature.nonce_proof);
        assert(ok.has_value() && *ok && "benchmark PureSign nonce proof verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto verify_nonce_with_cached_proof_bench = make_bench(*config, "nonce");
    verify_nonce_with_cached_proof_bench.run("puresign_legacy.nonce.verify_proof_cached_template", [&] {
        purify::Result<bool> ok =
            bench_case->public_key.verify_message_nonce_proof(bench_case->message_proof_cache,
                                                              bench_case->proven_signature.nonce_proof);
        assert(ok.has_value() && *ok && "benchmark cached PureSign nonce proof verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto verify_nonce_with_proof_plusplus_bench = make_bench(*config, "nonce");
    verify_nonce_with_proof_plusplus_bench.run("puresign_plusplus.nonce.verify_proof", [&] {
        purify::Result<bool> ok =
            bench_case->public_key_plusplus.verify_message_nonce_proof(
                bench_case->message, bench_case->proven_signature_plusplus.nonce_proof,
                &bench_case->puresign_plusplus_cache);
        assert(ok.has_value() && *ok && "benchmark PureSign++ nonce proof verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto verify_nonce_with_cached_proof_plusplus_bench = make_bench(*config, "nonce");
    verify_nonce_with_cached_proof_plusplus_bench.run(
        "puresign_plusplus.nonce.verify_proof_cached_template", [&] {
            purify::Result<bool> ok =
                bench_case->public_key_plusplus.verify_message_nonce_proof(
                    bench_case->message_proof_cache, bench_case->proven_signature_plusplus.nonce_proof,
                    &bench_case->puresign_plusplus_cache);
            assert(ok.has_value() && *ok && "benchmark cached PureSign++ nonce proof verification should succeed");
            ankerl::nanobench::doNotOptimizeAway(*ok);
        });

    auto sign_bench = make_bench(*config, "signature");
    sign_bench.run("puresign_legacy.signature.sign", [&] {
        purify::Result<purify::puresign::Signature> signature =
            bench_case->key_pair->sign_message(bench_case->message);
        assert(signature.has_value() && "benchmark PureSign signing should succeed");
        ankerl::nanobench::doNotOptimizeAway(signature->bytes.data());
    });

    auto sign_with_proof_bench = make_bench(*config, "signature");
    sign_with_proof_bench.run("puresign_legacy.signature.sign_with_proof", [&] {
        purify::Result<purify::puresign::ProvenSignature> signature =
            bench_case->key_pair->sign_message_with_proof(bench_case->message);
        assert(signature.has_value() && "benchmark PureSign proof signing should succeed");
        ankerl::nanobench::doNotOptimizeAway(signature->signature.bytes.data());
    });

    auto sign_with_cached_proof_bench = make_bench(*config, "signature");
    sign_with_cached_proof_bench.run("puresign_legacy.signature.sign_with_proof_cached_template", [&] {
        purify::Result<purify::puresign::ProvenSignature> signature =
            bench_case->key_pair->sign_message_with_proof(bench_case->message_proof_cache);
        assert(signature.has_value() && "benchmark cached PureSign proof signing should succeed");
        ankerl::nanobench::doNotOptimizeAway(signature->signature.bytes.data());
    });

    auto sign_with_proof_plusplus_bench = make_bench(*config, "signature");
    sign_with_proof_plusplus_bench.run("puresign_plusplus.signature.sign_with_proof", [&] {
        purify::Result<purify::puresign_plusplus::ProvenSignature> signature =
            bench_case->key_pair_plusplus->sign_message_with_proof(bench_case->message,
                                                                   &bench_case->puresign_plusplus_cache);
        assert(signature.has_value() && "benchmark PureSign++ proof signing should succeed");
        ankerl::nanobench::doNotOptimizeAway(signature->signature.bytes.data());
    });

    auto sign_with_cached_proof_plusplus_bench = make_bench(*config, "signature");
    sign_with_cached_proof_plusplus_bench.run("puresign_plusplus.signature.sign_with_proof_cached_template", [&] {
        purify::Result<purify::puresign_plusplus::ProvenSignature> signature =
            bench_case->key_pair_plusplus->sign_message_with_proof(
                bench_case->message_proof_cache, &bench_case->puresign_plusplus_cache);
        assert(signature.has_value() && "benchmark cached PureSign++ proof signing should succeed");
        ankerl::nanobench::doNotOptimizeAway(signature->signature.bytes.data());
    });

    auto verify_signature_bench = make_bench(*config, "signature");
    verify_signature_bench.run("puresign_legacy.signature.verify", [&] {
        purify::Result<bool> ok =
            bench_case->public_key.verify_signature(bench_case->message, bench_case->signature);
        assert(ok.has_value() && *ok && "benchmark PureSign signature verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto verify_with_proof_bench = make_bench(*config, "signature");
    verify_with_proof_bench.run("puresign_legacy.signature.verify_with_proof", [&] {
        purify::Result<bool> ok =
            bench_case->public_key.verify_message_signature_with_proof(bench_case->message,
                                                                       bench_case->proven_signature);
        assert(ok.has_value() && *ok && "benchmark PureSign proof verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto verify_signature_with_cached_proof_bench = make_bench(*config, "signature");
    verify_signature_with_cached_proof_bench.run("puresign_legacy.signature.verify_with_proof_cached_template", [&] {
        purify::Result<bool> ok =
            bench_case->public_key.verify_message_signature_with_proof(bench_case->message_proof_cache,
                                                                       bench_case->proven_signature);
        assert(ok.has_value() && *ok && "benchmark cached PureSign proof verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto verify_with_proof_plusplus_bench = make_bench(*config, "signature");
    verify_with_proof_plusplus_bench.run("puresign_plusplus.signature.verify_with_proof", [&] {
        purify::Result<bool> ok =
            bench_case->public_key_plusplus.verify_message_signature_with_proof(
                bench_case->message, bench_case->proven_signature_plusplus, &bench_case->puresign_plusplus_cache);
        assert(ok.has_value() && *ok && "benchmark PureSign++ proof verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto verify_signature_with_cached_proof_plusplus_bench = make_bench(*config, "signature");
    verify_signature_with_cached_proof_plusplus_bench.run(
        "puresign_plusplus.signature.verify_with_proof_cached_template", [&] {
            purify::Result<bool> ok =
                bench_case->public_key_plusplus.verify_message_signature_with_proof(
                    bench_case->message_proof_cache, bench_case->proven_signature_plusplus,
                    &bench_case->puresign_plusplus_cache);
            assert(ok.has_value() && *ok && "benchmark cached PureSign++ proof verification should succeed");
            ankerl::nanobench::doNotOptimizeAway(*ok);
        });

    return 0;
}
