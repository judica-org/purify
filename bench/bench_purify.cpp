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

namespace {

using namespace std::chrono_literals;

using purify::BulletproofWitnessData;
using purify::Bytes;
using purify::ExperimentalBulletproofProof;
using purify::FieldElement;
using purify::NativeBulletproofCircuit;
using purify::NativeBulletproofCircuitRow;
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
    NativeBulletproofCircuit circuit;
    ExperimentalBulletproofProof experimental_proof;
    purify::puresign::PublicKey public_key;
    purify::puresign::Signature signature;
    purify::puresign::ProvenSignature proven_signature;
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
                                           purify::bytes_from_ascii("bench-experimental-proof"));
    if (!experimental_proof.has_value()) {
        std::cerr << experimental_proof.error().message() << "\n";
        return std::nullopt;
    }
    out.experimental_proof = std::move(*experimental_proof);

    purify::Result<purify::puresign::PublicKey> public_key = purify::puresign::derive_public_key(out.secret);
    if (!public_key.has_value()) {
        std::cerr << public_key.error().message() << "\n";
        return std::nullopt;
    }
    out.public_key = std::move(*public_key);

    purify::Result<purify::puresign::Signature> signature = purify::puresign::sign_message(out.secret, out.message);
    if (!signature.has_value()) {
        std::cerr << signature.error().message() << "\n";
        return std::nullopt;
    }
    out.signature = std::move(*signature);

    purify::Result<purify::puresign::ProvenSignature> proven_signature =
        purify::puresign::sign_message_with_proof(out.secret, out.message);
    if (!proven_signature.has_value()) {
        std::cerr << proven_signature.error().message() << "\n";
        return std::nullopt;
    }
    out.proven_signature = std::move(*proven_signature);

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
ankerl::nanobench::Bench make_bench(const BenchConfig& config) {
    ankerl::nanobench::Bench bench;
    bench.title("purify")
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
    std::size_t circuit_bytes = estimate_bytes(bench_case->circuit);
    purify::Result<Bytes> proven_signature_bytes = bench_case->proven_signature.serialize();
    if (!proven_signature_bytes.has_value()) {
        std::cerr << proven_signature_bytes.error().message() << "\n";
        return 1;
    }

    std::cout << "purify benchmark setup\n";
    std::cout << "proof_system=experimental_bulletproof_and_bppp_norm_arg\n";
    std::cout << "message_bytes=" << bench_case->message.size() << "\n";
    std::cout << "gates=" << bench_case->circuit.n_gates << "\n";
    std::cout << "constraints=" << bench_case->circuit.c.size() << "\n";
    std::cout << "commitments=" << bench_case->circuit.n_commitments << "\n";
    std::cout << "circuit_size_bytes=" << circuit_bytes << "\n";
    std::cout << "experimental_proof_size_bytes=" << bench_case->experimental_proof.proof.size() << "\n";
    std::cout << "norm_arg_n_vec_len=" << bench_case->norm_arg_inputs.n_vec.size() << "\n";
    std::cout << "norm_arg_l_vec_len=" << bench_case->norm_arg_inputs.l_vec.size() << "\n";
    std::cout << "norm_arg_c_vec_len=" << bench_case->norm_arg_inputs.c_vec.size() << "\n";
    std::cout << "norm_arg_proof_size_bytes=" << bench_case->norm_arg_proof.proof.size() << "\n";
    std::cout << "puresign_signature_size_bytes=" << bench_case->signature.bytes.size() << "\n";
    std::cout << "puresign_proven_signature_size_bytes=" << proven_signature_bytes->size() << "\n";

    auto build_bench = make_bench(*config);
    build_bench.run("build native verifier circuit", [&] {
        purify::Result<NativeBulletproofCircuit> built = purify::verifier_circuit(bench_case->message, bench_case->witness.public_key);
        assert(built.has_value() && "benchmark verifier circuit build should succeed");
        ankerl::nanobench::doNotOptimizeAway(built->c.size());
    });

    auto experimental_prove_bench = make_bench(*config);
    experimental_prove_bench.run("prove experimental circuit", [&] {
        purify::Result<ExperimentalBulletproofProof> proof =
            purify::prove_experimental_circuit(bench_case->circuit, bench_case->witness.assignment,
                                               experimental_nonce, purify::bppp::base_generator(),
                                               experimental_binding);
        assert(proof.has_value() && "benchmark experimental circuit proof should succeed");
        ankerl::nanobench::doNotOptimizeAway(proof->proof.data());
        ankerl::nanobench::doNotOptimizeAway(proof->proof.size());
    });

    auto experimental_verify_bench = make_bench(*config);
    experimental_verify_bench.run("verify experimental circuit", [&] {
        purify::Result<bool> ok =
            purify::verify_experimental_circuit(bench_case->circuit, bench_case->experimental_proof,
                                                purify::bppp::base_generator(), experimental_binding);
        assert(ok.has_value() && *ok && "benchmark experimental circuit verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto prove_bench = make_bench(*config);
    prove_bench.run("prove bppp norm arg", [&] {
        purify::Result<purify::bppp::NormArgProof> proof = purify::bppp::prove_norm_arg(bench_case->norm_arg_inputs);
        assert(proof.has_value() && "benchmark norm-arg prove should succeed");
        ankerl::nanobench::doNotOptimizeAway(proof->proof.data());
        ankerl::nanobench::doNotOptimizeAway(proof->proof.size());
    });

    auto verify_bench = make_bench(*config);
    verify_bench.run("verify bppp norm arg", [&] {
        bool ok = purify::bppp::verify_norm_arg(bench_case->norm_arg_proof);
        assert(ok && "benchmark verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(ok);
    });

    auto prepare_nonce_bench = make_bench(*config);
    prepare_nonce_bench.run("prepare puresign message nonce", [&] {
        purify::Result<purify::puresign::PreparedNonce> prepared =
            purify::puresign::prepare_message_nonce(bench_case->secret, bench_case->message);
        assert(prepared.has_value() && "benchmark PureSign nonce preparation should succeed");
        ankerl::nanobench::doNotOptimizeAway(prepared->public_nonce().xonly.data());
    });

    auto sign_bench = make_bench(*config);
    sign_bench.run("sign puresign message", [&] {
        purify::Result<purify::puresign::Signature> signature =
            purify::puresign::sign_message(bench_case->secret, bench_case->message);
        assert(signature.has_value() && "benchmark PureSign signing should succeed");
        ankerl::nanobench::doNotOptimizeAway(signature->bytes.data());
    });

    auto sign_with_proof_bench = make_bench(*config);
    sign_with_proof_bench.run("sign puresign message with proof", [&] {
        purify::Result<purify::puresign::ProvenSignature> signature =
            purify::puresign::sign_message_with_proof(bench_case->secret, bench_case->message);
        assert(signature.has_value() && "benchmark PureSign proof signing should succeed");
        ankerl::nanobench::doNotOptimizeAway(signature->signature.bytes.data());
    });

    auto verify_signature_bench = make_bench(*config);
    verify_signature_bench.run("verify puresign signature", [&] {
        purify::Result<bool> ok =
            purify::puresign::verify_signature(bench_case->public_key, bench_case->message, bench_case->signature);
        assert(ok.has_value() && *ok && "benchmark PureSign signature verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    auto verify_with_proof_bench = make_bench(*config);
    verify_with_proof_bench.run("verify puresign signature with proof", [&] {
        purify::Result<bool> ok =
            purify::puresign::verify_message_signature_with_proof(bench_case->public_key, bench_case->message,
                                                                  bench_case->proven_signature);
        assert(ok.has_value() && *ok && "benchmark PureSign proof verification should succeed");
        ankerl::nanobench::doNotOptimizeAway(*ok);
    });

    return 0;
}
