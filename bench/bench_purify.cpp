// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bench_purify.cpp
 * @brief Nanobench-based performance harness for circuit construction and BPPP operations.
 */

#define ANKERL_NANOBENCH_IMPLEMENT
#include "third_party/nanobench/src/include/nanobench.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string_view>

#include "purify_bppp.hpp"

namespace {

using namespace std::chrono_literals;

using purify::BulletproofWitnessData;
using purify::Bytes;
using purify::FieldElement;
using purify::NativeBulletproofCircuit;
using purify::NativeBulletproofCircuitRow;
using purify::UInt512;

constexpr std::string_view kSecretHex =
    "11427c7268288dddf0cd24af3d30524fd817a91e103e7e02eb28b78db81cb350"
    "b3d2562f45fa8ecd711d1becc02fa348cf2187429228e7aac6644a3da2824e93";

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
BenchConfig parse_args(int argc, char** argv) {
    BenchConfig config;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        auto consume_value = [&](const char* name) -> std::string_view {
            if (i + 1 >= argc) {
                throw std::runtime_error(std::string("Missing value for ") + name);
            }
            return argv[++i];
        };
        if (arg == "--epochs") {
            config.epochs = static_cast<std::size_t>(std::stoull(std::string(consume_value("--epochs"))));
        } else if (arg == "--min-epoch-ms") {
            config.min_epoch_time = std::chrono::milliseconds(std::stoll(std::string(consume_value("--min-epoch-ms"))));
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [--epochs N] [--min-epoch-ms MS]\n";
            std::exit(0);
        } else {
            throw std::runtime_error(std::string("Unknown argument: ") + std::string(arg));
        }
    }
    return config;
}

/** @brief Builds the shared benchmark fixture and validates the initial proof instance. */
PurifyBenchCase make_case() {
    PurifyBenchCase out;
    out.message = Bytes{0x01, 0x23, 0x45, 0x67};
    out.secret = UInt512::from_hex(kSecretHex);
    out.witness = purify::prove_assignment_data(out.message, out.secret);

    out.norm_arg_inputs.rho[31] = 1;
    out.norm_arg_inputs.generators = purify::bppp::create_generators(
        out.witness.assignment.left.size() + out.witness.assignment.right.size());
    out.norm_arg_inputs.n_vec = purify::bppp::scalar_bytes(out.witness.assignment.left);
    out.norm_arg_inputs.l_vec = purify::bppp::scalar_bytes(out.witness.assignment.right);
    out.norm_arg_inputs.c_vec = purify::bppp::scalar_bytes(out.witness.assignment.output);
    out.norm_arg_proof = purify::bppp::prove_norm_arg(out.norm_arg_inputs);
    if (!purify::bppp::verify_norm_arg(out.norm_arg_proof)) {
        throw std::runtime_error("Initial BPPP proof verification failed");
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

}  // namespace

/**
 * @brief Runs the Purify benchmark suite.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Process exit status.
 */
int main(int argc, char** argv) {
    BenchConfig config = parse_args(argc, argv);
    PurifyBenchCase bench_case = make_case();

    NativeBulletproofCircuit circuit = purify::verifier_circuit(bench_case.message, bench_case.witness.public_key);
    std::size_t circuit_bytes = estimate_bytes(circuit);

    std::cout << "purify benchmark setup\n";
    std::cout << "proof_system=bppp_norm_arg\n";
    std::cout << "message_bytes=" << bench_case.message.size() << "\n";
    std::cout << "gates=" << circuit.n_gates << "\n";
    std::cout << "constraints=" << circuit.c.size() << "\n";
    std::cout << "commitments=" << circuit.n_commitments << "\n";
    std::cout << "circuit_size_bytes=" << circuit_bytes << "\n";
    std::cout << "norm_arg_n_vec_len=" << bench_case.norm_arg_inputs.n_vec.size() << "\n";
    std::cout << "norm_arg_l_vec_len=" << bench_case.norm_arg_inputs.l_vec.size() << "\n";
    std::cout << "norm_arg_c_vec_len=" << bench_case.norm_arg_inputs.c_vec.size() << "\n";
    std::cout << "proof_size_bytes=" << bench_case.norm_arg_proof.proof.size() << "\n";

    auto build_bench = make_bench(config);
    build_bench.run("build native verifier circuit", [&] {
        NativeBulletproofCircuit built = purify::verifier_circuit(bench_case.message, bench_case.witness.public_key);
        ankerl::nanobench::doNotOptimizeAway(built.c.size());
    });

    auto prove_bench = make_bench(config);
    prove_bench.run("prove bppp norm arg", [&] {
        purify::bppp::NormArgProof proof = purify::bppp::prove_norm_arg(bench_case.norm_arg_inputs);
        ankerl::nanobench::doNotOptimizeAway(proof.proof.data());
        ankerl::nanobench::doNotOptimizeAway(proof.proof.size());
    });

    auto verify_bench = make_bench(config);
    verify_bench.run("verify bppp norm arg", [&] {
        bool ok = purify::bppp::verify_norm_arg(bench_case.norm_arg_proof);
        if (!ok) {
            throw std::runtime_error("BPPP verification failed during benchmark");
        }
        ankerl::nanobench::doNotOptimizeAway(ok);
    });

    return 0;
}
