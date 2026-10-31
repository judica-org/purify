// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Public accumulation of synthetic standalone norm proofs. This is neither a
// construction-receipt proof nor a benchmark of the experimental circuit layer.

#include <charconv>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <string_view>

#include "purify/accumulation.hpp"

namespace {

using Clock = std::chrono::steady_clock;
using purify::FieldElement;
using purify::bppp::ScalarBytes;
namespace accumulation = purify::bppp::accumulation;

struct Options {
    std::size_t claims = 0;
    std::size_t norm_size = 0;
    std::size_t linear_size = 0;
};

void usage(std::ostream& out, const char* executable) {
    out << "Usage: " << executable << " --claims N --norm-size G --linear-size H\n"
        << "  1 <= N <= 1000; G is a power of two <= 32768; H is a power of two <= G.\n"
        << "  Synthetic standalone norm proofs with different public c-vectors.\n"
        << "  Original inputs and authenticated accumulation transitions remain required.\n";
}

bool parse_options(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view option(argv[i]);
        std::size_t* target = nullptr;
        if (option == "--claims") target = &options.claims;
        if (option == "--norm-size") target = &options.norm_size;
        if (option == "--linear-size") target = &options.linear_size;
        if (target == nullptr || *target != 0 || i + 1 == argc) return false;
        const std::string_view value(argv[++i]);
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), *target);
        if (parsed.ec != std::errc() || parsed.ptr != value.data() + value.size() || *target == 0) {
            return false;
        }
    }
    return options.claims <= 1000 && options.claims != 0 && options.norm_size <= 32768 &&
        purify::is_power_of_two_size(options.norm_size) &&
        purify::is_power_of_two_size(options.linear_size) && options.linear_size <= options.norm_size;
}

double elapsed_ms(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

template <typename T>
bool succeeded(const purify::Result<T>& result, std::string_view stage) {
    if (result.has_value()) return true;
    std::cerr << "Failed at " << stage << ": " << result.error().name() << '\n';
    return false;
}

struct PrivateWitness {
    purify::bppp::NormArgInputs inputs;

    ~PrivateWitness() {
        purify::detail::secure_clear_bytes(inputs.n_vec.data(), inputs.n_vec.size() * sizeof(ScalarBytes));
        purify::detail::secure_clear_bytes(inputs.l_vec.data(), inputs.l_vec.size() * sizeof(ScalarBytes));
    }
};

purify::Status sample_witness(std::vector<ScalarBytes>& values) {
    // Dimensions are bounded by the CLI. One bulk RNG call avoids measuring
    // a system-call-per-coordinate workload instead of the proof protocol.
    PURIFY_RETURN_IF_ERROR(purify::fill_secure_random(std::span(
        reinterpret_cast<unsigned char*>(values.data()), values.size() * sizeof(ScalarBytes))),
        "benchmark:random_witness");
    for (auto& value : values) {
        for (;;) {
            const auto parsed = FieldElement::try_from_bytes32(value);
            if (parsed && !parsed->is_zero()) break;
            PURIFY_RETURN_IF_ERROR(purify::fill_secure_random(value), "benchmark:resample_witness");
        }
    }
    return {};
}

// The generator stream is shared through Basis. Every leaf retains its own
// canonical public coefficient vector for authenticated statement replay.
struct PublishedNorm {
    ScalarBytes rho;
    purify::bppp::PointBytes commitment;
    std::vector<ScalarBytes> c_vec;
    purify::Bytes proof;
};

purify::Result<PublishedNorm> publish_norm(const accumulation::Basis& basis, std::size_t index,
                                          purify_secp_context* context) {
    PrivateWitness witness;
    witness.inputs.rho = FieldElement::from_u64(index + 3).to_bytes_be();
    witness.inputs.generators = basis.norm_generators();
    witness.inputs.c_vec.reserve(basis.l_vec_len());
    for (std::size_t i = 0; i < basis.l_vec_len(); ++i) {
        witness.inputs.c_vec.push_back(
            FieldElement::from_u64(17 + index * basis.l_vec_len() + i).to_bytes_be());
    }
    witness.inputs.n_vec.resize(basis.n_vec_len());
    witness.inputs.l_vec.resize(basis.l_vec_len());
    PURIFY_RETURN_IF_ERROR(sample_witness(witness.inputs.n_vec), "benchmark:n_witness");
    PURIFY_RETURN_IF_ERROR(sample_witness(witness.inputs.l_vec), "benchmark:l_witness");
    PURIFY_ASSIGN_OR_RETURN(auto published, purify::bppp::prove_norm_arg(witness.inputs, context),
                            "benchmark:publish_norm");
    // The private input vectors are erased as this function exits. Only the
    // completed public norm proof escapes into the subsequent public stages.
    return PublishedNorm{published.rho, published.commitment,
                         std::move(published.c_vec), std::move(published.proof)};
}

int benchmark(const Options& options) {
    auto context = purify::make_secp_context();
    if (!context) {
        std::cerr << "Could not create secp256k1 context\n";
        return 1;
    }
    auto stage = Clock::now();
    auto basis = accumulation::Basis::create(options.norm_size, options.linear_size,
        "Purify/Benchmark/StandaloneNorm/V1", context.get());
    if (!succeeded(basis, "common deterministic basis")) return 1;
    const double basis_ms = elapsed_ms(stage);

    stage = Clock::now();
    std::vector<PublishedNorm> published;
    published.reserve(options.claims);
    std::size_t child_proof_bytes = 0;
    std::size_t public_leaf_record_bytes = 0;
    std::size_t coefficient_bytes = 0;
    for (std::size_t i = 0; i < options.claims; ++i) {
        auto leaf = publish_norm(*basis, i, context.get());
        if (!succeeded(leaf, "independent leaf publication")) return 1;
        child_proof_bytes += leaf->proof.size();
        const auto c_bytes = leaf->c_vec.size() * sizeof(ScalarBytes);
        coefficient_bytes += c_bytes;
        public_leaf_record_bytes += leaf->rho.size() + leaf->commitment.size() + c_bytes + leaf->proof.size();
        published.push_back(std::move(*leaf));
        if ((i + 1) % 10 == 0 || i + 1 == options.claims) {
            std::cerr << "Published " << i + 1 << '/' << options.claims << " standalone norm proofs\n";
        }
    }
    const double leaf_publication_ms = elapsed_ms(stage);

    std::vector<accumulation::PendingClaim> claims;
    claims.reserve(published.size());
    std::vector<purify::Bytes> reduction_transcripts;
    reduction_transcripts.reserve(published.size());
    purify::bppp::NormArgProof public_input;
    public_input.n_vec_len = basis->n_vec_len();
    public_input.generators = basis->norm_generators();
    std::size_t polynomial_terms = 0;
    std::size_t polynomial_scalars = 0;
    std::size_t coefficient_commitment_bytes = 0;
    std::size_t reduction_proof_bytes = 0;
    double prepare_ms = 0;
    double prove_reduction_ms = 0;
    double reduction_codec_ms = 0;
    double verify_reduction_ms = 0;
    for (const auto& leaf : published) {
        stage = Clock::now();
        public_input.rho = leaf.rho;
        public_input.commitment = leaf.commitment;
        public_input.c_vec = leaf.c_vec;
        public_input.proof = leaf.proof;
        auto prepared = accumulation::prepare_norm(*basis, public_input, context.get());
        if (!succeeded(prepared, "public norm preparation and coefficient authentication")) return 1;
        prepare_ms += elapsed_ms(stage);
        coefficient_commitment_bytes += prepared->coefficient_commitment().size();

        stage = Clock::now();
        auto reduction = accumulation::prove_norm_reduction(*basis, *prepared, context.get());
        if (!succeeded(reduction, "public coefficient opening")) return 1;
        prove_reduction_ms += elapsed_ms(stage);

        stage = Clock::now();
        auto encoded_reduction = accumulation::serialize_norm_reduction(*basis, *reduction, context.get());
        if (!succeeded(encoded_reduction, "norm reduction serialization")) return 1;
        auto parsed_reduction = accumulation::parse_norm_reduction(*basis, *encoded_reduction, context.get());
        if (!succeeded(parsed_reduction, "norm reduction parsing")) return 1;
        reduction_codec_ms += elapsed_ms(stage);

        stage = Clock::now();
        auto claim = accumulation::verify_norm_reduction(*basis, *prepared, *parsed_reduction, context.get());
        if (!succeeded(claim, "short norm reduction verification")) return 1;
        verify_reduction_ms += elapsed_ms(stage);
        polynomial_terms += claim->polynomial().size();
        for (const auto& term : claim->polynomial()) polynomial_scalars += 1 + term.factors.size();
        claims.push_back(std::move(*claim));
        reduction_proof_bytes += encoded_reduction->size();
        reduction_transcripts.push_back(std::move(*encoded_reduction));
        if (reduction_transcripts.size() % 10 == 0 || reduction_transcripts.size() == published.size()) {
            std::cerr << "Verified " << reduction_transcripts.size() << '/' << published.size()
                      << " public norm reductions\n";
        }
    }

    stage = Clock::now();
    auto proof = accumulation::prove_step(*basis, claims, context.get());
    if (!succeeded(proof, "public accumulation proving")) return 1;
    const double prove_step_ms = elapsed_ms(stage);

    stage = Clock::now();
    auto encoded = accumulation::serialize_step(*basis, *proof, context.get());
    if (!succeeded(encoded, "canonical step serialization")) return 1;
    auto parsed = accumulation::parse_step(*basis, *encoded, context.get());
    if (!succeeded(parsed, "canonical step parsing")) return 1;
    const double codec_ms = elapsed_ms(stage);

    stage = Clock::now();
    auto pending = accumulation::verify_step(*basis, claims, *parsed, context.get());
    if (!succeeded(pending, "short accumulation verification")) return 1;
    const double verify_step_ms = elapsed_ms(stage);

    stage = Clock::now();
    auto decided = accumulation::decide(*basis, *pending, context.get());
    if (!succeeded(decided, "mandatory final decider")) return 1;
    const double decide_ms = elapsed_ms(stage);

    std::cout << std::fixed << std::setprecision(3)
        << "{\n"
        << "  \"scope\": \"synthetic_standalone_norm_accumulation\",\n"
        << "  \"common_c_vector_required\": false,\n"
        << "  \"private_witnesses_needed_for_accumulation\": false,\n"
        << "  \"original_inputs_and_authenticated_transitions_required\": true,\n"
        << "  \"compressed_construction_receipt\": false,\n"
        << "  \"claims\": " << options.claims << ",\n"
        << "  \"norm_size\": " << options.norm_size << ",\n"
        << "  \"linear_size\": " << options.linear_size << ",\n"
        << "  \"basis_dimension\": " << basis->dimension() << ",\n"
        << "  \"step_proof_bytes\": " << encoded->size() << ",\n"
        << "  \"child_norm_proof_bytes\": " << child_proof_bytes << ",\n"
        << "  \"retained_public_leaf_record_bytes\": " << public_leaf_record_bytes << ",\n"
        << "  \"retained_public_coefficient_bytes\": " << coefficient_bytes << ",\n"
        << "  \"derived_coefficient_commitment_bytes\": " << coefficient_commitment_bytes << ",\n"
        << "  \"retained_coefficient_opening_proof_bytes\": " << reduction_proof_bytes << ",\n"
        << "  \"retained_coefficient_opening_count\": " << reduction_transcripts.size() << ",\n"
        << "  \"public_claim_descriptor_count\": " << claims.size() << ",\n"
        << "  \"public_polynomial_term_count\": " << polynomial_terms << ",\n"
        << "  \"public_polynomial_scalar_count\": " << polynomial_scalars << ",\n"
        << "  \"timings_ms\": {\n"
        << "    \"basis\": " << basis_ms << ",\n"
        << "    \"leaf_publication\": " << leaf_publication_ms << ",\n"
        << "    \"prepare_and_authenticate_coefficients\": " << prepare_ms << ",\n"
        << "    \"prove_norm_reductions\": " << prove_reduction_ms << ",\n"
        << "    \"reduction_codec_roundtrip\": " << reduction_codec_ms << ",\n"
        << "    \"verify_norm_reductions\": " << verify_reduction_ms << ",\n"
        << "    \"prove_step\": " << prove_step_ms << ",\n"
        << "    \"codec_roundtrip\": " << codec_ms << ",\n"
        << "    \"verify_step\": " << verify_step_ms << ",\n"
        << "    \"decide\": " << decide_ms << "\n"
        << "  }\n}\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        usage(std::cout, argv[0]);
        return 0;
    }
    Options options;
    if (!parse_options(argc, argv, options)) {
        usage(std::cerr, argv[0]);
        return 1;
    }
    return benchmark(options);
}
