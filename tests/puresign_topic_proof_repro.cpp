// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cstdlib>
#include <iostream>
#include <string_view>

#include "purify.hpp"
#include "purify_test_helpers.hpp"

namespace {

constexpr std::string_view kTopic = "session-pp-downstream-repro";
constexpr std::size_t kDefaultIterations = 256;

std::size_t parse_iterations(int argc, char** argv) {
    if (argc <= 1) {
        return kDefaultIterations;
    }
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(argv[1], &end, 10);
    if (end == argv[1] || end == nullptr || *end != '\0' || parsed == 0) {
        std::cerr << "usage: " << argv[0] << " [iterations]\n";
        std::exit(2);
    }
    return static_cast<std::size_t>(parsed);
}

}  // namespace

int main(int argc, char** argv) {
    const std::size_t iterations = parse_iterations(argc, argv);

    purify::Result<purify::SecretKey> secret = purify_test::sample_secret();
    if (!secret.has_value()) {
        std::cerr << "sample_secret failed: " << secret.error().name() << "\n";
        return 1;
    }

    purify::SecpContextPtr context = purify::make_secp_context();
    if (context == nullptr) {
        std::cerr << "secp context creation failed\n";
        return 1;
    }

    purify::Bytes topic = purify::bytes_from_ascii(kTopic);
    purify::Result<purify::puresign_plusplus::KeyPair> key_pair =
        purify::puresign_plusplus::KeyPair::from_secret(*secret, context.get());
    if (!key_pair.has_value()) {
        std::cerr << "KeyPair::from_secret failed: " << key_pair.error().name() << "\n";
        return 1;
    }

    const purify::puresign_plusplus::PublicKey& public_key = key_pair->public_key();
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        std::cout << "prepare_topic_nonce_with_proof iteration=" << (iteration + 1) << "\n";
        purify::Result<purify::puresign_plusplus::PreparedNonceWithProof> prepared =
            key_pair->prepare_topic_nonce_with_proof(topic, context.get());
        if (!prepared.has_value()) {
            std::cerr << "prepare_topic_nonce_with_proof failed on iteration "
                      << (iteration + 1) << ": " << prepared.error().name() << "\n";
            return 1;
        }

        std::cout << "verify_topic_nonce_proof iteration=" << (iteration + 1) << "\n";
        purify::Result<bool> verified =
            public_key.verify_topic_nonce_proof(topic, prepared->proof(), context.get());
        if (!verified.has_value()) {
            std::cerr << "verify_topic_nonce_proof failed on iteration "
                      << (iteration + 1) << ": " << verified.error().name() << "\n";
            return 1;
        }
        if (!*verified) {
            std::cerr << "verify_topic_nonce_proof rejected proof on iteration "
                      << (iteration + 1) << "\n";
            return 1;
        }
    }

    std::cout << "repro completed " << iterations << " iteration(s)\n";
    return 0;
}
