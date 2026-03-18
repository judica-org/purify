// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_runtime.hpp
 * @brief Runtime helpers and CLI wiring for the Purify executable.
 */

#pragma once

#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>

#include "purify_bppp.hpp"
#include "purify.hpp"

namespace purify {

/**
 * @brief Parses a hexadecimal string into raw bytes.
 * @param hex Input hex string; ASCII whitespace is ignored.
 * @return Parsed bytes.
 */
inline Bytes bytes_from_hex(std::string_view hex) {
    Bytes out;
    std::string filtered;
    filtered.reserve(hex.size());
    for (char ch : hex) {
        if (std::isspace(static_cast<unsigned char>(ch)) == 0) {
            filtered.push_back(ch);
        }
    }
    if ((filtered.size() & 1U) != 0) {
        throw std::runtime_error("Hex input must have even length");
    }
    for (std::size_t i = 0; i < filtered.size(); i += 2) {
        auto decode = [](char ch) -> unsigned {
            if (ch >= '0' && ch <= '9') {
                return static_cast<unsigned>(ch - '0');
            }
            if (ch >= 'a' && ch <= 'f') {
                return static_cast<unsigned>(10 + ch - 'a');
            }
            if (ch >= 'A' && ch <= 'F') {
                return static_cast<unsigned>(10 + ch - 'A');
            }
            throw std::runtime_error("Invalid hex input");
        };
        out.push_back(static_cast<unsigned char>((decode(filtered[i]) << 4) | decode(filtered[i + 1])));
    }
    return out;
}

/**
 * @brief Parses a fixed-size hexadecimal string into an array.
 * @tparam N Required byte length.
 * @param hex Input hex string.
 * @return Parsed byte array.
 */
template <std::size_t N>
inline std::array<unsigned char, N> array_from_hex(std::string_view hex) {
    Bytes bytes = bytes_from_hex(hex);
    if (bytes.size() != N) {
        throw std::runtime_error(std::format("Expected {} bytes of hex input", N));
    }
    std::array<unsigned char, N> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

/**
 * @brief Encodes a byte container as lowercase hexadecimal.
 * @tparam ByteContainer Container with byte-like values.
 * @param bytes Input bytes.
 * @return Hexadecimal string.
 */
template <typename ByteContainer>
inline std::string hex_from_bytes(const ByteContainer& bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        out << std::setw(2) << static_cast<unsigned>(byte);
    }
    return out.str();
}

/**
 * @brief Samples a uniformly random integer below a range.
 * @param range Exclusive upper bound.
 * @return Random integer in the interval [0, range).
 */
inline UInt512 random_below(const UInt512& range) {
    std::random_device rng;
    while (true) {
        std::array<unsigned char, 64> bytes{};
        for (unsigned char& byte : bytes) {
            byte = static_cast<unsigned char>(rng());
        }
        UInt512 candidate = UInt512::from_bytes_be(bytes.data(), bytes.size());
        if (candidate.compare(range) < 0) {
            return candidate;
        }
    }
}

/**
 * @brief Generates a Purify keypair or derives one from an explicit secret.
 * @param secret_override Optional packed secret to reuse instead of sampling.
 * @return Generated keypair bundle.
 */
inline GeneratedKey generate_key(const std::optional<UInt512>& secret_override = std::nullopt) {
    UInt512 secret = secret_override.has_value() ? *secret_override : random_below(key_space_size());
    return derive_key(secret);
}

/**
 * @brief Writes a byte buffer to disk.
 * @param path Output file path.
 * @param bytes Bytes to write.
 */
inline void write_file(const std::string& path, const Bytes& bytes) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Unable to open output file");
    }
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file) {
        throw std::runtime_error("Unable to write output file");
    }
}

/**
 * @brief Writes a serialized witness assignment for a message and secret.
 * @param message Message bytes to evaluate.
 * @param secret Packed secret scalar pair.
 * @param output_path Destination path for the witness blob.
 */
inline void prove(const Bytes& message, const UInt512& secret, const std::string& output_path = "prove.assn") {
    write_file(output_path, prove_assignment(message, secret));
}

/**
 * @brief Dispatches the purify_cpp command-line interface.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Process exit status.
 */
inline int run_cli(int argc, char** argv) {
    auto usage = [&]() {
        std::cout << "Usage: " << argv[0] << " gen [<seckey>]: generate a key\n";
        std::cout << "       " << argv[0] << " eval <seckey> <hexmsg>: evaluate the PRF\n";
        std::cout << "       " << argv[0] << " verifier <hexmsg> <pubkey>: output verifier circuit for a given message\n";
        std::cout << "       " << argv[0] << " prove <hexmsg> <seckey>: produce input for verifier\n";
        std::cout << "       " << argv[0] << " run-circuit <hexmsg> <seckey>: build and evaluate the native verifier circuit\n";
        std::cout << "       " << argv[0] << " commit-eval <seckey> <hexmsg> <blind32>: commit to the evaluated output\n";
    };

    try {
        if (argc < 2) {
            usage();
            return 0;
        }
        std::string command = argv[1];
        if (command == "gen") {
            std::optional<UInt512> secret_override;
            if (argc >= 3) {
                secret_override = UInt512::from_hex(argv[2]);
            }
            GeneratedKey key = generate_key(secret_override);
            std::cout << "z=" << key.secret.to_hex() << " # private key\n";
            std::cout << "x=" << key.public_key.to_hex() << " # public key\n";
            return 0;
        }
        if (command == "eval") {
            if (argc != 4) {
                usage();
                return 1;
            }
            UInt512 secret = UInt512::from_hex(argv[2]);
            Bytes message = bytes_from_hex(argv[3]);
            std::cout << "eval: " << eval(secret, message).to_hex() << "\n";
            return 0;
        }
        if (command == "verifier") {
            if (argc != 4) {
                usage();
                return 1;
            }
            Bytes message = bytes_from_hex(argv[2]);
            UInt512 pubkey = UInt512::from_hex(argv[3]);
            std::cout << verifier(message, pubkey) << "\n";
            return 0;
        }
        if (command == "prove") {
            if (argc != 4) {
                usage();
                return 1;
            }
            Bytes message = bytes_from_hex(argv[2]);
            UInt512 secret = UInt512::from_hex(argv[3]);
            prove(message, secret);
            return 0;
        }
        if (command == "run-circuit") {
            if (argc != 4) {
                usage();
                return 1;
            }
            Bytes message = bytes_from_hex(argv[2]);
            UInt512 secret = UInt512::from_hex(argv[3]);
            BulletproofWitnessData witness = prove_assignment_data(message, secret);
            NativeBulletproofCircuit circuit = verifier_circuit(message, witness.public_key);
            bool ok = circuit.evaluate(witness.assignment);
            std::cout << "gates=" << circuit.n_gates << "\n";
            std::cout << "constraints=" << circuit.c.size() << "\n";
            std::cout << "commitments=" << circuit.n_commitments << "\n";
            std::cout << (ok ? "ok" : "fail") << "\n";
            return ok ? 0 : 1;
        }
        if (command == "commit-eval") {
            if (argc != 5) {
                usage();
                return 1;
            }
            UInt512 secret = UInt512::from_hex(argv[2]);
            Bytes message = bytes_from_hex(argv[3]);
            auto blind = array_from_hex<32>(argv[4]);
            auto committed = bppp::commit_output_witness(message, secret, blind);
            std::cout << "pubkey=" << committed.public_key.to_hex() << "\n";
            std::cout << "output=" << committed.output.to_hex() << "\n";
            std::cout << "commit=" << hex_from_bytes(committed.commitment) << "\n";
            return 0;
        }
        std::cout << "Unknown command\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return 1;
    }
}

}  // namespace purify
