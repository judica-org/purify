// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify_runtime.hpp
 * @brief CLI runtime helpers and command dispatch for the Purify executable.
 */

#pragma once

#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
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
inline Result<Bytes> bytes_from_hex(std::string_view hex) {
    Bytes out;
    std::string filtered;
    filtered.reserve(hex.size());
    for (char ch : hex) {
        if (std::isspace(static_cast<unsigned char>(ch)) == 0) {
            filtered.push_back(ch);
        }
    }
    if ((filtered.size() & 1U) != 0) {
        return unexpected_error(ErrorCode::InvalidHexLength, "bytes_from_hex:odd_length");
    }
    for (std::size_t i = 0; i < filtered.size(); i += 2) {
        auto decode = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') {
                return static_cast<int>(ch - '0');
            }
            if (ch >= 'a' && ch <= 'f') {
                return static_cast<int>(10 + ch - 'a');
            }
            if (ch >= 'A' && ch <= 'F') {
                return static_cast<int>(10 + ch - 'A');
            }
            return -1;
        };
        int high = decode(filtered[i]);
        int low = decode(filtered[i + 1]);
        if (high < 0 || low < 0) {
            return unexpected_error(ErrorCode::InvalidHex, "bytes_from_hex:invalid_digit");
        }
        out.push_back(static_cast<unsigned char>((high << 4) | low));
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
inline Result<std::array<unsigned char, N>> array_from_hex(std::string_view hex) {
    Result<Bytes> bytes = bytes_from_hex(hex);
    if (!bytes.has_value()) {
        return unexpected_error(bytes.error(), "array_from_hex:parse_bytes");
    }
    if (bytes->size() != N) {
        return unexpected_error(ErrorCode::InvalidFixedSize, "array_from_hex:wrong_size");
    }
    std::array<unsigned char, N> out{};
    std::copy(bytes->begin(), bytes->end(), out.begin());
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
 * @brief Writes a byte buffer to disk.
 * @param path Output file path.
 * @param bytes Bytes to write.
 */
inline Status write_file(const std::string& path, const Bytes& bytes) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return unexpected_error(ErrorCode::IoOpenFailed, "write_file:open");
    }
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file) {
        return unexpected_error(ErrorCode::IoWriteFailed, "write_file:write");
    }
    return {};
}

/**
 * @brief Writes a serialized witness assignment for a message and secret.
 * @param message Message bytes to evaluate.
 * @param secret Owned secret key.
 * @param output_path Destination path for the witness blob.
 */
inline Status prove(const Bytes& message, const SecretKey& secret, const std::string& output_path = "prove.assn") {
    Result<Bytes> assignment = prove_assignment(message, secret);
    if (!assignment.has_value()) {
        return unexpected_error(assignment.error(), "prove:prove_assignment");
    }
    return write_file(output_path, *assignment);
}

/**
 * @brief Dispatches the purify_cpp command-line interface.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Process exit status.
 */
inline int run_cli(int argc, char** argv) {
    auto print_error = [](const Error& error) {
        std::cerr << error.message() << "\n";
        return 1;
    };

    auto usage = [&]() {
        std::cout << "Usage: " << argv[0] << " gen [<seckey>]: generate a key\n";
        std::cout << "       " << argv[0] << " eval <seckey> <hexmsg>: evaluate the PRF\n";
        std::cout << "       " << argv[0] << " verifier <hexmsg> <pubkey>: output verifier circuit for a given message\n";
        std::cout << "       " << argv[0] << " prove <hexmsg> <seckey>: produce input for verifier\n";
        std::cout << "       " << argv[0] << " run-circuit <hexmsg> <seckey>: build and evaluate the native verifier circuit\n";
        std::cout << "       " << argv[0] << " commit-eval <seckey> <hexmsg> <blind32>: commit to the evaluated output\n";
    };

    if (argc < 2) {
        usage();
        return 0;
    }
    std::string command = argv[1];
    if (command == "gen") {
        std::optional<SecretKey> secret_override;
        if (argc >= 3) {
            Result<SecretKey> parsed = SecretKey::from_hex(argv[2]);
            if (!parsed.has_value()) {
                return print_error(parsed.error());
            }
            secret_override = std::move(*parsed);
        }
        Result<GeneratedKey> key =
            secret_override.has_value() ? derive_key(*secret_override) : generate_key();
        if (!key.has_value()) {
            return print_error(key.error());
        }
        std::cout << "z=" << key->secret.packed().to_hex() << " # private key\n";
        std::cout << "x=" << key->public_key.to_hex() << " # public key\n";
        return 0;
    }
    if (command == "eval") {
        if (argc != 4) {
            usage();
            return 1;
        }
        Result<SecretKey> secret = SecretKey::from_hex(argv[2]);
        if (!secret.has_value()) {
            return print_error(secret.error());
        }
        Result<Bytes> message = bytes_from_hex(argv[3]);
        if (!message.has_value()) {
            return print_error(message.error());
        }
        Result<FieldElement> value = eval(*secret, *message);
        if (!value.has_value()) {
            return print_error(value.error());
        }
        std::cout << "eval: " << value->to_hex() << "\n";
        return 0;
    }
    if (command == "verifier") {
        if (argc != 4) {
            usage();
            return 1;
        }
        Result<Bytes> message = bytes_from_hex(argv[2]);
        if (!message.has_value()) {
            return print_error(message.error());
        }
        Result<UInt512> pubkey = UInt512::try_from_hex(argv[3]);
        if (!pubkey.has_value()) {
            return print_error(pubkey.error());
        }
        Result<std::string> verifier_program = verifier(*message, *pubkey);
        if (!verifier_program.has_value()) {
            return print_error(verifier_program.error());
        }
        std::cout << *verifier_program << "\n";
        return 0;
    }
    if (command == "prove") {
        if (argc != 4) {
            usage();
            return 1;
        }
        Result<Bytes> message = bytes_from_hex(argv[2]);
        if (!message.has_value()) {
            return print_error(message.error());
        }
        Result<SecretKey> secret = SecretKey::from_hex(argv[3]);
        if (!secret.has_value()) {
            return print_error(secret.error());
        }
        Status status = prove(*message, *secret);
        if (!status.has_value()) {
            return print_error(status.error());
        }
        return 0;
    }
    if (command == "run-circuit") {
        if (argc != 4) {
            usage();
            return 1;
        }
        Result<Bytes> message = bytes_from_hex(argv[2]);
        if (!message.has_value()) {
            return print_error(message.error());
        }
        Result<SecretKey> secret = SecretKey::from_hex(argv[3]);
        if (!secret.has_value()) {
            return print_error(secret.error());
        }
        Result<BulletproofWitnessData> witness = prove_assignment_data(*message, *secret);
        if (!witness.has_value()) {
            return print_error(witness.error());
        }
        Result<NativeBulletproofCircuit> circuit = verifier_circuit(*message, witness->public_key);
        if (!circuit.has_value()) {
            return print_error(circuit.error());
        }
        bool ok = circuit->evaluate(witness->assignment);
        std::cout << "gates=" << circuit->n_gates << "\n";
        std::cout << "constraints=" << circuit->c.size() << "\n";
        std::cout << "commitments=" << circuit->n_commitments << "\n";
        std::cout << (ok ? "ok" : "fail") << "\n";
        return ok ? 0 : 1;
    }
    if (command == "commit-eval") {
        if (argc != 5) {
            usage();
            return 1;
        }
        Result<SecretKey> secret = SecretKey::from_hex(argv[2]);
        if (!secret.has_value()) {
            return print_error(secret.error());
        }
        Result<Bytes> message = bytes_from_hex(argv[3]);
        if (!message.has_value()) {
            return print_error(message.error());
        }
        Result<std::array<unsigned char, 32>> blind = array_from_hex<32>(argv[4]);
        if (!blind.has_value()) {
            return print_error(blind.error());
        }
        Result<bppp::CommittedPurifyWitness> committed = bppp::commit_output_witness(*message, *secret, *blind);
        if (!committed.has_value()) {
            return print_error(committed.error());
        }
        std::cout << "pubkey=" << committed->public_key.to_hex() << "\n";
        std::cout << "output=" << committed->output.to_hex() << "\n";
        std::cout << "commit=" << hex_from_bytes(committed->commitment) << "\n";
        return 0;
    }
    std::cout << "Unknown command\n";
    return 1;
}

}  // namespace purify
