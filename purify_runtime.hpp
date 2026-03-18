#pragma once

#include <cctype>
#include <fstream>
#include <iostream>
#include <optional>
#include <random>
#include <string>
#include <string_view>

#include "purify.hpp"

namespace purify {

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

inline GeneratedKey generate_key(const std::optional<UInt512>& secret_override = std::nullopt) {
    UInt512 secret = secret_override.has_value() ? *secret_override : random_below(key_space_size());
    return derive_key(secret);
}

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

inline void prove(const Bytes& message, const UInt512& secret, const std::string& output_path = "prove.assn") {
    write_file(output_path, prove_assignment(message, secret));
}

inline int run_cli(int argc, char** argv) {
    auto usage = [&]() {
        std::cout << "Usage: " << argv[0] << " gen [<seckey>]: generate a key\n";
        std::cout << "       " << argv[0] << " eval <seckey> <hexmsg>: evaluate the PRF\n";
        std::cout << "       " << argv[0] << " verifier <hexmsg> <pubkey>: output verifier circuit for a given message\n";
        std::cout << "       " << argv[0] << " prove <hexmsg> <seckey>: produce input for verifier\n";
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
        std::cout << "Unknown command\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return 1;
    }
}

}  // namespace purify
