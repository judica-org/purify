// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

#include "../src/bridge/bppp_bridge.h"
#include "purify.hpp"

namespace {

using Point = std::array<unsigned char, 33>;
using Scalar = std::array<unsigned char, 32>;

struct Vector {
  std::uint64_t role;
  std::string_view scalar;
  std::string_view first;
  std::string_view second;
  std::string_view output;
};

constexpr std::string_view kBasisDigest =
    "4047eedb842ea65b60ce2a08b26117a40a684a431a6040dfabe5b271d65e919f";

constexpr std::array kVectors{
    Vector{
        1, "0000000000000000000000000000000000000000000000000000000000000001",
        "022a8a4e320657bd5a0fbd99af8e02414e5f80c2b4ac73139c9cd54cffac226308",
        "02f125794870a264768934fb8dabde39dda4a724169661864547b1ac373774a536",
        "023ae0a509fdca1e77792fc72508d50e37683fd779d118a8e8ba2454cac9aa70a0"},
    Vector{
        1, "0000000000000000000000000000000000000000000000000000000000000002",
        "022a8a4e320657bd5a0fbd99af8e02414e5f80c2b4ac73139c9cd54cffac226308",
        "02f125794870a264768934fb8dabde39dda4a724169661864547b1ac373774a536",
        "025ed00251115024934607de96b8cdb1aa5282c241d31fdd6682263e2e386e3dfc"},
    Vector{
        2, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "029ad5b3d22eb2729e9edf41193b663dce3c669c9fd5c158d9088d2c5f1e308dfd",
        "0380ce1caab2dc56cf9b1e53e7968aac27761e9844fdf10272e92ee7a3b7660d71",
        "0216ed252f1d01e2407a296193c53899cadfe04a76be8a6126d948031a5950a82e"},
};

unsigned char nibble(char digit) {
  if (digit >= '0' && digit <= '9') {
    return static_cast<unsigned char>(digit - '0');
  }
  if (digit >= 'a' && digit <= 'f') {
    return static_cast<unsigned char>(digit - 'a' + 10);
  }
  return 0xff;
}

template <std::size_t Size>
std::array<unsigned char, Size> hex(std::string_view encoded) {
  std::array<unsigned char, Size> out{};
  if (encoded.size() != 2 * Size) {
    return {};
  }
  for (std::size_t i = 0; i < Size; ++i) {
    const auto high = nibble(encoded[2 * i]);
    const auto low = nibble(encoded[2 * i + 1]);
    if (high > 0x0f || low > 0x0f) {
      return {};
    }
    out[i] = static_cast<unsigned char>((high << 4) | low);
  }
  return out;
}

void append_role(std::vector<unsigned char> &message, std::uint64_t role) {
  for (unsigned int i = 0; i < 8; ++i) {
    message.push_back(static_cast<unsigned char>((role >> (8 * i)) & 0xffU));
  }
}

bool check_vector(const Vector &vector, purify_secp_context *secp) {
  const auto digest = hex<32>(kBasisDigest);
  std::array<Point, 2> points{};
  const purify::TaggedHash pair_hash("Purify/BPPP/OpeningGeneratorPairV2");
  for (std::size_t index = 0; index < points.size(); ++index) {
    std::vector<unsigned char> message(digest.begin(), digest.end());
    append_role(message, vector.role);
    message.push_back(static_cast<unsigned char>(index));
    const auto seed = pair_hash.digest(message);
    if (purify_bppp_public_hash_to_point(secp, seed.data(), seed.size(),
                                         points[index].data()) == 0) {
      return false;
    }
  }
  if (points[0] != hex<33>(vector.first) ||
      points[1] != hex<33>(vector.second)) {
    return false;
  }

  const Scalar one = hex<32>(
      "0000000000000000000000000000000000000000000000000000000000000001");
  const std::array scalars{one, hex<32>(vector.scalar)};
  Point output{};
  if (purify_bppp_public_msm(
          secp, reinterpret_cast<const unsigned char *>(points.data()),
          reinterpret_cast<const unsigned char *>(scalars.data()),
          points.size(), output.data()) == 0) {
    return false;
  }
  return output == hex<33>(vector.output);
}

} // namespace

int main() {
  auto secp = purify::make_secp_context();
  if (!secp) {
    std::cerr << "FAIL: opening-base vector context creates\n";
    return 1;
  }
  for (const auto &vector : kVectors) {
    if (!check_vector(vector, secp.get())) {
      std::cerr << "FAIL: native opening-base vector mismatch\n";
      return 1;
    }
  }
  return 0;
}
