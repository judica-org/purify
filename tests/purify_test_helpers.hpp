// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef PURIFY_TEST_HELPERS_HPP
#define PURIFY_TEST_HELPERS_HPP

#include "test_harness.hpp"

namespace purify_test {

inline purify::Bytes sample_message() {
    return purify::Bytes{0x01, 0x23, 0x45, 0x67};
}

inline purify::Result<purify::UInt512> sample_secret() {
    return purify::UInt512::try_from_hex(
        "11427c7268288dddf0cd24af3d30524fd817a91e103e7e02eb28b78db81cb350"
        "b3d2562f45fa8ecd711d1becc02fa348cf2187429228e7aac6644a3da2824e93");
}

}  // namespace purify_test

#endif
