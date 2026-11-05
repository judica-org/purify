// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cstdint>
#include <type_traits>
#include <vector>

#include "secure_cleanup.hpp"
#include "test_harness.hpp"

namespace {

struct SecretObject {
    std::uint64_t first;
    std::uint64_t second;
};

using ObjectGuard = purify::detail::WipeOnDestruction<SecretObject>;
static_assert(!std::is_copy_constructible_v<ObjectGuard>);
static_assert(!std::is_move_constructible_v<ObjectGuard>);

static_assert(
    !purify::detail::SecureErasable<const std::array<unsigned char, 32>>);
static_assert(!purify::detail::SecureErasable<std::vector<bool>>);

void test_object_guard(purify_test::TestContext& ctx) {
    SecretObject value{0x1122334455667788ULL, 0x8877665544332211ULL};
    {
        purify::detail::WipeOnDestruction guard(value);
    }
    ctx.expect(value.first == 0 && value.second == 0,
               "object guard wipes the complete object representation");
}

void test_contiguous_range_guard(purify_test::TestContext& ctx) {
    std::vector<std::uint32_t> values{1, 2, 3, 4};
    {
        purify::detail::WipeOnDestruction guard(values);
    }
    ctx.expect(std::ranges::all_of(values,
                                   [](std::uint32_t value) {
                                       return value == 0;
                                   }),
               "range guard wipes every live contiguous element");

    std::array<unsigned char, 32> bytes{};
    bytes.fill(0xa5);
    {
        purify::detail::WipeOnDestruction guard(bytes);
    }
    ctx.expect(std::ranges::all_of(bytes,
                                   [](unsigned char value) {
                                       return value == 0;
                                   }),
               "range guard wipes fixed-size byte arrays");
}

}  // namespace

void run_secure_cleanup_tests(purify_test::TestContext& ctx) {
    test_object_guard(ctx);
    test_contiguous_range_guard(ctx);
}
