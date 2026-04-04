// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stdexcept>
#include <type_traits>
#include <utility>

#if defined(__has_include)
#if __has_include(<expected>)
#include <expected>
#endif
#endif

#include "test_harness.hpp"
#include "purify/expected.hpp"

namespace {

struct ThrowOnMove {
    static bool g_throw_on_move;

    explicit ThrowOnMove(int v) : value(v) {}

    ThrowOnMove(const ThrowOnMove&) = delete;
    ThrowOnMove& operator=(const ThrowOnMove&) = delete;

    ThrowOnMove(ThrowOnMove&& other)
    {
        if (g_throw_on_move) {
            throw std::runtime_error("ThrowOnMove move");
        }
        value = other.value;
        other.value = -1;
    }

    ThrowOnMove& operator=(ThrowOnMove&& other)
    {
        if (g_throw_on_move) {
            throw std::runtime_error("ThrowOnMove move assign");
        }
        value = other.value;
        other.value = -1;
        return *this;
    }

    int value{0};
};

bool ThrowOnMove::g_throw_on_move = false;

void test_expected_assignment_preserves_error_state(purify_test::TestContext& ctx)
{
    purify::Expected<ThrowOnMove, int> target(purify::Unexpected<int>(7));

    ThrowOnMove::g_throw_on_move = false;
    purify::Expected<ThrowOnMove, int> source(ThrowOnMove{9});

    bool threw = false;
    ThrowOnMove::g_throw_on_move = true;
    try {
        target = std::move(source);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    ThrowOnMove::g_throw_on_move = false;

    ctx.expect(threw, "Expected move assignment surfaces the throwing value move");
    ctx.expect(!target.has_value(), "Expected remains on the error alternative after a failed cross-alternative move");
    if (!target.has_value()) {
        ctx.expect(target.error() == 7, "Expected preserves the prior error payload after a failed cross-alternative move");
    }
}

void test_expected_stays_on_purify_abi(purify_test::TestContext& ctx)
{
#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
    ctx.expect(!std::is_same_v<purify::Expected<int, int>, std::expected<int, int>>,
               "Public Expected remains Purify's fallback type even when std::expected is available");
#else
    ctx.expect(true, "std::expected is unavailable; Public Expected uses Purify's fallback type");
#endif
}

} // namespace

void run_expected_tests(purify_test::TestContext& ctx)
{
    test_expected_stays_on_purify_abi(ctx);
    test_expected_assignment_preserves_error_state(ctx);
}
