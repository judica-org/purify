// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef PURIFY_TEST_HARNESS_HPP
#define PURIFY_TEST_HARNESS_HPP

#include <iostream>
#include <string_view>

#include "purify.hpp"

namespace purify_test {

struct TestContext {
    int failures = 0;

    void expect(bool condition, std::string_view message) {
        if (!condition) {
            ++failures;
            std::cerr << "FAIL: " << message << "\n";
        }
    }
};

template <typename T>
void expect_ok(TestContext& ctx, const purify::Result<T>& result, std::string_view message) {
    if (!result.has_value()) {
        std::cerr << "FAIL: " << message << " (" << result.error().name() << ")\n";
        ++ctx.failures;
        return;
    }
    ctx.expect(true, message);
}

inline void expect_ok(TestContext& ctx, const purify::Status& status, std::string_view message) {
    ctx.expect(status.has_value(), message);
}

template <typename T>
void expect_error(TestContext& ctx, const purify::Result<T>& result, purify::ErrorCode code, std::string_view message) {
    ctx.expect(!result.has_value() && result.error().code == code, message);
}

}  // namespace purify_test

#endif
