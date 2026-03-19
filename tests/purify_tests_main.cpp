// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <iostream>

#include "test_harness.hpp"

using purify_test::TestContext;

void run_purify_tests(TestContext& ctx);
void run_legacy_bulletproof_tests(TestContext& ctx);

int main() {
    TestContext ctx;

    run_purify_tests(ctx);
    run_legacy_bulletproof_tests(ctx);

    if (ctx.failures != 0) {
        std::cerr << ctx.failures << " test(s) failed\n";
        return 1;
    }

    std::cout << "all tests passed\n";
    return 0;
}
