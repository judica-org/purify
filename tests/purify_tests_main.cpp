// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <array>
#include <iostream>
#include <string_view>

#include "test_harness.hpp"

using purify_test::TestContext;

void run_purify_tests(TestContext& ctx);
void run_puresign_tests(TestContext& ctx);
void run_legacy_bulletproof_tests(TestContext& ctx);
void run_expected_tests(TestContext& ctx);

namespace {

using SuiteFn = void (*)(TestContext&);

struct SuiteSpec {
    std::string_view name;
    SuiteFn run;
};

constexpr std::array<SuiteSpec, 4> kSuites{{
    {"core", &run_purify_tests},
    {"puresign", &run_puresign_tests},
    {"legacy_bulletproof", &run_legacy_bulletproof_tests},
    {"expected", &run_expected_tests},
}};

const SuiteSpec* find_suite(std::string_view name) {
    for (const SuiteSpec& suite : kSuites) {
        if (suite.name == name) {
            return &suite;
        }
    }
    return nullptr;
}

void print_usage(std::ostream& out, std::string_view program) {
    out << "Usage: " << program << " [--list-suites] [--suite <name>]...\n";
}

void print_suites(std::ostream& out) {
    out << "Available suites:\n";
    for (const SuiteSpec& suite : kSuites) {
        out << "  " << suite.name << "\n";
    }
}

}  // namespace

int main(int argc, char** argv) {
    TestContext ctx;

    if (argc == 1) {
        for (const SuiteSpec& suite : kSuites) {
            suite.run(ctx);
        }
    } else {
        for (int i = 1; i < argc; ++i) {
            std::string_view arg = argv[i];
            if (arg == "--list-suites") {
                print_suites(std::cout);
                return 0;
            }
            if (arg == "--suite") {
                if (i + 1 >= argc) {
                    print_usage(std::cerr, argv[0]);
                    return 1;
                }
                const SuiteSpec* suite = find_suite(argv[++i]);
                if (suite == nullptr) {
                    std::cerr << "unknown suite: " << argv[i] << "\n";
                    print_suites(std::cerr);
                    return 1;
                }
                suite->run(ctx);
                continue;
            }
            print_usage(std::cerr, argv[0]);
            return 1;
        }
    }

    if (ctx.failures != 0) {
        std::cerr << ctx.failures << " test(s) failed\n";
        return 1;
    }

    std::cout << "all tests passed\n";
    return 0;
}
