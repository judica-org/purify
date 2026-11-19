// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file main.cpp
 * @brief Thin CLI entrypoint for the Purify executable.
 */

#include "purify_runtime.hpp"

/**
 * @brief Runs the Purify command-line interface.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Process exit status.
 */
int main(int argc, char** argv) {
    return purify::run_cli(argc, argv);
}
