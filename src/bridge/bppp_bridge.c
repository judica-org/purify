// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_bridge.c
 * @brief C bridge that binds Purify's lightweight ABI to secp256k1-zkp internals and BPPP helpers.
 */

#define SECP256K1_BUILD
#define ENABLE_MODULE_GENERATOR 1
#define ENABLE_MODULE_BPPP 1
#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_SCHNORRSIG 1

#include "purify.h"
#include "bppp_bridge.h"
#include "purify/secp_bridge.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if defined(PURIFY_VALGRIND_TESTING)
#include <valgrind/memcheck.h>
/* Proof points and terminal scalars are public from these protocol lines on. */
#define PURIFY_BRIDGE_DECLASSIFY(data, size) \
    VALGRIND_MAKE_MEM_DEFINED((data), (size))
#else
#define PURIFY_BRIDGE_DECLASSIFY(data, size) ((void)(data), (void)(size))
#endif

#include "third_party/secp256k1-zkp/include/secp256k1_extrakeys.h"
#include "third_party/secp256k1-zkp/include/secp256k1_schnorrsig.h"
#include "third_party/secp256k1-zkp/src/secp256k1.c"
#include "third_party/secp256k1-zkp/src/precomputed_ecmult.c"
#include "third_party/secp256k1-zkp/src/precomputed_ecmult_gen.c"
#include "src/legacy_bulletproof/circuit_impl.h"

#undef secp256k1_scratch_alloc

#include "src/bridge/resources_impl.h"
#include "src/bridge/scalar_hash_impl.h"
#include "src/bridge/bip340_impl.h"
#include "src/bridge/parse_impl.h"
#include "src/bridge/bulletproof_circuit_impl.h"
#include "src/bridge/bppp_secret_prover_impl.h"
#include "src/bridge/bppp_commit_impl.h"
#include "src/bridge/bppp_norm_arg_impl.h"
#include "src/bridge/bppp_public_impl.h"
