// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

/*
 * Verification-only toy model.
 *
 * The field prime is 107. With A = 118 mod 107 = 11, B = 339 mod 107 = 18,
 * and D = 5, the two Purify toy curves have prime group orders:
 *   curve1: y^2 = x^3 + 11x + 18 over GF(107), order 109
 *   curve2: y^2 = x^3 + 61x + 3  over GF(107), order 107
 *
 * Because both curve groups are prime-order, any non-infinity point is a
 * generator in the toy model.
 */

#define PURIFY_CBMC_MODEL_FIELD_PRIME_U64 UINT64_C(107)
#define PURIFY_CBMC_MODEL_FIELD_PRIME_INIT \
    UINT64_C(107), UINT64_C(0), UINT64_C(0), UINT64_C(0)
#define PURIFY_CBMC_MODEL_CURVE_ORDER_N1_INIT \
    UINT64_C(109), UINT64_C(0), UINT64_C(0), UINT64_C(0)
#define PURIFY_CBMC_MODEL_CURVE_ORDER_N2_INIT \
    UINT64_C(107), UINT64_C(0), UINT64_C(0), UINT64_C(0)
#define PURIFY_CBMC_MODEL_CURVE_HALF_N1_INIT \
    UINT64_C(54), UINT64_C(0), UINT64_C(0), UINT64_C(0)
#define PURIFY_CBMC_MODEL_CURVE_HALF_N2_INIT \
    UINT64_C(53), UINT64_C(0), UINT64_C(0), UINT64_C(0)
#define PURIFY_CBMC_MODEL_FIELD_DI_INIT \
    UINT64_C(43), UINT64_C(0), UINT64_C(0), UINT64_C(0)

#define PURIFY_CBMC_MODEL_FIELD_NON_SQUARE_U64 UINT64_C(2)
#define PURIFY_CBMC_MODEL_CURVE1_X_U64 UINT64_C(1)
#define PURIFY_CBMC_MODEL_CURVE2_X_U64 UINT64_C(0)
