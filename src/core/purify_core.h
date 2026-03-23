// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#pragma once

#include "purify.h"

#ifdef __cplusplus
extern "C" {
#endif

purify_error_code purify_core_sample_secret_key(unsigned char out_secret_key[PURIFY_SECRET_KEY_BYTES]);
purify_error_code purify_core_seed_secret_key(unsigned char out_secret_key[PURIFY_SECRET_KEY_BYTES],
                                              const unsigned char* seed,
                                              size_t seed_len);

#ifdef __cplusplus
}
#endif
