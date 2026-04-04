// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file purify/secp_context.h
 * @brief Shared public declaration of Purify's reusable secp256k1 context handle.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Caller-owned reusable secp256k1 context handle shared across Purify C and C++ APIs. */
typedef struct purify_secp_context purify_secp_context;

/** @brief Creates one reusable secp256k1 context for the Purify bridge and public APIs. */
purify_secp_context* purify_secp_context_create(void);

/** @brief Destroys a context returned by `purify_secp_context_create`. */
void purify_secp_context_destroy(purify_secp_context* context);

#ifdef __cplusplus
}  // extern "C"
#endif
