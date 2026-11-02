// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * Private ABI for the selected recursive construction-parent verifier.
 *
 * This header is deliberately not installed. A successful proof call returns
 * a pending native accumulation root, never an accepted receipt. The C++
 * wrapper must parse that root against its fixed basis and call decide().
 */

#ifndef PURIFY_SRC_BRIDGE_CONSTRUCTION_PARENT_BRIDGE_H
#define PURIFY_SRC_BRIDGE_CONSTRUCTION_PARENT_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PURIFY_CONSTRUCTION_PARENT_ROOT_SIZE = 545,
    PURIFY_CONSTRUCTION_PARENT_DESCRIPTOR_SIZE = 130,
};

typedef enum purify_construction_parent_status {
    PURIFY_CONSTRUCTION_PARENT_OK = 0,
    PURIFY_CONSTRUCTION_PARENT_MALFORMED = 1,
    PURIFY_CONSTRUCTION_PARENT_PROOF_REJECTED = 2,
    PURIFY_CONSTRUCTION_PARENT_BUFFER_TOO_SMALL = 3,
    PURIFY_CONSTRUCTION_PARENT_ARTIFACT_IO = 4,
    PURIFY_CONSTRUCTION_PARENT_ARTIFACT_REJECTED = 5,
    PURIFY_CONSTRUCTION_PARENT_INTERNAL_ERROR = 6,
} purify_construction_parent_status;

typedef struct purify_construction_parent_verifier
    purify_construction_parent_verifier;

/**
 * Opens the sole qualified verifier at an explicit UTF-8 storage path.
 *
 * The path cannot select verifier identity. `verifier_output` is cleared
 * before validation and owns one verifier only on success.
 */
purify_construction_parent_status purify_construction_parent_verifier_load(
    const uint8_t* artifact_path, size_t artifact_path_length,
    purify_construction_parent_verifier** verifier_output);

/**
 * Authenticates one exact construction parent and returns its pending root.
 *
 * `pending_root_output` must not alias an input. It is cleared before every
 * input and proof check. Success still requires native root parsing and the
 * final accumulation decision.
 */
purify_construction_parent_status purify_construction_parent_verify(
    const purify_construction_parent_verifier* verifier,
    const uint8_t construction_statement_digest[32],
    const uint8_t resolved_setup_record_digest[32],
    const uint8_t* canonical_seed_root,
    size_t canonical_seed_root_length,
    const uint8_t native_basis_digest[32],
    const uint8_t native_raw_generator_digest[32],
    uint32_t anchor_count,
    const uint8_t* anchor_descriptors,
    size_t anchor_descriptors_length,
    const uint8_t* proof,
    size_t proof_length,
    uint8_t* pending_root_output,
    size_t pending_root_capacity);

void purify_construction_parent_verifier_destroy(
    purify_construction_parent_verifier* verifier);

#ifdef __cplusplus
}
#endif

#endif // PURIFY_SRC_BRIDGE_CONSTRUCTION_PARENT_BRIDGE_H
