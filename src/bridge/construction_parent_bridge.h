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
    /* Fixed by the mixed SHA-256 construction-parent qualification. */
    PURIFY_CONSTRUCTION_PARENT_PROOF_SIZE = 15076,
    PURIFY_CONSTRUCTION_PARENT_STATEMENT_SIZE = 200,
};

typedef enum purify_construction_parent_status {
    PURIFY_CONSTRUCTION_PARENT_OK = 0,
    PURIFY_CONSTRUCTION_PARENT_MALFORMED = 1,
    PURIFY_CONSTRUCTION_PARENT_PROOF_REJECTED = 2,
    PURIFY_CONSTRUCTION_PARENT_ARTIFACT_OPEN_FAILED = 3,
    PURIFY_CONSTRUCTION_PARENT_ARTIFACT_REJECTED = 4,
    PURIFY_CONSTRUCTION_PARENT_ARTIFACT_SNAPSHOT_FAILED = 5,
    /* The backend contained a panic. */
    PURIFY_CONSTRUCTION_PARENT_INTERNAL_ERROR = 6,
} purify_construction_parent_status;

/**
 * Public statement of one construction parent.
 *
 * The layout has no padding: 192 bytes of fixed-width values followed by two
 * 32-bit counts, PURIFY_CONSTRUCTION_PARENT_STATEMENT_SIZE bytes in all.
 */
typedef struct purify_construction_parent_statement {
    uint8_t construction_statement_digest[32];
    uint8_t resolved_setup_record_digest[32];
    uint8_t recovery_root[64];
    uint8_t native_basis_digest[32];
    uint8_t native_raw_generator_digest[32];
    uint32_t setup_leaf_count;
    uint32_t anchor_leaf_count;
} purify_construction_parent_statement;

typedef struct purify_construction_parent_verifier
    purify_construction_parent_verifier;

/**
 * Opens the configured verifier at an explicit UTF-8 storage path.
 *
 * The path cannot select verifier identity. `verifier_output` is cleared
 * before validation and owns one verifier only on success.
 */
purify_construction_parent_status purify_construction_parent_verifier_load(
    const uint8_t* artifact_path, size_t artifact_path_length,
    purify_construction_parent_verifier** verifier_output);

/**
 * Authenticates the pending root of one exact construction parent.
 *
 * `leaf_descriptors` holds one PURIFY_CONSTRUCTION_PARENT_DESCRIPTOR_SIZE
 * record per leaf, setup leaves first. `pending_root_output` must not alias
 * an input and is cleared before any input is read. Success still requires
 * native root parsing and the final accumulation decision.
 */
purify_construction_parent_status purify_construction_parent_authenticate_root(
    const purify_construction_parent_verifier* verifier,
    const purify_construction_parent_statement* statement,
    const uint8_t* leaf_descriptors,
    size_t leaf_descriptors_length,
    const uint8_t* proof,
    size_t proof_length,
    uint8_t pending_root_output[PURIFY_CONSTRUCTION_PARENT_ROOT_SIZE]);

void purify_construction_parent_verifier_destroy(
    purify_construction_parent_verifier* verifier);

#ifdef __cplusplus
}
#endif

#endif // PURIFY_SRC_BRIDGE_CONSTRUCTION_PARENT_BRIDGE_H
