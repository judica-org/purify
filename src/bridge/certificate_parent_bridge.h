// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * Private ABI for the selected recursive certificate-parent verifier.
 *
 * This header is deliberately not installed. A successful proof call returns
 * a pending native accumulation root, never an accepted certificate. The C++
 * wrapper must parse that root against its fixed basis and call decide().
 */

#ifndef PURIFY_SRC_BRIDGE_CERTIFICATE_PARENT_BRIDGE_H
#define PURIFY_SRC_BRIDGE_CERTIFICATE_PARENT_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PURIFY_CERTIFICATE_PARENT_ROOT_SIZE = 481,
    /* Fixed by the certificate-parent production qualification. */
    PURIFY_CERTIFICATE_PARENT_PROOF_SIZE = 15268,
};

typedef enum purify_certificate_parent_status {
    PURIFY_CERTIFICATE_PARENT_OK = 0,
    PURIFY_CERTIFICATE_PARENT_MALFORMED = 1,
    PURIFY_CERTIFICATE_PARENT_PROOF_REJECTED = 2,
    PURIFY_CERTIFICATE_PARENT_BUFFER_TOO_SMALL = 3,
    PURIFY_CERTIFICATE_PARENT_ARTIFACT_OPEN_FAILED = 4,
    PURIFY_CERTIFICATE_PARENT_ARTIFACT_REJECTED = 5,
    PURIFY_CERTIFICATE_PARENT_INTERNAL_ERROR = 6,
    PURIFY_CERTIFICATE_PARENT_ARTIFACT_SNAPSHOT_FAILED = 7,
} purify_certificate_parent_status;

typedef struct purify_certificate_parent_verifier
    purify_certificate_parent_verifier;

/**
 * Opens the configured verifier at an explicit UTF-8 storage path.
 *
 * The path cannot select verifier identity. `verifier_output` is cleared
 * before validation and owns one verifier only on success.
 */
purify_certificate_parent_status purify_certificate_parent_verifier_load(
    const uint8_t* artifact_path, size_t artifact_path_length,
    purify_certificate_parent_verifier** verifier_output);

/**
 * Authenticates one exact certificate parent and returns its pending root.
 *
 * `pending_root_output` must not alias an input. It is cleared before every
 * input and proof check. Success still requires native root parsing and the
 * final accumulation decision.
 */
purify_certificate_parent_status purify_certificate_parent_verify(
    const purify_certificate_parent_verifier* verifier,
    const uint8_t certificate_context_digest[32],
    uint64_t total_responses,
    uint64_t total_steps,
    const uint8_t final_manifest[32],
    const uint8_t* proof,
    size_t proof_length,
    uint8_t* pending_root_output,
    size_t pending_root_capacity);

void purify_certificate_parent_verifier_destroy(
    purify_certificate_parent_verifier* verifier);

#ifdef __cplusplus
}
#endif

#endif // PURIFY_SRC_BRIDGE_CERTIFICATE_PARENT_BRIDGE_H
