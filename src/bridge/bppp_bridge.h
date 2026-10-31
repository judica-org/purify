// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/**
 * @file bppp_bridge.h
 * @brief C ABI bridging Purify C++ code to secp256k1-zkp BPPP functionality.
 */

#pragma once

#include <stddef.h>

#include "purify/secp_bridge.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct purify_bppp_backend_resources purify_bppp_backend_resources;

/**
 * @brief Computes the maximum serialized size of a BPPP norm proof.
 * @param n_vec_len Length of the n vector.
 * @param c_vec_len Length of the c vector.
 * @return Required output buffer size in bytes.
 */
size_t purify_bppp_required_proof_size(size_t n_vec_len, size_t c_vec_len);

/** @brief Serializes the secp256k1 base generator into compressed form. */
int purify_bppp_base_generator(purify_secp_context* context, unsigned char out33[33]);
/** @brief Serializes the alternate value generator used by Pedersen commitments. */
int purify_bppp_value_generator_h(purify_secp_context* context, unsigned char out33[33]);
/**
 * @brief Expands the generator list required by the BPPP prover and verifier.
 * @param count Number of generators requested.
 * @param out Output buffer for count compressed points.
 * @param out_len In/out serialized byte length.
 * @return Nonzero on success.
 */
int purify_bppp_create_generators(purify_secp_context* context, size_t count, unsigned char* out, size_t* out_len);

purify_bppp_backend_resources* purify_bppp_backend_resources_create(purify_secp_context* context,
                                                                    const unsigned char* generators33,
                                                                    size_t generators_count);
purify_bppp_backend_resources* purify_bppp_backend_resources_clone(
    const purify_bppp_backend_resources* resources);
void purify_bppp_backend_resources_destroy(purify_bppp_backend_resources* resources);

int purify_bppp_commit_norm_arg(purify_secp_context* context,
                                const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                                const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                                size_t l_vec_len, const unsigned char* c_vec32, size_t c_vec_len,
                                unsigned char commitment_out33[33]);
int purify_bppp_commit_norm_arg_with_resources(purify_bppp_backend_resources* resources,
                                               const unsigned char rho32[32],
                                               const unsigned char* n_vec32, size_t n_vec_len,
                                               const unsigned char* l_vec32, size_t l_vec_len,
                                               const unsigned char* c_vec32, size_t c_vec_len,
                                               unsigned char commitment_out33[33]);

int purify_bppp_commit_witness_only(purify_secp_context* context,
                                    const unsigned char* generators33, size_t generators_count,
                                    const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                                    size_t l_vec_len, unsigned char commitment_out33[33]);
int purify_bppp_commit_witness_only_with_resources(purify_bppp_backend_resources* resources,
                                                   const unsigned char* n_vec32, size_t n_vec_len,
                                                   const unsigned char* l_vec32, size_t l_vec_len,
                                                   unsigned char commitment_out33[33]);

int purify_bppp_offset_commitment(purify_secp_context* context,
                                  const unsigned char commitment33[33], const unsigned char scalar32[32],
                                  unsigned char commitment_out33[33]);

int purify_point_scale(purify_secp_context* context,
                       const unsigned char point33[33], const unsigned char scalar32[32],
                       unsigned char out33[33]);

int purify_point_add(purify_secp_context* context,
                     const unsigned char lhs33[33], const unsigned char rhs33[33],
                     unsigned char out33[33]);

/**
 * @brief Computes a Pedersen commitment to an arbitrary 32-byte scalar value.
 * @param blind32 Blinding factor in big-endian scalar form.
 * @param value32 Committed value in big-endian scalar form.
 * @param value_gen33 Compressed generator for the value term.
 * @param blind_gen33 Compressed generator for the blind term.
 * @param commitment_out33 Serialized compressed commitment output.
 * @return Nonzero on success.
 */
int purify_pedersen_commit_char(purify_secp_context* context,
                                const unsigned char blind32[32], const unsigned char value32[32],
                                const unsigned char value_gen33[33], const unsigned char blind_gen33[33],
                                unsigned char commitment_out33[33]);

/**
 * @brief Produces a standalone BPPP norm argument.
 * @param rho32 Fiat-Shamir seed.
 * @param generators33 Serialized generator list.
 * @param generators_count Number of generators in generators33.
 * @param n_vec32 Serialized n vector.
 * @param n_vec_len Length of the n vector.
 * @param l_vec32 Serialized l vector.
 * @param l_vec_len Length of the l vector.
 * @param c_vec32 Serialized c vector.
 * @param c_vec_len Length of the c vector.
 * @param commitment_out33 Commitment output used by the proof.
 * @param proof_out Output buffer for the serialized proof.
 * @param proof_len In/out proof buffer length.
 * @return Nonzero on success.
 */
int purify_bppp_prove_norm_arg(purify_secp_context* context,
                               const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                               const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                               size_t l_vec_len, const unsigned char* c_vec32, size_t c_vec_len,
                               unsigned char commitment_out33[33], unsigned char* proof_out, size_t* proof_len);
int purify_bppp_prove_norm_arg_with_resources(purify_bppp_backend_resources* resources,
                                              const unsigned char rho32[32],
                                              const unsigned char* n_vec32, size_t n_vec_len,
                                              const unsigned char* l_vec32, size_t l_vec_len,
                                              const unsigned char* c_vec32, size_t c_vec_len,
                                              unsigned char commitment_out33[33], unsigned char* proof_out,
                                              size_t* proof_len);

int purify_bppp_prove_norm_arg_to_commitment(purify_secp_context* context,
                                             const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                                             const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                                             size_t l_vec_len, const unsigned char* c_vec32, size_t c_vec_len,
                                             const unsigned char commitment33[33], unsigned char* proof_out, size_t* proof_len);
int purify_bppp_prove_norm_arg_to_commitment_with_resources(purify_bppp_backend_resources* resources,
                                                            const unsigned char rho32[32],
                                                            const unsigned char* n_vec32, size_t n_vec_len,
                                                            const unsigned char* l_vec32, size_t l_vec_len,
                                                            const unsigned char* c_vec32, size_t c_vec_len,
                                                            const unsigned char commitment33[33],
                                                            unsigned char* proof_out, size_t* proof_len);

/**
 * @brief Verifies a standalone BPPP norm argument.
 * @param rho32 Fiat-Shamir seed.
 * @param generators33 Serialized generator list.
 * @param generators_count Number of generators in generators33.
 * @param c_vec32 Serialized c vector.
 * @param c_vec_len Length of the c vector.
 * @param n_vec_len Length of the hidden n vector.
 * @param commitment33 Serialized compressed commitment point.
 * @param proof Serialized proof bytes.
 * @param proof_len Proof length in bytes.
 * @return Nonzero on success.
 */
int purify_bppp_verify_norm_arg(purify_secp_context* context,
                                const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                                const unsigned char* c_vec32, size_t c_vec_len, size_t n_vec_len,
                                const unsigned char commitment33[33], const unsigned char* proof, size_t proof_len);
int purify_bppp_verify_norm_arg_with_resources(purify_bppp_backend_resources* resources,
                                               const unsigned char rho32[32],
                                               const unsigned char* c_vec32, size_t c_vec_len, size_t n_vec_len,
                                               const unsigned char commitment33[33], const unsigned char* proof,
                                               size_t proof_len);

/**
 * Prepares a pending polynomial-commitment claim from a public norm proof.
 *
 * Success checks encodings and computes the exact transcript and short group
 * equation. It does NOT verify the proof: the returned residual must still be
 * checked against the folded generators by an accumulator's final decider.
 * gamma_count must equal log2(n_vec_len); gammas32 may be NULL only when zero.
 * The residual uses canonical compressed SEC1, or 33 zero bytes for infinity.
 */
int purify_bppp_prepare_norm_arg_claim(purify_secp_context* context,
                                     const unsigned char rho32[32],
                                     const unsigned char* generators33, size_t generators_count,
                                     const unsigned char* c_vec32, size_t c_vec_len, size_t n_vec_len,
                                     const unsigned char commitment33[33],
                                     const unsigned char* proof, size_t proof_len,
                                     unsigned char terminal_n32[32], unsigned char terminal_l32[32],
                                     unsigned char* gammas32, size_t gamma_count,
                                     unsigned char residual33[33]);

/**
 * Converts a norm generator stream to the pending claim's SEC1 basis.
 * The first n_vec_len points are unchanged. The next c_vec_len points become
 * H_i + c_i*G. Remaining points are unchanged independent padding generators.
 * The caller authenticates the deterministic stream and common coefficients.
 */
int purify_bppp_shift_norm_basis(purify_secp_context* context,
                               const unsigned char* generators33, size_t generators_count,
                               const unsigned char* c_vec32, size_t c_vec_len, size_t n_vec_len,
                               unsigned char* points_out33);

/**
 * Variable-time arithmetic for public accumulator data only.
 * Points use canonical SEC1 or all-zero33 for infinity; scalars are canonical.
 * An empty MSM returns infinity and permits NULL points/scalars.
 */
int purify_bppp_public_msm(purify_secp_context* context,
                         const unsigned char* points33, const unsigned char* scalars32,
                         size_t count, unsigned char out33[33]);

/**
 * Hashes framed public input to a finite point using the vendored generator map.
 * Callers must bind their protocol domain and complete challenge transcript.
 */
int purify_bppp_public_hash_to_point(purify_secp_context* context,
                                   const unsigned char* input, size_t input_len,
                                   unsigned char out33[33]);

typedef struct purify_bulletproof_row_view {
    size_t size;
    const size_t* indices;
    const unsigned char* scalars32;
} purify_bulletproof_row_view;

typedef struct purify_bulletproof_circuit_view {
    size_t n_gates;
    size_t n_commits;
    size_t n_bits;
    size_t n_constraints;
    const purify_bulletproof_row_view* wl;
    const purify_bulletproof_row_view* wr;
    const purify_bulletproof_row_view* wo;
    const purify_bulletproof_row_view* wv;
    const unsigned char* c32;
} purify_bulletproof_circuit_view;

typedef struct purify_bulletproof_assignment_view {
    size_t n_gates;
    size_t n_commits;
    const unsigned char* al32;
    const unsigned char* ar32;
    const unsigned char* ao32;
    const unsigned char* v32;
} purify_bulletproof_assignment_view;

typedef struct purify_bulletproof_backend_resources purify_bulletproof_backend_resources;

size_t purify_bulletproof_required_proof_size(size_t n_gates);

purify_bulletproof_backend_resources* purify_bulletproof_backend_resources_create(purify_secp_context* context,
                                                                                  size_t n_gates);
purify_bulletproof_backend_resources* purify_bulletproof_backend_resources_clone(
    const purify_bulletproof_backend_resources* resources);
void purify_bulletproof_backend_resources_destroy(purify_bulletproof_backend_resources* resources);

int purify_bulletproof_prove_circuit(purify_secp_context* context,
                                     const purify_bulletproof_circuit_view* circuit,
                                     const purify_bulletproof_assignment_view* assignment,
                                     const unsigned char* blind32,
                                     const unsigned char value_gen33[33],
                                     const unsigned char nonce32[32],
                                     const unsigned char* extra_commit,
                                     size_t extra_commit_len,
                                     unsigned char commitment_out33[33],
                                     unsigned char* proof_out,
                                     size_t* proof_len);
int purify_bulletproof_prove_circuit_with_resources(purify_bulletproof_backend_resources* resources,
                                                    const purify_bulletproof_circuit_view* circuit,
                                                    const purify_bulletproof_assignment_view* assignment,
                                                    const unsigned char* blind32,
                                                    const unsigned char value_gen33[33],
                                                    const unsigned char nonce32[32],
                                                    const unsigned char* extra_commit,
                                                    size_t extra_commit_len,
                                                    unsigned char commitment_out33[33],
                                                    unsigned char* proof_out,
                                                    size_t* proof_len);

int purify_bulletproof_prove_circuit_assume_valid(purify_secp_context* context,
                                                  const purify_bulletproof_circuit_view* circuit,
                                                  const purify_bulletproof_assignment_view* assignment,
                                                  const unsigned char* blind32,
                                                  const unsigned char value_gen33[33],
                                                  const unsigned char nonce32[32],
                                                  const unsigned char* extra_commit,
                                                  size_t extra_commit_len,
                                                  unsigned char commitment_out33[33],
                                                  unsigned char* proof_out,
                                                  size_t* proof_len);
int purify_bulletproof_prove_circuit_assume_valid_with_resources(purify_bulletproof_backend_resources* resources,
                                                                 const purify_bulletproof_circuit_view* circuit,
                                                                 const purify_bulletproof_assignment_view* assignment,
                                                                 const unsigned char* blind32,
                                                                 const unsigned char value_gen33[33],
                                                                 const unsigned char nonce32[32],
                                                                 const unsigned char* extra_commit,
                                                                 size_t extra_commit_len,
                                                                 unsigned char commitment_out33[33],
                                                                 unsigned char* proof_out,
                                                                 size_t* proof_len);

int purify_bulletproof_verify_circuit(purify_secp_context* context,
                                      const purify_bulletproof_circuit_view* circuit,
                                      const unsigned char commitment33[33],
                                      const unsigned char value_gen33[33],
                                      const unsigned char* extra_commit,
                                      size_t extra_commit_len,
                                      const unsigned char* proof,
                                      size_t proof_len);
int purify_bulletproof_verify_circuit_with_resources(purify_bulletproof_backend_resources* resources,
                                                     const purify_bulletproof_circuit_view* circuit,
                                                     const unsigned char commitment33[33],
                                                     const unsigned char value_gen33[33],
                                                     const unsigned char* extra_commit,
                                                     size_t extra_commit_len,
                                                     const unsigned char* proof,
                                                     size_t proof_len);

#ifdef __cplusplus
}
#endif
