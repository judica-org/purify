#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t purify_bppp_required_proof_size(size_t n_vec_len, size_t c_vec_len);

int purify_bppp_base_generator(unsigned char out33[33]);
int purify_bppp_value_generator_h(unsigned char out33[33]);
int purify_bppp_create_generators(size_t count, unsigned char* out, size_t* out_len);

int purify_pedersen_commit_char(const unsigned char blind32[32], const unsigned char value32[32],
                                const unsigned char value_gen33[33], const unsigned char blind_gen33[33],
                                unsigned char commitment_out33[33]);

int purify_bppp_prove_norm_arg(const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                               const unsigned char* n_vec32, size_t n_vec_len, const unsigned char* l_vec32,
                               size_t l_vec_len, const unsigned char* c_vec32, size_t c_vec_len,
                               unsigned char commitment_out33[33], unsigned char* proof_out, size_t* proof_len);

int purify_bppp_verify_norm_arg(const unsigned char rho32[32], const unsigned char* generators33, size_t generators_count,
                                const unsigned char* c_vec32, size_t c_vec_len, size_t n_vec_len,
                                const unsigned char commitment33[33], const unsigned char* proof, size_t proof_len);

#ifdef __cplusplus
}
#endif
