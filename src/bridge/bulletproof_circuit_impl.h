// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/*
 * Bridge to the imported Bulletproof circuit prover and verifier.
 *
 * Part of the Purify secp256k1 bridge translation unit. Include only from
 * bppp_bridge.c, after secp256k1.c and the parts listed before this one.
 */

#ifndef PURIFY_BRIDGE_BULLETPROOF_CIRCUIT_IMPL_H
#define PURIFY_BRIDGE_BULLETPROOF_CIRCUIT_IMPL_H

static void purify_free_bulletproof_circuit(secp256k1_bulletproof_circuit* circuit) {
    if (circuit == NULL) {
        return;
    }
    free(circuit->wl);
    free(circuit->wr);
    free(circuit->wo);
    free(circuit->wv);
    free(circuit->c);
    free(circuit->entries);
    memset(circuit, 0, sizeof(*circuit));
}

static void purify_free_bulletproof_assignment(secp256k1_bulletproof_circuit_assignment* assignment) {
    if (assignment == NULL) {
        return;
    }
    purify_bridge_secure_free_array(assignment->al, assignment->n_gates, sizeof(*assignment->al));
    purify_bridge_secure_free_array(assignment->ar, assignment->n_gates, sizeof(*assignment->ar));
    purify_bridge_secure_free_array(assignment->ao, assignment->n_gates, sizeof(*assignment->ao));
    purify_bridge_secure_free_array(assignment->v, assignment->n_commits, sizeof(*assignment->v));
    memset(assignment, 0, sizeof(*assignment));
}

static size_t purify_total_row_entries(const purify_bulletproof_row_view* rows, size_t count, int* ok) {
    size_t total = 0;
    size_t i;

    if (ok != NULL) {
        *ok = 0;
    }
    if (count == 0) {
        if (ok != NULL) {
            *ok = 1;
        }
        return 0;
    }
    if (rows == NULL) {
        return 0;
    }
    for (i = 0; i < count; ++i) {
        if (rows[i].size != 0 && (rows[i].indices == NULL || rows[i].scalars32 == NULL)) {
            return 0;
        }
        if (!purify_bridge_checked_add_size(total, rows[i].size, &total)) {
            return 0;
        }
    }
    if (ok != NULL) {
        *ok = 1;
    }
    return total;
}

static int purify_build_row_family(secp256k1_bulletproof_wmatrix_row* out_rows,
                                   size_t row_count,
                                   const purify_bulletproof_row_view* in_rows,
                                   size_t n_constraints,
                                   secp256k1_bulletproof_wmatrix_entry* entries,
                                   size_t* offset) {
    size_t i;
    for (i = 0; i < row_count; ++i) {
        size_t j;
        out_rows[i].size = in_rows[i].size;
        out_rows[i].entry = in_rows[i].size == 0 ? NULL : entries + *offset;
        for (j = 0; j < in_rows[i].size; ++j) {
            size_t entry_idx = *offset + j;
            if (in_rows[i].indices[j] >= n_constraints) {
                return 0;
            }
            out_rows[i].entry[j].idx = in_rows[i].indices[j];
            if (!purify_parse_fast_scalar(in_rows[i].scalars32 + 32 * j, &out_rows[i].entry[j].scal)) {
                return 0;
            }
            entries[entry_idx] = out_rows[i].entry[j];
        }
        *offset += in_rows[i].size;
    }
    return 1;
}

static void purify_bulletproof_circuit_evaluate_sum_row(secp256k1_scalar* acc,
                                                         const secp256k1_bulletproof_wmatrix_row* row,
                                                         const secp256k1_scalar* assn) {
    size_t j;
    for (j = 0; j < row->size; ++j) {
        secp256k1_scalar term;
        secp256k1_fast_scalar_mul(&term, &row->entry[j].scal, assn);
        secp256k1_scalar_add(&acc[row->entry[j].idx], &acc[row->entry[j].idx], &term);
        secp256k1_scalar_clear(&term);
    }
}

static int purify_bulletproof_circuit_evaluate(const secp256k1_bulletproof_circuit* circuit,
                                               const secp256k1_bulletproof_circuit_assignment* assignment) {
    secp256k1_scalar* acc = NULL;
    size_t i;
    int ok = 0;

    if (circuit == NULL || assignment == NULL) {
        return 0;
    }
    if (assignment->n_gates != circuit->n_gates || assignment->n_commits != circuit->n_commits) {
        return 0;
    }

    acc = circuit->n_constraints == 0 ? NULL : (secp256k1_scalar*)calloc(circuit->n_constraints, sizeof(*acc));
    if (circuit->n_constraints != 0 && acc == NULL) {
        return 0;
    }

    for (i = 0; i < assignment->n_gates; ++i) {
        secp256k1_scalar product;
        int matches;
        secp256k1_scalar_mul(&product, &assignment->al[i], &assignment->ar[i]);
        matches = secp256k1_scalar_eq(&product, &assignment->ao[i]);
        secp256k1_scalar_clear(&product);
        if (!matches) {
            goto done;
        }
    }

    for (i = 0; i < circuit->n_constraints; ++i) {
        secp256k1_scalar_clear(&acc[i]);
    }

    for (i = 0; i < circuit->n_gates; ++i) {
        purify_bulletproof_circuit_evaluate_sum_row(acc, &circuit->wl[i], &assignment->al[i]);
        purify_bulletproof_circuit_evaluate_sum_row(acc, &circuit->wr[i], &assignment->ar[i]);
        purify_bulletproof_circuit_evaluate_sum_row(acc, &circuit->wo[i], &assignment->ao[i]);
    }
    for (i = 0; i < circuit->n_commits; ++i) {
        secp256k1_scalar negated_v;
        secp256k1_scalar_negate(&negated_v, &assignment->v[i]);
        purify_bulletproof_circuit_evaluate_sum_row(acc, &circuit->wv[i], &negated_v);
        secp256k1_scalar_clear(&negated_v);
    }
    for (i = 0; i < circuit->n_constraints; ++i) {
        secp256k1_scalar constant_term;
        secp256k1_scalar one;
        int matches;
        secp256k1_scalar_set_int(&one, 1);
        secp256k1_fast_scalar_mul(&constant_term, &circuit->c[i], &one);
        matches = secp256k1_scalar_eq(&acc[i], &constant_term);
        secp256k1_scalar_clear(&constant_term);
        secp256k1_scalar_clear(&one);
        if (!matches) {
            goto done;
        }
    }
    ok = 1;

done:
    purify_bridge_secure_free_array(acc, circuit->n_constraints, sizeof(*acc));
    return ok;
}

static int purify_build_bulletproof_circuit(const purify_bulletproof_circuit_view* view,
                                            secp256k1_bulletproof_circuit* out) {
    int ok = 0;
    size_t row_entries = 0;
    size_t total_entries = 0;
    size_t offset = 0;
    size_t i;

    /* Bit/range-style circuits can have no explicit constraint rows, so the
     * constant vector is optional when n_constraints == 0.
     */
    if (view == NULL || out == NULL || (view->n_constraints != 0 && view->c32 == NULL)) {
        return 0;
    }
    if (!secp256k1_is_power_of_two(view->n_gates)) {
        return 0;
    }
    memset(out, 0, sizeof(*out));

    row_entries = purify_total_row_entries(view->wl, view->n_gates, &ok);
    if (!ok || !purify_bridge_checked_add_size(total_entries, row_entries, &total_entries)) return 0;
    row_entries = purify_total_row_entries(view->wr, view->n_gates, &ok);
    if (!ok || !purify_bridge_checked_add_size(total_entries, row_entries, &total_entries)) return 0;
    row_entries = purify_total_row_entries(view->wo, view->n_gates, &ok);
    if (!ok || !purify_bridge_checked_add_size(total_entries, row_entries, &total_entries)) return 0;
    row_entries = purify_total_row_entries(view->wv, view->n_commits, &ok);
    if (!ok || !purify_bridge_checked_add_size(total_entries, row_entries, &total_entries)) return 0;

    out->n_gates = view->n_gates;
    out->n_commits = view->n_commits;
    out->n_bits = view->n_bits;
    out->n_constraints = view->n_constraints;
    out->wl = (secp256k1_bulletproof_wmatrix_row*)purify_calloc_array(view->n_gates, sizeof(*out->wl));
    out->wr = (secp256k1_bulletproof_wmatrix_row*)purify_calloc_array(view->n_gates, sizeof(*out->wr));
    out->wo = (secp256k1_bulletproof_wmatrix_row*)purify_calloc_array(view->n_gates, sizeof(*out->wo));
    out->wv = (secp256k1_bulletproof_wmatrix_row*)purify_calloc_array(view->n_commits, sizeof(*out->wv));
    /* Mirror the legacy circuit representation: no explicit constraints means
     * no c vector allocation either.
     */
    out->c = (secp256k1_fast_scalar*)purify_malloc_array(view->n_constraints, sizeof(*out->c));
    out->entries = (secp256k1_bulletproof_wmatrix_entry*)purify_malloc_array(total_entries, sizeof(*out->entries));
    if ((view->n_gates != 0 && (out->wl == NULL || out->wr == NULL || out->wo == NULL)) ||
        (view->n_commits != 0 && out->wv == NULL) ||
        (view->n_constraints != 0 && out->c == NULL) ||
        (total_entries != 0 && out->entries == NULL)) {
        purify_free_bulletproof_circuit(out);
        return 0;
    }

    if (!purify_build_row_family(out->wl, view->n_gates, view->wl, view->n_constraints, out->entries, &offset) ||
        !purify_build_row_family(out->wr, view->n_gates, view->wr, view->n_constraints, out->entries, &offset) ||
        !purify_build_row_family(out->wo, view->n_gates, view->wo, view->n_constraints, out->entries, &offset) ||
        !purify_build_row_family(out->wv, view->n_commits, view->wv, view->n_constraints, out->entries, &offset)) {
        purify_free_bulletproof_circuit(out);
        return 0;
    }
    for (i = 0; i < view->n_constraints; ++i) {
        if (!purify_parse_fast_scalar(view->c32 + 32 * i, &out->c[i])) {
            purify_free_bulletproof_circuit(out);
            return 0;
        }
    }
    return 1;
}

static int purify_build_bulletproof_assignment(const purify_bulletproof_assignment_view* view,
                                               secp256k1_bulletproof_circuit_assignment* out) {
    if (view == NULL || out == NULL) {
        return 0;
    }
    if ((view->n_gates != 0 && (view->al32 == NULL || view->ar32 == NULL || view->ao32 == NULL)) ||
        (view->n_commits != 0 && view->v32 == NULL)) {
        return 0;
    }
    memset(out, 0, sizeof(*out));
    out->n_gates = view->n_gates;
    out->n_commits = view->n_commits;
    out->al = (secp256k1_scalar*)purify_malloc_array(view->n_gates, sizeof(*out->al));
    out->ar = (secp256k1_scalar*)purify_malloc_array(view->n_gates, sizeof(*out->ar));
    out->ao = (secp256k1_scalar*)purify_malloc_array(view->n_gates, sizeof(*out->ao));
    out->v = (secp256k1_scalar*)purify_malloc_array(view->n_commits, sizeof(*out->v));
    if ((view->n_gates != 0 && (out->al == NULL || out->ar == NULL || out->ao == NULL)) ||
        (view->n_commits != 0 && out->v == NULL)) {
        purify_free_bulletproof_assignment(out);
        return 0;
    }
    if (!purify_parse_scalar_array(view->al32, view->n_gates, out->al) ||
        !purify_parse_scalar_array(view->ar32, view->n_gates, out->ar) ||
        !purify_parse_scalar_array(view->ao32, view->n_gates, out->ao) ||
        !purify_parse_scalar_array(view->v32, view->n_commits, out->v)) {
        purify_free_bulletproof_assignment(out);
        return 0;
    }
    return 1;
}

size_t purify_bulletproof_required_proof_size(size_t n_gates) {
    size_t proof_size = 0;

    if (n_gates == 0) {
        return 0;
    }
    if (!purify_bridge_checked_add_size(321u, secp256k1_bulletproof_innerproduct_proof_length(n_gates), &proof_size)) {
        return 0;
    }
    return proof_size;
}

static int purify_bulletproof_prove_circuit_impl(const purify_bulletproof_circuit_view* circuit,
                                                 const purify_bulletproof_assignment_view* assignment,
                                                 const unsigned char* blinds32,
                                                 const unsigned char value_gen33[33],
                                                 const unsigned char nonce32[32],
                                                 const unsigned char* extra_commit,
                                                 size_t extra_commit_len,
                                                 unsigned char* commitments_out33,
                                                 unsigned char* proof_out,
                                                 size_t* proof_len,
                                                 int require_valid_assignment,
                                                 purify_secp_context* context,
                                                 purify_bulletproof_backend_resources* resources) {
    secp256k1_context* ctx = NULL;
    secp256k1_scratch_space* scratch = NULL;
    secp256k1_bulletproof_generators* gens = NULL;
    secp256k1_bulletproof_circuit bp_circuit;
    secp256k1_bulletproof_circuit_assignment bp_assignment;
    secp256k1_ge value_gen;
    secp256k1_ge* commit_points = NULL;
    secp256k1_scalar* blinds = NULL;
    size_t n_commits = 0;
    size_t required_generators = 0;
    size_t commitment_bytes = 0;
    size_t scratch_checkpoint = 0;
    size_t i;
    int ok = 0;
    int owns_resources = 0;
    int scratch_contains_secrets = 0;

    memset(&bp_circuit, 0, sizeof(bp_circuit));
    memset(&bp_assignment, 0, sizeof(bp_assignment));

    if (circuit == NULL || assignment == NULL || value_gen33 == NULL || nonce32 == NULL || proof_out == NULL || proof_len == NULL) {
        return 0;
    }
    if (extra_commit == NULL && extra_commit_len != 0) {
        return 0;
    }
    if (!purify_build_bulletproof_circuit(circuit, &bp_circuit) ||
        !purify_build_bulletproof_assignment(assignment, &bp_assignment)) {
        goto done;
    }
    if (bp_assignment.n_gates != bp_circuit.n_gates || bp_assignment.n_commits != bp_circuit.n_commits) {
        goto done;
    }
    if (require_valid_assignment && !purify_bulletproof_circuit_evaluate(&bp_circuit, &bp_assignment)) {
        goto done;
    }
    if (resources == NULL) {
        resources = purify_bulletproof_backend_resources_create(context, bp_circuit.n_gates);
        if (resources == NULL) {
            goto done;
        }
        owns_resources = 1;
    }
    if (resources->n_gates < bp_circuit.n_gates || resources->ctx == NULL || resources->scratch == NULL || resources->gens == NULL) {
        goto done;
    }
    if (!purify_bulletproof_reserve_circuit_scratch(resources, &bp_circuit)) {
        goto done;
    }
    ctx = resources->ctx;
    scratch = resources->scratch;
    gens = resources->gens;
    if (!purify_bridge_checked_mul_size(2u, bp_circuit.n_gates, &required_generators) ||
        gens->n < required_generators) {
        goto done;
    }
    if (!purify_parse_generator_as_ge(ctx, value_gen33, &value_gen)) {
        goto done;
    }

    n_commits = bp_circuit.n_commits;
    if (!purify_bridge_checked_mul_size(n_commits, 33u, &commitment_bytes)) {
        goto done;
    }
    if (n_commits != 0) {
        if (commitments_out33 == NULL) {
            goto done;
        }
        memset(commitments_out33, 0, commitment_bytes);
        commit_points = (secp256k1_ge*)purify_malloc_array(n_commits, sizeof(*commit_points));
        blinds = (secp256k1_scalar*)purify_calloc_array(n_commits, sizeof(*blinds));
        if (commit_points == NULL || blinds == NULL) {
            goto done;
        }
    }
    for (i = 0; i < n_commits; ++i) {
        secp256k1_gej commitj;
        if (blinds32 != NULL && !purify_parse_scalar(blinds32 + 32u * i, &blinds[i], 0)) {
            goto done;
        }
        secp256k1_pedersen_ecmult_scalar(&commitj, &blinds[i], &bp_assignment.v[i], &value_gen, gens->blinding_gen);
        if (secp256k1_gej_is_infinity(&commitj)) {
            goto done;
        }
        secp256k1_ge_set_gej(&commit_points[i], &commitj);
        if (!purify_serialize_point(commitments_out33 + 33u * i, &commit_points[i])) {
            goto done;
        }
    }

    scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);
    scratch_contains_secrets = 1;
    ok = secp256k1_bulletproof_relation66_prove_impl(
        &ctx->error_callback,
        scratch,
        proof_out,
        proof_len,
        &bp_assignment,
        n_commits == 0 ? NULL : commit_points,
        n_commits == 0 ? NULL : blinds,
        n_commits,
        &value_gen,
        &bp_circuit,
        gens,
        nonce32,
        extra_commit,
        extra_commit_len
    );

done:
    if (scratch_contains_secrets) {
        purify_bridge_secure_clear_scratch_tail(scratch, scratch_checkpoint);
    }
    if (blinds != NULL) {
        for (i = 0; i < n_commits; ++i) secp256k1_scalar_clear(&blinds[i]);
    }
    free(blinds);
    free(commit_points);
    purify_free_bulletproof_assignment(&bp_assignment);
    purify_free_bulletproof_circuit(&bp_circuit);
    if (owns_resources) {
        purify_bulletproof_backend_resources_destroy(resources);
    }
    return ok;
}

int purify_bulletproof_prove_circuit(purify_secp_context* context,
                                     const purify_bulletproof_circuit_view* circuit,
                                     const purify_bulletproof_assignment_view* assignment,
                                     const unsigned char* blinds32,
                                     const unsigned char value_gen33[33],
                                     const unsigned char nonce32[32],
                                     const unsigned char* extra_commit,
                                     size_t extra_commit_len,
                                     unsigned char* commitments_out33,
                                     unsigned char* proof_out,
                                     size_t* proof_len) {
    return purify_bulletproof_prove_circuit_impl(circuit, assignment, blinds32, value_gen33, nonce32,
                                                 extra_commit, extra_commit_len, commitments_out33,
                                                 proof_out, proof_len, 1, context, NULL);
}

int purify_bulletproof_prove_circuit_with_resources(purify_bulletproof_backend_resources* resources,
                                                    const purify_bulletproof_circuit_view* circuit,
                                                    const purify_bulletproof_assignment_view* assignment,
                                                    const unsigned char* blinds32,
                                                    const unsigned char value_gen33[33],
                                                    const unsigned char nonce32[32],
                                                    const unsigned char* extra_commit,
                                                    size_t extra_commit_len,
                                                    unsigned char* commitments_out33,
                                                    unsigned char* proof_out,
                                                    size_t* proof_len) {
    return purify_bulletproof_prove_circuit_impl(circuit, assignment, blinds32, value_gen33, nonce32,
                                                 extra_commit, extra_commit_len, commitments_out33,
                                                 proof_out, proof_len, 1, NULL, resources);
}

int purify_bulletproof_prove_circuit_assume_valid(purify_secp_context* context,
                                                  const purify_bulletproof_circuit_view* circuit,
                                                  const purify_bulletproof_assignment_view* assignment,
                                                  const unsigned char* blinds32,
                                                  const unsigned char value_gen33[33],
                                                  const unsigned char nonce32[32],
                                                  const unsigned char* extra_commit,
                                                  size_t extra_commit_len,
                                                  unsigned char* commitments_out33,
                                                  unsigned char* proof_out,
                                                  size_t* proof_len) {
    return purify_bulletproof_prove_circuit_impl(circuit, assignment, blinds32, value_gen33, nonce32,
                                                 extra_commit, extra_commit_len, commitments_out33,
                                                 proof_out, proof_len, 0, context, NULL);
}

int purify_bulletproof_prove_circuit_assume_valid_with_resources(purify_bulletproof_backend_resources* resources,
                                                                 const purify_bulletproof_circuit_view* circuit,
                                                                 const purify_bulletproof_assignment_view* assignment,
                                                                 const unsigned char* blinds32,
                                                                 const unsigned char value_gen33[33],
                                                                 const unsigned char nonce32[32],
                                                                 const unsigned char* extra_commit,
                                                                 size_t extra_commit_len,
                                                                 unsigned char* commitments_out33,
                                                                 unsigned char* proof_out,
                                                                 size_t* proof_len) {
    return purify_bulletproof_prove_circuit_impl(circuit, assignment, blinds32, value_gen33, nonce32,
                                                 extra_commit, extra_commit_len, commitments_out33,
                                                 proof_out, proof_len, 0, NULL, resources);
}

static int purify_bulletproof_verify_circuit_impl(purify_secp_context* context,
                                                  purify_bulletproof_backend_resources* resources,
                                                  const purify_bulletproof_circuit_view* circuit,
                                                  const unsigned char* commitments33,
                                                  const unsigned char value_gen33[33],
                                                  const unsigned char* extra_commit,
                                                  size_t extra_commit_len,
                                                  const unsigned char* proof,
                                                  size_t proof_len);

int purify_bulletproof_verify_circuit(purify_secp_context* context,
                                      const purify_bulletproof_circuit_view* circuit,
                                      const unsigned char* commitments33,
                                      const unsigned char value_gen33[33],
                                      const unsigned char* extra_commit,
                                      size_t extra_commit_len,
                                      const unsigned char* proof,
                                      size_t proof_len) {
    return purify_bulletproof_verify_circuit_impl(context, NULL, circuit, commitments33, value_gen33,
                                                  extra_commit, extra_commit_len, proof, proof_len);
}

static int purify_bulletproof_verify_circuit_impl(purify_secp_context* context,
                                                  purify_bulletproof_backend_resources* resources,
                                                  const purify_bulletproof_circuit_view* circuit,
                                                  const unsigned char* commitments33,
                                                  const unsigned char value_gen33[33],
                                                  const unsigned char* extra_commit,
                                                  size_t extra_commit_len,
                                                  const unsigned char* proof,
                                                  size_t proof_len) {
    secp256k1_context* ctx = NULL;
    secp256k1_scratch_space* scratch = NULL;
    secp256k1_bulletproof_generators* gens = NULL;
    secp256k1_bulletproof_circuit bp_circuit;
    secp256k1_ge value_gen;
    secp256k1_ge* commit_points = NULL;
    const secp256k1_ge* commit_ptr = NULL;
    const secp256k1_bulletproof_circuit* circuit_ptr = NULL;
    const unsigned char* proof_ptr = NULL;
    const unsigned char* extra_commit_ptr = NULL;
    size_t n_commits = 0;
    size_t required_generators = 0;
    size_t commitment_bytes = 0;
    size_t i;
    int ok = 0;
    int owns_resources = 0;

    memset(&bp_circuit, 0, sizeof(bp_circuit));
    if (circuit == NULL || value_gen33 == NULL || proof == NULL) {
        return 0;
    }
    if (extra_commit == NULL && extra_commit_len != 0) {
        return 0;
    }
    if (!purify_build_bulletproof_circuit(circuit, &bp_circuit)) {
        goto done;
    }
    if (resources == NULL) {
        resources = purify_bulletproof_backend_resources_create(context, bp_circuit.n_gates);
        if (resources == NULL) {
            goto done;
        }
        owns_resources = 1;
    }
    if (resources->n_gates < bp_circuit.n_gates || resources->ctx == NULL || resources->scratch == NULL || resources->gens == NULL) {
        goto done;
    }
    if (!purify_bulletproof_reserve_circuit_scratch(resources, &bp_circuit)) {
        goto done;
    }
    ctx = resources->ctx;
    scratch = resources->scratch;
    gens = resources->gens;
    if (!purify_bridge_checked_mul_size(2u, bp_circuit.n_gates, &required_generators) ||
        gens->n < required_generators) {
        goto done;
    }
    if (!purify_parse_generator_as_ge(ctx, value_gen33, &value_gen)) {
        goto done;
    }

    n_commits = bp_circuit.n_commits;
    if (!purify_bridge_checked_mul_size(n_commits, 33u, &commitment_bytes)) {
        goto done;
    }
    if (n_commits != 0) {
        if (commitments33 == NULL) {
            goto done;
        }
        commit_points = (secp256k1_ge*)purify_malloc_array(n_commits, sizeof(*commit_points));
        if (commit_points == NULL) {
            goto done;
        }
        for (i = 0; i < n_commits; ++i) {
            if (!purify_parse_point_as_ge(commitments33 + 33u * i, &commit_points[i])) {
                goto done;
            }
        }
        commit_ptr = commit_points;
    }

    circuit_ptr = &bp_circuit;
    proof_ptr = proof;
    extra_commit_ptr = extra_commit;
    ok = secp256k1_bulletproof_relation66_verify_impl(
        &ctx->error_callback,
        scratch,
        &proof_ptr,
        1,
        proof_len,
        n_commits == 0 ? NULL : &commit_ptr,
        n_commits == 0 ? NULL : &n_commits,
        &value_gen,
        &circuit_ptr,
        gens,
        &extra_commit_ptr,
        &extra_commit_len
    );

done:
    free(commit_points);
    purify_free_bulletproof_circuit(&bp_circuit);
    if (owns_resources) {
        purify_bulletproof_backend_resources_destroy(resources);
    }
    return ok;
}

int purify_bulletproof_verify_circuit_with_resources(purify_bulletproof_backend_resources* resources,
                                                     const purify_bulletproof_circuit_view* circuit,
                                                     const unsigned char* commitments33,
                                                     const unsigned char value_gen33[33],
                                                     const unsigned char* extra_commit,
                                                     size_t extra_commit_len,
                                                     const unsigned char* proof,
                                                     size_t proof_len) {
    return purify_bulletproof_verify_circuit_impl(NULL, resources, circuit, commitments33, value_gen33,
                                                  extra_commit, extra_commit_len, proof, proof_len);
}

#endif /* PURIFY_BRIDGE_BULLETPROOF_CIRCUIT_IMPL_H */
