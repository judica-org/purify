// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

/*
 * Scalar wrappers and SHA-256 / HMAC-SHA-256 over secp256k1 internals.
 *
 * Part of the Purify secp256k1 bridge translation unit. Include only from
 * bppp_bridge.c, after secp256k1.c and the parts listed before this one.
 */

#ifndef PURIFY_BRIDGE_SCALAR_HASH_IMPL_H
#define PURIFY_BRIDGE_SCALAR_HASH_IMPL_H

static secp256k1_scalar* purify_scalar_cast(purify_scalar* scalar) {
    return (secp256k1_scalar*)scalar;
}

static const secp256k1_scalar* purify_scalar_cast_const(const purify_scalar* scalar) {
    return (const secp256k1_scalar*)scalar;
}

void purify_scalar_set_int(purify_scalar* out, unsigned int value) {
    secp256k1_scalar_set_int(purify_scalar_cast(out), value);
}

void purify_scalar_set_u64(purify_scalar* out, uint64_t value) {
    secp256k1_scalar_set_u64(purify_scalar_cast(out), value);
}

void purify_scalar_set_b32(purify_scalar* out, const unsigned char input32[32], int* overflow) {
    secp256k1_scalar_set_b32(purify_scalar_cast(out), input32, overflow);
}

void purify_scalar_get_b32(unsigned char output32[32], const purify_scalar* value) {
    secp256k1_scalar_get_b32(output32, purify_scalar_cast_const(value));
}

int purify_scalar_is_zero(const purify_scalar* value) {
    return secp256k1_scalar_is_zero(purify_scalar_cast_const(value));
}

int purify_scalar_is_one(const purify_scalar* value) {
    return secp256k1_scalar_is_one(purify_scalar_cast_const(value));
}

int purify_scalar_is_even(const purify_scalar* value) {
    return secp256k1_scalar_is_even(purify_scalar_cast_const(value));
}

int purify_scalar_eq(const purify_scalar* lhs, const purify_scalar* rhs) {
    return secp256k1_scalar_eq(purify_scalar_cast_const(lhs), purify_scalar_cast_const(rhs));
}

void purify_scalar_negate(purify_scalar* out, const purify_scalar* value) {
    secp256k1_scalar_negate(purify_scalar_cast(out), purify_scalar_cast_const(value));
}

void purify_scalar_inverse(purify_scalar* out, const purify_scalar* value) {
    secp256k1_scalar_inverse(purify_scalar_cast(out), purify_scalar_cast_const(value));
}

void purify_scalar_inverse_var(purify_scalar* out, const purify_scalar* value) {
    secp256k1_scalar_inverse_var(purify_scalar_cast(out), purify_scalar_cast_const(value));
}

int purify_scalar_add(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs) {
    return secp256k1_scalar_add(purify_scalar_cast(out), purify_scalar_cast_const(lhs), purify_scalar_cast_const(rhs));
}

void purify_scalar_mul(purify_scalar* out, const purify_scalar* lhs, const purify_scalar* rhs) {
    secp256k1_scalar_mul(purify_scalar_cast(out), purify_scalar_cast_const(lhs), purify_scalar_cast_const(rhs));
}

void purify_scalar_cmov(purify_scalar* dst, const purify_scalar* src, int flag) {
    secp256k1_scalar_cmov(purify_scalar_cast(dst), purify_scalar_cast_const(src), flag);
}

void purify_sha256(unsigned char output32[32], const unsigned char *data,
                   size_t data_len) {
  static const unsigned char zero = 0;
  secp256k1_sha256 sha256;

  if (data == NULL && data_len == 0) {
    data = &zero;
  }

  secp256k1_sha256_initialize(&sha256);
  if (data_len != 0) {
    secp256k1_sha256_write(&sha256, data, data_len);
  }
  secp256k1_sha256_finalize(&sha256, output32);
  secp256k1_sha256_clear(&sha256);
}

int purify_sha256_many(unsigned char output32[32],
                       const unsigned char *const *items,
                       const size_t *item_lens,
                       size_t items_count) {
  secp256k1_sha256 sha256;
  if (output32 == NULL) {
    return 0;
  }
  if (items_count != 0 && (items == NULL || item_lens == NULL)) {
    memset(output32, 0, 32);
    return 0;
  }
  secp256k1_sha256_initialize(&sha256);
  for (size_t i = 0; i < items_count; ++i) {
    const unsigned char *item = items[i];
    size_t item_len = item_lens[i];
    if (item == NULL) {
      if (item_len != 0) {
        secp256k1_sha256_clear(&sha256);
        memset(output32, 0, 32);
        return 0;
      }
      continue;
    }
    if (item_len != 0) {
      secp256k1_sha256_write(&sha256, item, item_len);
    }
  }
  secp256k1_sha256_finalize(&sha256, output32);
  secp256k1_sha256_clear(&sha256);
  return 1;
}

void purify_hmac_sha256(unsigned char output32[32],
                        const unsigned char* key, size_t key_len,
                        const unsigned char* data, size_t data_len) {
    static const unsigned char zero = 0;
    secp256k1_hmac_sha256 hmac;

    if (key == NULL && key_len == 0) {
        key = &zero;
    }
    if (data == NULL && data_len == 0) {
        data = &zero;
    }

    secp256k1_hmac_sha256_initialize(&hmac, key, key_len);
    if (data_len != 0) {
        secp256k1_hmac_sha256_write(&hmac, data, data_len);
    }
    secp256k1_hmac_sha256_finalize(&hmac, output32);
    secp256k1_hmac_sha256_clear(&hmac);
}

#endif /* PURIFY_BRIDGE_SCALAR_HASH_IMPL_H */
