// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <stdio.h>
#include <string.h>

#include "../src/purify_field.h"
#include "purify.h"

static int failures = 0;

static void expect(int condition, const char* message) {
    if (!condition) {
        ++failures;
        fprintf(stderr, "FAIL: %s\n", message);
    }
}

static int all_zero(const unsigned char* data, size_t len) {
    size_t i = 0;
    for (i = 0; i < len; ++i) {
        if (data[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static void to_hex(char* out, const unsigned char* data, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    size_t i = 0;
    for (i = 0; i < len; ++i) {
        out[2 * i] = kHex[data[i] >> 4];
        out[2 * i + 1] = kHex[data[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

int main(void) {
    unsigned char random_bytes[32];
    purify_generated_key first = {{0}, {0}};
    purify_generated_key second = {{0}, {0}};
    purify_bip340_key bip340 = {{0}, {0}};
    unsigned char derived_public_key[PURIFY_PUBLIC_KEY_BYTES];
    unsigned char eval_a[PURIFY_FIELD_ELEMENT_BYTES];
    unsigned char eval_b[PURIFY_FIELD_ELEMENT_BYTES];
    char hex[2 * PURIFY_PUBLIC_KEY_BYTES + 1];
    purify_fe zero = {{{0}}};
    purify_fe zero_sqrt = {{{0}}};
    const unsigned char seed[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const unsigned char short_seed[8] = {0};
    const unsigned char message[] = "c api smoke";

    expect(purify_fill_secure_random(random_bytes, sizeof(random_bytes)) == PURIFY_ERROR_OK,
           "purify_fill_secure_random succeeds");
    expect(!all_zero(random_bytes, sizeof(random_bytes)),
           "purify_fill_secure_random produces non-zero output for one sample");
    expect(purify_fill_secure_random(NULL, 1) == PURIFY_ERROR_MISSING_VALUE,
           "purify_fill_secure_random rejects a null non-empty buffer");

    expect(purify_generate_key(NULL) == PURIFY_ERROR_MISSING_VALUE,
           "purify_generate_key rejects a null output pointer");
    expect(purify_generate_key_from_seed(&first, seed, sizeof(seed)) == PURIFY_ERROR_OK,
           "purify_generate_key_from_seed succeeds");
    expect(purify_generate_key_from_seed(&second, seed, sizeof(seed)) == PURIFY_ERROR_OK,
           "purify_generate_key_from_seed succeeds twice");
    expect(memcmp(&first, &second, sizeof(first)) == 0,
           "purify_generate_key_from_seed is deterministic");
    to_hex(hex, first.secret_key, sizeof(first.secret_key));
    expect(strcmp(hex,
                  "244033992dfe583985332da27b7cdfddaf05df5c5c3bc8db763af6dd75f07ee28737e8d9a8d5592a3f10944c89f6ae82e53f76ae9dc17c77c22cf7a352cdb59c")
               == 0,
           "purify_generate_key_from_seed preserves the legacy packed-secret test vector");
    to_hex(hex, first.public_key, sizeof(first.public_key));
    expect(strcmp(hex,
                  "79b928249e7889d70fe96c9b748d9d3863f5ac48e66340c5c8962aba2f12bd0985bb7f26a806cf0bfc8f149984117903917723d62bd4059475f6287c05622397")
               == 0,
           "purify_generate_key_from_seed preserves the legacy packed-public-key test vector");
    expect(purify_generate_key_from_seed(&second, short_seed, sizeof(short_seed)) == PURIFY_ERROR_RANGE_VIOLATION,
           "purify_generate_key_from_seed rejects short seed material");
    {
        purify_generated_key aliased_seed_key = {{0}, {0}};
        memcpy(aliased_seed_key.secret_key, seed, sizeof(seed));
        expect(purify_generate_key_from_seed(&aliased_seed_key, aliased_seed_key.secret_key, sizeof(seed)) == PURIFY_ERROR_OK,
               "purify_generate_key_from_seed accepts seed storage inside the output bundle");
        expect(memcmp(&aliased_seed_key, &first, sizeof(first)) == 0,
               "purify_generate_key_from_seed aliasing matches the non-aliased result");
    }

    expect(purify_validate_secret_key(first.secret_key) == PURIFY_ERROR_OK,
           "purify_validate_secret_key accepts generated secrets");
    expect(purify_validate_public_key(first.public_key) == PURIFY_ERROR_OK,
           "purify_validate_public_key accepts generated public keys");
    expect(purify_validate_secret_key(NULL) == PURIFY_ERROR_MISSING_VALUE,
           "purify_validate_secret_key rejects null input");

    memset(derived_public_key, 0, sizeof(derived_public_key));
    expect(purify_derive_public_key(derived_public_key, first.secret_key) == PURIFY_ERROR_OK,
           "purify_derive_public_key succeeds");
    expect(memcmp(derived_public_key, first.public_key, sizeof(derived_public_key)) == 0,
           "purify_derive_public_key matches seeded key generation");
    {
        unsigned char aliased_public_key[PURIFY_PUBLIC_KEY_BYTES];
        memcpy(aliased_public_key, first.secret_key, sizeof(aliased_public_key));
        expect(purify_derive_public_key(aliased_public_key, aliased_public_key) == PURIFY_ERROR_OK,
               "purify_derive_public_key accepts identical input and output pointers");
        expect(memcmp(aliased_public_key, first.public_key, sizeof(aliased_public_key)) == 0,
               "purify_derive_public_key aliasing matches the non-aliased result");
    }

    expect(purify_derive_bip340_key(&bip340, first.secret_key) == PURIFY_ERROR_OK,
           "purify_derive_bip340_key succeeds");
    expect(!all_zero(bip340.secret_key, sizeof(bip340.secret_key)),
           "purify_derive_bip340_key produces a non-zero BIP340 secret");
    expect(!all_zero(bip340.xonly_public_key, sizeof(bip340.xonly_public_key)),
           "purify_derive_bip340_key produces a non-zero x-only public key");
    {
        unsigned char aliased_bip340[sizeof(purify_bip340_key)];
        memcpy(aliased_bip340, first.secret_key, PURIFY_SECRET_KEY_BYTES);
        expect(purify_derive_bip340_key((purify_bip340_key*)aliased_bip340, aliased_bip340) == PURIFY_ERROR_OK,
               "purify_derive_bip340_key accepts secret storage inside the output struct");
        expect(memcmp(aliased_bip340, &bip340, sizeof(bip340)) == 0,
               "purify_derive_bip340_key aliasing matches the non-aliased result");
    }

    memset(eval_a, 0, sizeof(eval_a));
    memset(eval_b, 0, sizeof(eval_b));
    expect(purify_eval(eval_a, first.secret_key, message, sizeof(message) - 1) == PURIFY_ERROR_OK,
           "purify_eval succeeds");
    expect(purify_eval(eval_b, first.secret_key, message, sizeof(message) - 1) == PURIFY_ERROR_OK,
           "purify_eval succeeds twice");
    expect(memcmp(eval_a, eval_b, sizeof(eval_a)) == 0,
           "purify_eval is deterministic");
    expect(!all_zero(eval_a, sizeof(eval_a)),
           "purify_eval produces a non-zero field element for one sample");
    {
        unsigned char aliased_eval_secret[PURIFY_SECRET_KEY_BYTES];
        unsigned char aliased_eval_message[PURIFY_FIELD_ELEMENT_BYTES];
        memcpy(aliased_eval_secret, first.secret_key, sizeof(aliased_eval_secret));
        memset(aliased_eval_message, 0, sizeof(aliased_eval_message));
        memcpy(aliased_eval_message, message, sizeof(message) - 1);
        expect(purify_eval(aliased_eval_secret, aliased_eval_secret, message, sizeof(message) - 1) == PURIFY_ERROR_OK,
               "purify_eval accepts output overlapping the secret input");
        expect(memcmp(aliased_eval_secret, eval_a, sizeof(eval_a)) == 0,
               "purify_eval with aliased secret input matches the non-aliased result");
        expect(purify_eval(aliased_eval_message, first.secret_key, aliased_eval_message, sizeof(message) - 1) == PURIFY_ERROR_OK,
               "purify_eval accepts output overlapping the message input");
        expect(memcmp(aliased_eval_message, eval_a, sizeof(eval_a)) == 0,
               "purify_eval with aliased message input matches the non-aliased result");
    }

    purify_fe_set_zero(&zero);
    expect(purify_fe_sqrt(&zero_sqrt, &zero) != 0,
           "purify_fe_sqrt accepts zero");
    expect(purify_fe_is_zero(&zero_sqrt) != 0,
           "purify_fe_sqrt(0) returns 0");

    expect(strcmp(purify_error_name(PURIFY_ERROR_RANGE_VIOLATION), "range_violation") == 0,
           "purify_error_name exposes stable programmatic names");
    expect(strcmp(purify_error_message(PURIFY_ERROR_OK), "success") == 0,
           "purify_error_message describes success");

    if (failures != 0) {
        fprintf(stderr, "%d C test(s) failed\n", failures);
        return 1;
    }

    puts("all c api tests passed");
    return 0;
}
