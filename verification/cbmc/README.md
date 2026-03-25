# CBMC Harnesses

This directory contains bounded model checking harnesses for:

- the exact pure C wide-integer core in [`src/core/uint.c`](../../src/core/uint.c)
- verification-only toy-model checks of [`src/core/field.c`](../../src/core/field.c) and [`src/core/curve.c`](../../src/core/curve.c)
  under the explicit bridge stub in [`secp_bridge_small_field.c`](secp_bridge_small_field.c)

Current proof scope:

Proof-class legend:

- `tautological`: too close to the implementation to give much independent assurance.
- `relational`: compares distinct code paths or checks algebraic invariants inside the same implementation boundary.
- `independent`: checks against a separately written decoder/oracle, a fixed vector, or an explicit boundary contract.

There are currently no CBMC harnesses in the `tautological` bucket; the old copied-formula `combine`
check was replaced with the point-average oracle below.

- `u256_bytes_roundtrip_harness.c` (`relational`): 256-bit byte encoding/decoding round-trips exactly.
- `u256_add_sub_inverse_harness.c` (`relational`): successful `try_add` and `try_sub` calls are algebraic inverses.
- `u256_shift_roundtrip_harness.c` (`relational`): lossless left shifts round-trip through `shifted_right`.
- `u256_widen_narrow_harness.c` (`relational`): widen/narrow helpers preserve canonical inputs and reject non-canonical high limbs.
- `u512_divmod_same_harness.c` (`relational`): `purify_u512_try_divmod_same()` returns a remainder below the denominator and reconstructs the original numerator.
- `core_validate_secret_key_contract_harness.c` (`independent`): `purify_validate_secret_key()` exactly accepts values below the documented 64-byte upper bound and rejects `NULL`, the bound itself, and larger values.
- `core_validate_public_key_contract_harness.c` (`independent`): `purify_validate_public_key()` exactly accepts values below the documented 64-byte upper bound and rejects `NULL`, the bound itself, and larger values.
- `field_encoding_boundaries_harness.c` (`independent`): canonical field `b32`/`u256` encodings round-trip, while inputs at or above the modulus are rejected.
- `field_local_identities_harness.c` (`relational`): field subtraction/addition round-trips, signed conversion matches negation, square roots of squares succeed, and a known non-square is rejected.
- `curve_lift_x_contract_harness.c` (`relational`): `purify_curve_is_x_coord()` and `purify_curve_lift_x()` agree exactly, and successful lifts preserve `x`, produce affine `z = 1`, and land on-curve.
- `curve_group_laws_harness.c` (`relational`): arbitrary liftable toy-model points, including both `y` signs and arbitrary non-zero projective representatives, satisfy identity/inverse laws, doubling matches addition, and multiplying by the documented subgroup order reaches infinity.
- `curve_affine_negate_contract_harness.c` (`relational`): projective-to-affine conversion preserves the represented point, negation is involutive, and infinity stays canonical.
- `curve_add_mixed_equivalence_harness.c` (`relational`): `purify_curve_add_mixed()` matches full Jacobian addition on equivalent non-affine representatives.
- `curve_double_in_place_harness.c` (`relational`): in-place doubling matches out-of-place doubling and still agrees with `add(p, p)` on arbitrary toy-model points.
- `curve_secret_mul_consistency_harness.c` (`relational`): the hardened secret-scalar ladder matches affine(public `mul`) on arbitrary toy-model points for every non-zero scalar in range.
- `curve_secret_mul_zero_reject_harness.c` (`independent`): `purify_curve_mul_secret_affine()` rejects the zero scalar exactly on arbitrary toy-model points.
- `curve_secret_mul_one_identity_harness.c` (`independent`): `purify_curve_mul_secret_affine()` returns the affine input point for scalar one on arbitrary toy-model points.
- `curve_combine_point_average_harness.c` (`independent`): `purify_curve_combine()` matches the average of `X(P+Q)` and `X(P-Q)` on the untwisted toy-model curve, which is the derivation-level combine spec rather than a copied field formula.
- `curve_hash_to_curve_contract_harness.c` (`independent`): `purify_curve_hash_to_curve()` rejects null arguments that violate its API contract. Concrete hash-to-curve outputs are covered separately by the generator-vector harnesses.
- `curve_key_to_bits_roundtrip_harness.c` (`independent`): `purify_curve_key_to_bits()` round-trips through a separately written signed-window decoder for all bounded `(value, max_value)` pairs with `1 <= value <= max_value <= 100`.
- `curve_pack_public_roundtrip_harness.c` (`relational`): `purify_curve_pack_public()` and `purify_curve_unpack_public()` round-trip every toy-model public key.
- `curve_unpack_public_inverse_harness.c` (`relational`): every valid packed toy-model public key decodes and re-encodes exactly.
- `curve_unpack_secret_roundtrip_harness.c` (`independent`): mixed-radix packed secrets decode back to the original `(z1, z2)` pair for every in-range toy-model witness.
- `curve_unpack_secret_inverse_harness.c` (`independent`): every valid packed toy-model secret decodes and re-encodes exactly through a separately written mixed-radix encoder.
- `curve_key_space_invariants_harness.c` (`independent`): key-space constants, upper bounds, and last-valid-element decodings are internally consistent.
- `curve_invalid_key_rejection_harness.c` (`independent`): out-of-range packed secret and public keys are rejected exactly at the documented space boundary.
- `hash_to_curve_generator_points_harness.c` (`independent`): `hash_to_curve("Generator/1")` and `hash_to_curve("Generator/2")` return exact, deterministic toy-model generator points.

The field and curve proofs are intentionally a toy-model argument, not a proof over the production secp backend. They use a verification-only prime field `GF(107)` and prime-order toy curves that preserve the same code paths and algebraic structure while replacing the backend bridge with a narrow deterministic model. That lets CBMC prove local arithmetic and curve logic without claiming that the backend itself is formally verified.

Run through CMake when `cbmc` is on `PATH`:

```sh
cmake --preset cbmc
cmake --build --preset cbmc
ctest --preset cbmc
```

Or configure manually with `-DPURIFY_BUILD_CBMC=ON`.
