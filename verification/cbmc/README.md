# CBMC Harnesses

This directory contains bounded model checking harnesses for:

- the exact pure C wide-integer core in [`src/core/uint.c`](../../src/core/uint.c)
- verification-only toy-model checks of [`src/core/field.c`](../../src/core/field.c) and [`src/core/curve.c`](../../src/core/curve.c)
  under the explicit bridge stub in [`secp_bridge_small_field.c`](secp_bridge_small_field.c)

Current proof scope:

- `u256_bytes_roundtrip_harness.c`: 256-bit byte encoding/decoding round-trips exactly.
- `u256_add_sub_inverse_harness.c`: successful `try_add` and `try_sub` calls are algebraic inverses.
- `u256_shift_roundtrip_harness.c`: lossless left shifts round-trip through `shifted_right`.
- `u256_widen_narrow_harness.c`: widen/narrow helpers preserve canonical inputs and reject non-canonical high limbs.
- `u512_divmod_same_harness.c`: `purify_u512_try_divmod_same()` returns a remainder below the denominator and reconstructs the original numerator.
- `field_local_identities_harness.c`: field subtraction/addition round-trips, signed conversion matches negation, square roots of squares succeed, and a known non-square is rejected.
- `curve_group_laws_harness.c`: fixed toy-model points lie on the curve, satisfy identity/inverse laws, doubling matches addition, and multiplying by the documented subgroup order reaches infinity.
- `curve_secret_mul_consistency_harness.c`: the hardened secret-scalar ladder matches affine(public `mul`) on both toy-model curves.
- `curve_combine_formula_harness.c`: `purify_curve_combine()` matches the direct field formula whenever the denominator is non-zero.
- `curve_key_to_bits_roundtrip_harness.c`: `purify_curve_key_to_bits()` round-trips through the signed-window decoder on all values in a bounded range.

The field and curve proofs are intentionally a toy-model argument, not a proof over the production secp backend. They use a verification-only prime field `GF(107)` and prime-order toy curves that preserve the same code paths and algebraic structure while replacing the backend bridge with a narrow deterministic model. That lets CBMC prove local arithmetic and curve logic without claiming that the backend itself is formally verified.

Run through CMake when `cbmc` is on `PATH`:

```sh
cmake --preset cbmc
cmake --build --preset cbmc
ctest --preset cbmc
```

Or configure manually with `-DPURIFY_BUILD_CBMC=ON`.
