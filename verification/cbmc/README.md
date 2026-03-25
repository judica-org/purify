# CBMC Harnesses

This directory contains bounded model checking harnesses for the pure C wide-integer core in [`src/core/uint.c`](../../src/core/uint.c).

Current proof scope:

- `u256_bytes_roundtrip_harness.c`: 256-bit byte encoding/decoding round-trips exactly.
- `u256_add_sub_inverse_harness.c`: successful `try_add` and `try_sub` calls are algebraic inverses.
- `u256_shift_roundtrip_harness.c`: lossless left shifts round-trip through `shifted_right`.
- `u256_widen_narrow_harness.c`: widen/narrow helpers preserve canonical inputs and reject non-canonical high limbs.
- `u512_divmod_same_harness.c`: `purify_u512_try_divmod_same()` returns a remainder below the denominator and reconstructs the original numerator.

These harnesses intentionally stop at the wide-integer layer. They do not claim formal coverage for field arithmetic, curve formulas, or protocol logic, because those layers currently depend on the secp256k1-zkp bridge and need additional modeling or stubbing to make a trustworthy CBMC proof.

Run through CMake when `cbmc` is on `PATH`:

```sh
cmake --preset cbmc
cmake --build --preset cbmc
ctest --preset cbmc
```

Or configure manually with `-DPURIFY_BUILD_CBMC=ON`.
