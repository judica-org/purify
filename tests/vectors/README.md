# Construction parent proof vectors

The two SHA-256 construction-parent proofs are each exactly 15,076 bytes.

- `construction_parent_sha256_accepted.proof` binds the deterministic
  two-anchor C++ fixture and reaches a natively deciding accumulation root.
- `construction_parent_sha256_nondeciding.proof` has the same public
  construction inputs and is valid under the recursive verifier, but
  authenticates a pending root rejected by native `decide()`.

The proof hashes identify these qualification fixtures; they are not protocol
constants. The compiled suite and verifier-artifact identities are the actual
acceptance constants. See
[`release/construction-parent-sha256.json`](../../release/construction-parent-sha256.json)
for all pinned lengths and hashes.

The 720,295,190-byte authenticated verifier artifact is deliberately external
and is not committed to this repository. The release acceptance test receives
its path through `PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT`.
