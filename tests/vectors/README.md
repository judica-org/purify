# Construction parent proof vectors

The two SHA-256 construction-parent proofs are each exactly 15,076 bytes.

- `construction_parent_sha256_accepted.proof` binds the deterministic
  two-anchor C++ fixture and reaches a natively deciding accumulation root.
- `construction_parent_sha256_nondeciding.proof` has the same public
  construction inputs and is valid under the recursive verifier, but
  authenticates a pending root rejected by native `decide()`.

The corresponding `*.fixture` files are each exactly 8,314 bytes. They are
the canonical prover inputs from which the two proofs were qualified. Keeping
them beside the proofs makes the qualification reproducible from a fresh
checkout without reconstructing private test state.

The proof hashes identify these qualification fixtures; they are not protocol
constants. The compiled suite and verifier-artifact identities are the actual
acceptance constants. See
[`release/construction-parent-sha256.json`](../../release/construction-parent-sha256.json)
for all pinned lengths and hashes.

The 693,735,316-byte authenticated verifier artifact is deliberately external
and is not committed to this repository. The release acceptance test receives
its path through `PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT`.

Given the authenticated artifact, verify both checked-in proofs with:

```sh
PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE="$PWD/tests/vectors/construction_parent_sha256_accepted.fixture" \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROVER_FIXTURE="$PWD/tests/vectors/construction_parent_sha256_nondeciding.fixture" \
PURIFY_CONSTRUCTION_PARENT_PROOF="$PWD/tests/vectors/construction_parent_sha256_accepted.proof" \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROOF="$PWD/tests/vectors/construction_parent_sha256_nondeciding.proof" \
PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT=/path/to/sha256-parent-verifier.nvk.zst \
cargo test --manifest-path rust/construction-parent/Cargo.toml --release \
  qualified_sha_parent_artifact_verifies_both_outputs -- --ignored --nocapture
```

Regenerating the proofs and artifact is an explicit native-resource release
operation. Each output path must not already exist:

```sh
PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE="$PWD/tests/vectors/construction_parent_sha256_accepted.fixture" \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROVER_FIXTURE="$PWD/tests/vectors/construction_parent_sha256_nondeciding.fixture" \
PURIFY_CONSTRUCTION_PARENT_PROOF_OUT=/new/path/accepted.proof \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROOF_OUT=/new/path/nondeciding.proof \
PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT_OUT=/new/path/sha256-parent-verifier.nvk.zst \
cargo test --manifest-path rust/construction-parent/Cargo.toml --release \
  native_profile_sha_parent_qualification_is_exact -- --ignored --nocapture
```
