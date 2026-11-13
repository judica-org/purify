# Construction parent proof vectors

The superseded centralized `Wit2` fixtures and proofs were removed at the
mixed distributed-parent cutover. No construction-parent qualification vector
is currently checked in. The current loader returns `QualificationPending`
before reading stale artifact bytes.

See
[`release/construction-parent-sha256.json`](../../release/construction-parent-sha256.json)
for the explicitly superseded artifact metadata and pending-vector status.

The superseded 693,735,316-byte artifact is external and deliberately not
accepted by this source tree. Requalifying the mixed relation is an explicit
native-resource release operation. It must start from newly exported `Wit3`
accepted and nondeciding fixtures, and every output path must not exist:

```sh
PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE=/new/path/accepted.wit3 \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROVER_FIXTURE=/new/path/nondeciding.wit3 \
PURIFY_CONSTRUCTION_PARENT_PROOF_OUT=/new/path/accepted.proof \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROOF_OUT=/new/path/nondeciding.proof \
PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT_OUT=/new/path/sha256-parent-verifier.nvk.zst \
cargo test --manifest-path rust/construction-parent/Cargo.toml --release \
  native_profile_sha_parent_qualification_is_exact -- --ignored --nocapture
```
