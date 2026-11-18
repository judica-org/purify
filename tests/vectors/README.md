# Construction parent qualification vectors

The mixed distributed construction-parent qualification pins four vectors:

- `construction_parent_sha256_accepted.wit4` is the deterministic public
  witness for an accepted two-anchor construction;
- `construction_parent_sha256_nondeciding.wit4` has identical public inputs
  and a distinct final root that is recursively valid but fails native
  accumulation decision;
- `construction_parent_sha256_accepted.proof` is the matching accepted Nova
  proof; and
- `construction_parent_sha256_nondeciding.proof` is the matching recursive
  proof for the nondeciding root.

Both Wit4 fixtures are 17,587 bytes and both proofs are 15,076 bytes. Normal
C++ tests regenerate and byte-compare the Wit4 fixtures. Rust tests parse the
same checked bytes. The artifact-backed release gate verifies both proofs and
requires the nondeciding proof to fail only at the native decision boundary.

The qualified fixture contains three setup leaves and two anchor leaves, for
five recursive steps. The prover CLI bounds Wit4 to 200 total leaves and a
676,297-byte frame. Char Formation V3 separately caps setup and anchor entries
at 100 each before this boundary. This qualification does not claim a
200-step performance measurement.

Reusable setup was qualified from the tagged predecessor's strict Wit3
fixture. Production accepts Wit4 only. Wit4 removes the already
descriptor-and-statement-bound 66-byte setup prefix and 96-byte anchor prefix
from each record. Exact projection checks covered descriptors, public points,
transcript inputs, proof reductions, ordered steps, and final roots. The Nova
relation, PK1, VK2, and 15,076-byte proof format are unchanged.

| Vector | SHA256 |
| --- | --- |
| Accepted Wit4 | `77b7331e92a538ebd1bfe90480166b298196ff4dd9a3d8f7557c202a3bab3418` |
| Nondeciding Wit4 | `9620a21298d175d3c68a5b7b98da82e11065beae2b6048c76625a2b7303a8115` |
| Accepted proof | `74b66a779134a39560185472708d94e9a1532240f7fcf9c66a88d91728e8d779` |
| Nondeciding proof | `a869016dea8d439f579b8c7be6c3613bc3e5f5e9f18f6177ee27c6050038b072` |

The 693,708,278-byte VK2 verifier artifact and 693,582,375-byte PK1 prover
artifact remain external. Their authenticated identities and all vector
hashes are recorded in
[`release/construction-parent-sha256.json`](../../release/construction-parent-sha256.json).

The final gate produced distinct randomized setup and installed-CLI proofs.
Both passed recursive verification, exact-state checking, the C++ receipt
boundary, and native accumulation decision. The installed CLI completed in
6,749.73 seconds with 4,722,769,920-byte maximum RSS and an
8,447,794,208-byte peak footprint. Setup completed successfully, but the
sandbox denied its extended `/usr/bin/time -l` metrics after the test passed;
the manifest therefore records setup memory as unavailable rather than zero.

Full vector requalification is an explicit native-resource release operation.
Every output path must not exist before running:

```sh
cd rust/construction-parent
PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE=/path/to/accepted.wit4 \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROVER_FIXTURE=/path/to/nondeciding.wit4 \
PURIFY_CONSTRUCTION_PARENT_PROOF_OUT=/new/path/accepted.proof \
PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROOF_OUT=/new/path/nondeciding.proof \
PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT_OUT=/new/path/sha256-parent-verifier.nvk.zst \
cargo test --release \
  native_profile_sha_parent_qualification_is_exact -- --ignored --nocapture
```

Select and persist reusable prover state with the frozen accepted Wit4 and an
independently selected VK2:

```sh
cd rust/construction-parent
PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE=/path/to/accepted.wit4 \
PURIFY_CONSTRUCTION_PARENT_PROVER_ARTIFACT_OUT=/new/path/sha256-parent-prover.pk1.zst \
PURIFY_CONSTRUCTION_PARENT_FRESH_PROOF_OUT=/new/path/fresh-accepted.proof \
PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT=/path/to/sha256-parent-verifier.nvk.zst \
cargo test --release \
  setup_only_qualification_persists_a_usable_prover -- --ignored --nocapture
```

That test authenticates the reloaded PK1, consumes it to produce one fresh
proof, independently reloads VK2, and verifies the exact recursive final
state. It does not accept the construction receipt. Pass the fresh proof
through the same C++ verifier and native accumulation decision used by the
release gate:

```sh
PURIFY_CONSTRUCTION_PARENT_QUALIFICATION_PROOF=/path/to/fresh-accepted.proof \
ctest --test-dir build-parent --output-on-failure \
  -R '^purify.tests.slashability_e2e$'
```

The override is test-only, must name an exact 15,076-byte proof for the
checked accepted Wit4, and does not change the compiled qualified proof used
by normal tests. A missing override retains the frozen vector path.
