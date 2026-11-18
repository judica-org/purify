# Qualification vectors

## Construction parent

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

## Certificate parent

The certificate-parent tests pin three checked-in cross-language vectors:

| Vector | Encoded bytes | SHA256 |
| --- | ---: | --- |
| `certificate_response_authorization_v1.txt` | 1,947 | `8199cfcf64a55db72ec3c7e110e860bef411992f0b5dd83a0b40e60db36a8c78` |
| `certificate_joined_witness_v2.bin` | 13,782 | `21146d1a2c78206288e741efb57995daba871f787a25ab8548e0119ce58c48d5` |
| `certificate_joined_witness_v3.bin` | 14,608 | `36a4806d937edd496f28464248256512d45e51e25e36b5b6c184e991b88c9d46` |

The authorization vector is 973 canonical response-authorization bytes
encoded as lowercase hex plus a newline. C++ produces the record and Rust
recomputes its common, response, binding, member, and ordered-manifest
digests. The table hashes the checked-in text file, not its decoded bytes.

CertJWit2 joins the same accepted public records and V4 nonce proofs to a
detached native receipt. It remains a compatibility vector for the native
member and recurrence tests; it is not accepted by the production
certificate-parent prover. CertJWit3 is the production linear witness. It
adds the fixed native basis and places one reduction and bound transition
beside each of the four ordered members, with no detached receipt or tree
suffix.

The qualified CertJWit3 has two responses with two members each. Its external
96-byte `Purify/CertPub1\0` frame has SHA256
`9057d923d70e4b600eb9e7f085a32f4a1eb245e6188dde6a0b8147a0ad816196`.
It fixes certificate context
`7bcb06b8538ccc9c79fd2f595bbbee9f08c0d829a97ccd92fc3175eb379039f5`,
two responses, four steps, and final manifest
`45e8147f293a6edcf50c178d94a4731b5e18784c7b404ba9c357b9db224c1f9c`.
The frame is independently reconstructed from public C++ records; CertJWit3
cannot choose it.

The 696,190,360-byte VK2 and 696,022,272-byte PK1 artifacts remain external.
The accepted 15,268-byte proof has SHA256
`887eb27a8893078734a57fb497ed9f9aadff03803454e419d497f0650727babb`.
Their exact identities, historical Char source commits, suite, timings, and
qualification scope are recorded in
[`release/certificate-parent-sha256.json`](../../release/certificate-parent-sha256.json).
That manifest records a historical Char qualification; the extraction into
this repository did not rerun setup or proving.

### Certificate requalification

Requalification is an explicit high-resource release operation. Do not
overwrite any checked vector or artifact. Regenerate candidates at new paths,
review their protocol differences, and update the frozen suite and artifact
descriptors only as one deliberate release.

First regenerate CertJWit3 from the deterministic external Char integration
fixture identified by the release manifest. Run
`char_certificate_nonce_parent_tests` from that exact source tree with a new
output path:

```sh
CHAR_CERTIFICATE_WITNESS_V3_OUT=/new/path/certificate.certjwit3 \
  /path/to/char-test-binary \
  --run_test=char_certificate_nonce_parent_tests
```

The test must still derive the public frame independently and must byte-check
the authorization, response order, member order, native decision, and final
manifest before exporting. CertJWit2 and the authorization text are
cross-language regression vectors, not inputs to certificate setup. If their
formats intentionally change, regenerate them from the same deterministic
C++ fixture and update both C++ and Rust expectations; do not infer new bytes
from the Rust relation.

From `rust/construction-parent`, create fresh transparent prover and verifier
artifacts. Both output paths must not exist:

```sh
PURIFY_CERTIFICATE_PARENT_PROVER_ARTIFACT_OUT=/new/path/certificate-parent-prover.pk1 \
PURIFY_CERTIFICATE_PARENT_VERIFIER_ARTIFACT_OUT=/new/path/certificate-parent-verifier.vk2 \
cargo test --release \
  setup_only_certificate_parent_qualification_writes_artifacts \
  -- --ignored --nocapture
```

Then prove the pinned public frame and the reviewed CertJWit3 with the fresh
artifacts. The proof output must not exist:

```sh
PURIFY_CERTIFICATE_PARENT_PROVER_ARTIFACT=/new/path/certificate-parent-prover.pk1 \
PURIFY_CERTIFICATE_PARENT_VERIFIER_ARTIFACT=/new/path/certificate-parent-verifier.vk2 \
PURIFY_CERTIFICATE_PARENT_PROOF_OUT=/new/path/certificate-parent-proof.bin \
cargo test --release \
  qualified_artifacts_produce_the_pinned_certificate_proof \
  -- --ignored --nocapture
```

Finally build Purify with
`PURIFY_BUILD_CONSTRUCTION_PARENT_VERIFIER=ON` and run the native C++ boundary
against both fresh resources:

```sh
PURIFY_TEST_CERTIFICATE_PARENT_VERIFIER_ARTIFACT=/new/path/certificate-parent-verifier.vk2 \
PURIFY_TEST_CERTIFICATE_PARENT_PROOF=/new/path/certificate-parent-proof.bin \
ctest --test-dir build-parent --output-on-failure \
  -R '^purify.tests.certificate_nonce_parent$'
```

That gate reconstructs the qualified manifest from the hash-pinned CertJWit3
public records, accepts the matching proof, rejects a changed manifest and
changed proof, parses the authenticated pending root against the native basis,
and completes native decision. Record new hashes and measured resources in a
new release manifest only after all three layers pass.
