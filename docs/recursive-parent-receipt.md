# Recursive construction receipt boundary

This document fixes the selected boundary between the transparent secq parent
proof and the native BP++ accumulator. It is an implementation map, not a claim
that construction receipts are accepted yet.

The parent must authenticate independently published anchor-escrow proofs. The
assembler learns no anchor or coalition secret. Child proof payloads, norm
reduction proofs, and accumulation transitions are witnesses to the parent and
can disappear after the final receipt is published.

## Acceptance rule

A construction receipt is accepted only when both checks succeed:

1. the secq parent proof verifies for the exact construction payload,
   registry-resolved setup-record digest and setup statement, resolved anchor
   statements, and serialized root pending claim; and
2. native `accumulation::decide` discharges that exact root claim against the
   fixed anchor-escrow basis.

Neither check is optional. A pending claim does not authenticate its ancestry,
and a parent proof which does not bind the decided claim proves a different
statement.

The coalition setup proof is one private parent witness selected by the
payload's recovery root. The parent authenticates it once, reduces its norm
obligation on the fixed 8,192-point setup basis, and constrains its exact
zero-extension into the 32,768-point construction basis. It then reconstructs
each anchor statement from that setup, the deterministic ordered anchor
reference and resolved root, the context, and the on-chain ciphertext.
Registry policy still determines which manifest is authorized, but it does not
replace setup-proof verification.

Recovery-root lookup must be immutable and one-to-one. The public statement
binds the nonzero digest of the exact historical setup record selected by that
root; the record preimage includes the root itself, roster, core, nonce-host
commitment, setup context, and registry schema version. This resolved digest is
contextual input and adds no on-chain bytes.

## Constrained relation

The parent first performs the following setup operations in its arithmetic
relation:

1. Parse the fixed setup proof and reconstruct its exact circuit, public
   signing-key output, recovery root, roster, and transcript binding.
2. Verify its V3 transcript and coefficient-opening reduction on the fixed
   setup basis. The result remains a pending claim.
3. Constrain that claim's point and polynomial to be unchanged when the setup
   basis digest is replaced by the construction basis digest. Every polynomial
   term must remain within the complete setup-basis prefix.

For every anchor child, it then performs the following operations:

1. Parse the fixed V3 proof payload and validate every scalar and secp256k1
   point encoding.
2. Reconstruct the exact anchor circuit and statement binding from public
   receipt data. No prover-supplied circuit digest or acceptance bit is used.
3. Replay the V3 raw-precommitment, zero-knowledge, and inner norm Fiat-Shamir
   transcripts, including canonical nonzero challenge sampling.
4. Compute the inner norm residual point and its compact generator-weight
   polynomials from the terminal scalars and folding challenges.
5. Reconstruct the exact coefficient commitment obligation and verify the
   public coefficient-opening reduction. This produces one leaf
   `PendingClaim`; it does not accept the child by itself.
6. Verify every ordered accumulation transition over the promoted setup claim
   and all anchor leaf claims. The final transition produces the root claim
   bound into the parent statement.

The secq commitment group has the secp256k1 coordinate field as its R1CS scalar
field. Secp256k1 point arithmetic is therefore native in the parent. BP++
scalars live modulo the secp256k1 group order and still require canonical
non-native scalar arithmetic. Proof-dependent SHA-256 challenges also remain
constrained unless the child proof suite is explicitly replaced.

The first complete group gadget constrains the secp256k1 curve equation, a
unique identity encoding, and addition for distinct points, doubling, inverses,
and both identity cases. Its circuit shape is independent of the private
branch. The scalar foundation constrains canonical four-limb values modulo the
secp256k1 group order and modular add, subtract, multiply, and inverse.
The compressed-point foundation constrains a unique coordinate-field integer,
the SEC1 parity bit, the curve equation, and non-identity. Complete fixed-shape
variable-base scalar multiplication costs 23,280 gates and produces a
1,415-byte standalone backend proof. A naive 32-term accumulation-step MSM
would therefore cost about 745,000 gates before transcript and scalar algebra.
The implemented fixed-shape Straus relation shares all 255 doublings and costs
`10,983 + 12,297*T` gates for `T` variable terms: 404,487 gates for the
32-term step equation. The fixed two-lane transcript challenge selector uses
2,317 gates and implements the documented unbiased nonzero reduction into the
secp scalar field. End-to-end transcript integration and the complete
V3/reduction/promotion/step relations remain before an acceptance API can be
exposed.

The exact secq SHA-256 gadget costs 30,952 multipliers per compression block,
plus eight multipliers per private input byte. Replaying the current V3
transcripts requires approximately 34 blocks per anchor, or about 1,052,368
SHA multipliers per anchor before point, scalar, reduction, or transition
constraints. This is a correct fallback relation, but it does not meet the
hundred-member production budget. The child transcript suite therefore needs
either a reviewed recursion-friendly replacement or a proof tree with a
measured bounded fan-in before activation. The existing SHA-based proof format
remains the only accepted format until a replacement has complete prover,
verifier, cross-suite rejection, and security tests. Because the protocol is
pre-release, that migration should replace the suite cleanly rather than add a
permanent compatibility path.

The native candidate Poseidon permutation is reproducible from the pinned
parameter generator and cross-language vectors. Its exact Secq R1CS gadget uses
264 multipliers and yields a 1,019-byte standalone proof. The canonical parent
builder also implements typed field, scalar, point-pair, byte-string, `u64`,
and clone-and-index challenge framing; its complete probe uses 1,857 gates.
This is deliberately not an accepted transcript suite: native prover
integration and cross-suite rejection must land together before the SHA format
can be replaced.

## Why the final MSM stays native

Directly checking every child's fixed-generator norm equation in the parent
would repeat linear work per anchor. The accumulator instead represents each
equation as a point and a compact polynomial over one deterministic basis.
Reduction and transition verification are logarithmic in the basis dimension.
Only the final root needs the linear fixed-basis MSM, so its cost is independent
of the number of anchors in the receipt.

For the current 8,192-gate anchor relation, the raw accumulation basis has
32,768 points and a final step has 15 folding factors. With the basis and
dimensions fixed by the receipt version, the minimal root-claim data is:

```text
point:33 || scale:32 || factors:15*32
```

That is 545 bytes before versioning and framing. It is additional to the secq
proof unless the final 32,768-term decision is moved inside the parent. Moving
that decision inside removes the public claim but makes the parent perform the
linear generator work. The initial production format should keep the explicit
claim and benchmark the native decision.

The transparent secq backend's proof length is logarithmic in its padded
multiplier count. Its implemented one-phase wire formula is:

```text
425 + 66 * ceil(log2(multiplier_count))
```

This formula does not predict the final receipt size until the full relation's
gate count is measured. The target is consequently closer to:

```text
construction payload + root pending claim + one secq parent proof
```

rather than treating the root obligation as an implicit or trusted value.

## Deterministic verification randomization

The secq backend combines independent verification equations with a random
scalar before its final MSM. That scalar is a verifier soundness challenge; it
is not secret prover randomness. Bitcoin consensus verification must not vary
with operating-system entropy.

The backend therefore seeds its verifier RNG with a domain-separated SHA-256
hash of the complete canonical circuit, statement, and proof, including length
framing. The Bulletproof library mixes that seed into its already proof-bound
Merlin transcript before sampling the equation coefficient. Every node derives
the same coefficient, while an altered circuit, statement, or proof derives a
different one. This is an intentional Fiat-Shamir transformation and relies on
the random-oracle model.

This construction currently verifies one equation bundle. A future batch
verifier must hash the complete ordered batch before deriving any coefficient.
It must not derive one coefficient and then accept later, adaptively selected
equations. Replacing the deterministic seed with `OsRng` would make consensus
acceptance depend on local state and is prohibited.

## Required negative tests

Before activation, end-to-end tests must reject at least:

- a changed setup, anchor reference, recovery root, context, or ciphertext;
- a changed V3 proof point, scalar, round message, or proof length;
- a noncanonical scalar or point and every exceptional group case;
- a valid proof moved to a different ordered manifest;
- a removed, duplicated, reordered, or substituted child;
- a changed coefficient opening or accumulation transition;
- a generic or vacuous setup-basis claim substituted for the typed setup
  reduction;
- a changed setup-to-construction basis promotion;
- a parent proof rebound to another root claim; and
- a valid parent proof followed by a false final native decision.

Benchmarks must report parent proving time, parent verification time, proof and
claim bytes, and final decision time separately for 1, 2, and 100 anchors.
