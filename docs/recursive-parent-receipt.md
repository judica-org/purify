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
2. Constrain its V4 leaf and coefficient-opening reduction on the fixed
   setup basis. The result remains a pending claim.
3. Constrain that claim's point and polynomial to be unchanged when the setup
   basis digest is replaced by the construction basis digest. Every polynomial
   term must remain within the complete setup-basis prefix.

For every anchor child, it then performs the following operations:

1. Parse the fixed V4 proof payload and validate every scalar and
   secp256k1 point encoding.
2. Reconstruct the exact anchor circuit and statement binding from public
   receipt data. No prover-supplied circuit digest or acceptance bit is used.
3. Replay the V4 precommitment and typed Poseidon proof transcript,
   including canonical two-lane nonzero challenge selection.
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
non-native scalar arithmetic. V4 proof-dependent challenges use the
constrained typed Poseidon transcript rather than SHA-256.

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
Verifier-derived constant points use pre-shifted four-bit circuit tables: one
scalar product costs 5,449 gates and produces a 1,283-byte proof. The
implemented three-bit variable-base relation constrains complete point tables,
shares every inter-window doubling, and costs `10,974 + 5,925*T` gates for `T`
terms. That is 200,574 gates for 32 terms and 390,174 for 64. The fixed
two-lane transcript challenge selector uses
2,317 gates and implements the documented unbiased nonzero reduction
into the secp scalar field. The V4 leaf, reduction, and step pieces are
implemented. The complete ordered construction parent, promotion
binding, root codec, and acceptance API remain.

The historical secq SHA-256 gadget costs 30,952 multipliers per
compression block, plus eight multipliers per private input byte.
Replaying V3 required approximately 34 blocks per anchor, or about
1,052,368 SHA multipliers per anchor before point, scalar, reduction, or
transition constraints. That fallback did not meet the hundred-member
budget. V4 now has native and Rust typed Poseidon implementations, so
these SHA counts are not V4 estimates.
V4 is still not a construction receipt. The fixed-fan-in
[batch statements](construction-receipt-batches.md) define a canonical
16-entry partition boundary, but do not supply a parent proof.

The native candidate Poseidon permutation is reproducible from the pinned
parameter generator and cross-language vectors. Its exact Secq R1CS gadget uses
264 multipliers and yields a 1,019-byte standalone proof. The canonical parent
builder also implements typed field, scalar, point-pair, byte-string, `u64`,
and clone-and-index challenge framing; its complete probe uses 1,857 gates.
Native V4 production and cross-suite rejection now use this transcript.
That implements the child suite, not construction-receipt acceptance.

The candidate parent relation now composes those foundations through one
complete public accumulation transition. It fixes the basis digest and claim
shape in the regenerated circuit, absorbs every ordered claim point and compact
polynomial, selects `beta`, constrains the batched claim MSM, selects `x`, and
constrains the compact polynomial evaluation `y`. It then derives the exact
role-separated `U0 + u U1` opening base from that post-claim transcript,
absorbs the result, derives every IPA round challenge, checks the complete
short MSM equation, and binds the resulting folded point, scale, and factors
to root-claim circuit constants. Identity round points remain valid. Shapes
are capped at 1,024 claims and 24 rounds. The claim cap covers the setup plus
the required 100-anchor construction while bounding host allocation; the
round cap follows the current backend limit. The one-claim, one-round
end-to-end probe uses 109,600 gates and a 1,547-byte transparent proof. This
is a composition check, not a production 15-round or 100-anchor size estimate.

This transition uses the separate
`Purify/BPPP/CandidateAccumStep/v1` Poseidon transcript. Native
algebraic steps use the matching typed transcript. This is still not
receipt acceptance.

The candidate [opening-base derivation](opening-base-v2.md) removes both fresh
hash-to-curve evaluations from the constrained path. It derives two
domain-separated constants per basis and role, samples a nonzero transcript
scalar only after the opening claim is fixed, and constrains
`U = U0 + u U1`. The native V2 reduction and step suites now use the identical
typed transcript, distinct proof types and codecs, and reject V1 encodings.
The standalone relation is cross-checked against the vendored native map and
is composed directly into the candidate step; no caller supplies an opening
point. The V4 leaf and typed native prepared-obligation adapter are
implemented. The complete ordered parent and its binding to the final
native decision remain before any acceptance API can exist.

The candidate coefficient reduction consumes an internal
`ConstrainedPreparedNorm`; there is no production constructor from raw claim
values. It absorbs the child relation's canonical `prepared_binding` scalar,
coefficient commitment, tensor weights, and claimed evaluation, derives the
role-1 opening base, and constrains the complete short IPA equation. It then
removes the coefficient evaluation from the norm residual and derives the
fusion challenge only after both pending equations and polynomials are fixed.
The resulting three-term pending claim feeds the accumulation-step
installer as existing circuit variables, without reallocation. The V4
leaf now produces that constrained prepared norm and binding. The native
adapter separately authenticates the exact prepared V4 bridge. Neither
path is receipt acceptance.
The shared one-reduction, one-claim, three-round-step probe uses 342,434 gates
and a 1,679-byte transparent proof. Its accepted proof plus deliberate
false-assignment proof completed in 110.85 seconds in the Release test run.

The production-shape V4 public setup leaf is exactly 854,293 gates. A
hidden anchor leaf is exactly 949,880 gates. Both fall in the backend's
1,745-byte proof-length bucket. These are leaf relation sizes, not a
complete parent-proof measurement.

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
- a changed V4 proof point, scalar, round message, or proof length;
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
