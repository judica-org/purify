# Recursive construction receipt boundary

This document fixes the selected boundary between a transparent Nova parent
proof and the native BP++ accumulator. It is an implementation map, not a
claim that construction receipts are accepted yet.

The parent must authenticate independently published anchor-escrow proofs. The
assembler learns no anchor or coalition secret. Child proof bodies, norm
reduction proofs, and accumulation transitions are witnesses to the parent and
can disappear after the final receipt is published.

## Target acceptance rule

A future receipt may be accepted only when all three checks succeed:

1. the setup reference resolves to one immutable, previously verified setup
   record and its canonical construction-basis seed claim;
2. the compressed Nova proof verifies the exact number of homogeneous anchor
   steps from that seed, ending at the payload-derived manifest and serialized
   root pending claim; and
3. native `accumulation::decide` discharges that exact root claim against the
   fixed anchor-escrow basis.

None of these checks is optional. A pending claim does not authenticate its
ancestry, and a parent proof which does not bind the decided claim proves a
different statement.

The coalition setup proof is verified when its immutable registry record is
created, rather than being repeated inside every construction receipt. That
transition reduces the setup norm obligation on the fixed 8,192-point setup
basis, constrains its exact zero-extension into the 32,768-point construction
basis, and stores the resulting canonical 545-byte seed claim. The historical
setup record remains Bitcoin-replayable, so a node syncing only from Bitcoin
can reproduce the seed without trusting a local cache.

Recovery-root lookup must be immutable and one-to-one. The public statement
binds the nonzero digest of the exact historical setup record selected by that
root; the record preimage includes the root itself, roster, core, nonce-host
commitment, setup context, and registry schema version. This resolved digest is
contextual input and adds no on-chain bytes.

## Registry seed and constrained recurrence

The immutable setup-record transition performs these operations once:

1. Parse the fixed setup proof and reconstruct its exact circuit, public
   signing-key output, recovery root, roster, and transcript binding.
2. Verify its V4 leaf and coefficient-opening reduction on the fixed
   setup basis. The result remains a pending claim.
3. Verify that claim's point and polynomial are unchanged under the typed
   setup-to-construction promotion. Every polynomial term must remain within
   the complete setup-basis prefix.
4. Verify a one-claim, 15-round accumulation transition into the canonical
   one-term seed root, then run the mandatory native decision before storing
   that root in the registry.

Every construction receipt then uses one fixed hidden-anchor matrix. For each
ordered anchor it performs the following operations:

1. Parse the fixed-shape private V4 proof witness and validate every scalar and
   secp256k1 point encoding.
2. Reconstruct the exact anchor circuit and statement binding from public
   receipt data. No prover-supplied circuit digest or acceptance bit is used.
3. Replay the V4 precommitment and typed Poseidon proof transcript,
   including canonical two-lane nonzero challenge selection.
4. Compute the inner norm residual point and its compact generator-weight
   polynomials from the terminal scalars and folding challenges.
5. Reconstruct the exact coefficient commitment obligation and verify the
   constrained coefficient-opening reduction. This produces one leaf
   `PendingClaim`; it does not accept the child by itself.
6. Verify one ordered two-claim accumulation transition from the previous root
   and this anchor leaf. The output root becomes the next step's input.

The recurrence state has exactly 20 primary-field elements: the root point's
SEC1 prefix and x coordinate, its scale and 15 folding factors, one rolling
Poseidon manifest field, and the ordered anchor index. The affine y coordinate
is private and constrained by the curve equation and prefix. The initial state
is derived by absorbing the manifest domain and version, construction statement
digest, resolved setup-record digest, seed root, and payload count. Each step
absorbs the prior manifest, zero-based index, exact statement binding, V4
precommitment, coefficient commitment, and anchored offset used by that leaf.
Final verification requires the expected step count, manifest, index, and
545-byte root; no intermediate state is an acceptance result.

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
into the secp scalar field. The V4 leaf, reduction, accumulation step, and
variable transcript-binding pieces are implemented. The fixed-matrix
recurrence is under integration. The canonical Nova codec, verifier-derived
initial state, construction payload codec, resource limits, and acceptance API
remain.

The historical secq SHA-256 gadget costs 30,952 multipliers per
compression block, plus eight multipliers per private input byte.
Replaying V3 required approximately 34 blocks per anchor, or about
1,052,368 SHA multipliers per anchor before point, scalar, reduction, or
transition constraints. That fallback did not meet the hundred-member
budget. V4 now has native and Rust typed Poseidon implementations, so
these SHA counts are not V4 estimates.
V4 is still not a construction receipt. Independently published child proofs
remain off-chain witnesses. The candidate payload carries each 192-byte anchor
ciphertext and its 32-byte nonzero V4 precommitment. The verifier derives the
leaf's expected coefficient commitment and anchored offset from that
precommitment and the exact resolved statement, while the recurrence manifest
binds those same constrained values. This gives a 224-byte entry before the
fixed receipt header, root claim, and compressed parent proof.

The native candidate Poseidon permutation is reproducible from the pinned
parameter generator and cross-language vectors. Its exact Secq R1CS gadget uses
264 multipliers and yields a 1,019-byte standalone proof. The canonical parent
builder also implements typed field, scalar, point-pair, byte-string, `u64`,
and clone-and-index challenge framing; its complete probe uses 1,857 gates.
Native V4 production and cross-suite rejection now use this transcript.
That implements the child suite, not construction-receipt acceptance.

The underlying generic accumulation primitive composes those foundations
through one constrained transition. It fixes the basis digest and claim
shape in the regenerated circuit, absorbs every ordered claim point and compact
polynomial, selects `beta`, constrains the batched claim MSM, selects `x`, and
constrains the compact polynomial evaluation `y`. It then derives the exact
role-separated `U0 + u U1` opening base from that post-claim transcript,
absorbs the result, derives every IPA round challenge, checks the complete
short MSM equation, and binds the resulting folded point, scale, and factors
to root-claim circuit constants. Identity round points remain valid. The
generic installer is capped at 1,024 claims and 24 rounds to bound host
allocation. The production recurrence uses exactly two claims per step: its
previous one-term root and one three-term anchor leaf. One hundred anchors are
one hundred state transitions, not one hundred claims in a flat step. The
one-claim, one-round end-to-end probe uses 109,600 gates and a 1,547-byte
transparent proof. This is a composition check, not a production 15-round
size estimate.

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
implemented. Remaining receipt work is the fixed-state Nova adapter, canonical
codec, expected-manifest reconstruction, exact-step enforcement, and final
root-to-decision acceptance boundary.

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

The standalone secq arithmetic probe for one reduction, one claim, and a
three-round step uses 342,434 gates and a 1,679-byte proof. Its accepted proof
plus deliberate false-assignment proof completed in 110.85 seconds in the
Release test run.

The production-shape V4 public setup leaf is exactly 854,293 gates. A
hidden anchor leaf is exactly 949,880 gates. Both fall in the standalone secq
backend's 1,745-byte proof-length bucket. That bucket does not predict
compressed Nova size. These are leaf relation sizes, not a complete
parent-proof measurement.

For the superseded flat parent, shared step powers make setup plus 12 anchors
and the first step total
16,041,247 gates, 735,969 below the `2^24` cap. Setup plus 13 totals
17,239,860, which is 462,644 over. A later anchor-only step fits 13
anchors at 16,170,296 gates; 14 totals 17,368,909 and is 591,693 over.
These are arithmetic bounds only. No near-cap proof has qualified peak
memory, proving time, or verification time.

These bounds explain why one flat circuit and the earlier 16-entry proof-tree
proposal are not the selected construction. The homogeneous Nova recurrence
processes one anchor per step and authenticates the exact ordered count in its
state and manifest. A legacy descriptor limit must not silently become a Nova
consensus limit; the construction receipt requires a new versioned codec.

## Recursive backend feasibility

Nova 0.76 over the secq/secp cycle is the selected transparent folding
backend. A fixed-relation session owns one canonical R1CS matrix, rejects a
changed matrix on later steps, binds every state transition, and compresses
with transparent Spartan IPA. This selection is not receipt activation: a
canonical proof codec, the production recurrence adapter, resource limits,
and the complete acceptance path remain required.

The first fixed-relation Release probe used a one-gate transition for two
steps. Its primary matrix had 10,442 constraints and 10,434 variables; the
secondary matrix had 10,787 constraints and 10,769 variables. Its deliberately
noncanonical bincode serialization was 10,660 bytes. Bincode is only an
in-memory proof-object measurement, not a consensus wire encoding or a size
bound.

A bounded scaling probe then added independent multiplication gates and one
linear constraint per extra gate. It measured the complete setup, two-step
fold, recursive verification, compression, and compressed verification in one
Release process:

| Gates | Measured bytes | Primary constraints / variables | Pipeline | Peak RSS |
| ---: | ---: | ---: | ---: | ---: |
| 1,024 | 10,660 | 12,488 / 13,503 | 4.298 s | 143,409,152 B |
| 16,384 | 11,288 | 43,208 / 59,583 | 9.144 s | 289,062,912 B |
| 65,536 | 11,916 | 141,512 / 207,039 | 30.994 s | 737,148,928 B |

At 65,536 gates, public-parameter generation took 3.996 seconds, folding
182 milliseconds, recursive verification 203 milliseconds, compression setup
281 milliseconds, compression 26.073 seconds, and compressed verification
257 milliseconds. The secondary matrix stayed fixed at 10,787 constraints and
10,769 variables in all three runs.

The measured object grew by 1,256 bytes while the synthetic gate count grew by
64 times, which is consistent with logarithmic proof growth. It does not
qualify the production relation. One hidden anchor leaf alone is about 950,000
gates and has denser scalar, curve, and transcript constraints. Extrapolating
the synthetic RSS line to that relation is unsafe; a production-shaped
measurement must pass an explicit memory ceiling before proof generation can
be exposed by an acceptance or RPC API.

The fixed-matrix mismatch between public setup and hidden anchor leaves is
resolved by the immutable setup registry described above. Per-anchor binding
digests, precommitments, coefficient commitments, and offsets are assignment
variables authenticated by the rolling manifest, so different valid anchors
must serialize one exact recurrence matrix. The setup leaf is not padded into
or repeated by that matrix.

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

That is 545 bytes before versioning and framing. It is additional to the Nova
proof unless the final 32,768-term decision is moved inside the recurrence.
Moving that decision inside removes the public claim but makes every parent
proof pay for the linear generator work. The initial production format should
keep the explicit claim and benchmark the native decision.

The earlier nonrecursive secq backend had a compact logarithmic proof formula,
but it did not solve flat-circuit memory and is not the selected parent
backend. The current candidate receipt budget is:

```text
69 + 224 * anchor_count + 545 + canonical_nova_proof_bytes
```

The 69-byte header and 224-byte entries are a codec target, not an implemented
consensus format. At 100 anchors, the non-proof portion is 23,014 bytes. Adding
the tiny probe's 10,660-byte noncanonical proof-object measurement would give
33,674 bytes, but the production proof can be sized only after the exact
recurrence and canonical Nova codec exist. The explicit 545-byte root remains
mandatory unless the linear final decision moves inside the parent.

## Standalone secq verifier randomization

This section applies to the earlier standalone Bulletproof-cycle relation
backend, not to compressed Nova receipt verification. That backend combines
independent verification equations with a random scalar before its final MSM.
The scalar is a verifier soundness challenge, not secret prover randomness.
Bitcoin consensus verification must not vary with operating-system entropy.

The backend therefore seeds its verifier RNG with a domain-separated SHA-256
hash of the complete canonical circuit, statement, and proof, including length
framing. The Bulletproof library mixes that seed into its already proof-bound
Merlin transcript before sampling the equation coefficient. Every node derives
the same coefficient, while an altered circuit, statement, or proof derives a
different one. This is an intentional Fiat-Shamir transformation and relies on
the random-oracle model.

This rule remains required wherever that backend is used, but it is not the
Nova verifier specification. A future batch verifier for the standalone
backend must hash the complete ordered batch before deriving any coefficient.
It must not derive one coefficient and then accept later, adaptively selected
equations. Replacing the deterministic seed with `OsRng` would make consensus
acceptance depend on local state and is prohibited.

## Required negative tests

Before activation, end-to-end tests must reject at least:

- during registry registration, a changed setup record digest, setup proof,
  basis promotion, 545-byte seed root, or false native setup decision;
- a changed anchor reference, recovery root, context, or ciphertext;
- a changed initial manifest, nonzero initial index, or wrong resolved seed;
- a changed public V4 precommitment, or a manifest using the wrong derived
  coefficient commitment or anchored offset;
- a changed V4 proof point, scalar, round message, or proof length;
- a noncanonical scalar or point and every exceptional group case;
- a valid proof moved to a different ordered manifest;
- a removed, duplicated, reordered, or substituted child;
- a changed coefficient opening or accumulation transition;
- a later step using a different serialized recurrence matrix;
- a wrong step count or final index;
- a changed final manifest or any final root-state field;
- a Nova proof rebound to another initial or final state;
- a noncanonical compressed Nova encoding;
- a parent proof rebound to another root claim; and
- a valid parent proof followed by a false final native decision.

Benchmarks must separately report public-parameter generation, folding,
compression setup, compression, recursive verification, compressed
verification, peak RSS, canonical proof bytes, payload bytes, root bytes, and
native-decision time for 1, 2, and 100 anchors.
