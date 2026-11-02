# Recursive construction receipt boundary

> Implementation note: the production recurrence uses the record-version-3
> public V4 anchor leaf and constrains its canonical punishment-key DLog
> equation. A deterministic two-anchor fixture has qualified the complete
> selected lifecycle: exact production-profile setup, two ordered full-scale
> folds, Spartan IPA compression, canonical verification, verifier-artifact
> serialization, and artifact reload. The external verifier artifact identity,
> private C ABI, and public C++ recursive-plus-native acceptance boundary are
> implemented. This is library acceptance, not consensus or enrollment
> activation.

This document fixes the selected boundary between a transparent Nova parent
proof and the native BP++ accumulator. It is an implementation map for the
library acceptance path, not a claim that construction receipts are active in
consensus or that coalition enrollment is safe to enable.

The acceptance result is a validity and ancestry result. It does not supply a
distributed setup or share-preserving child prover, resolve custody of a shared
coalition scalar, or prove pre-conflict confidentiality for the correlated
secp256k1 and companion-group keys. Those security obligations are separate
from recursive verification. Operational proving bounds at 100 to 1,000 anchors
and reduction or practical distribution of the roughly 609 MiB verifier also
remain open.

The parent must authenticate independently published anchor-escrow proofs. The
assembler learns no anchor or coalition secret. Child proof bodies, norm
reduction proofs, and accumulation transitions are witnesses to the parent and
can disappear after the final receipt is published.

## Target acceptance rule

The public C++ verifier returns an acceptance capability only when all three
checks succeed:

1. the setup reference resolves to one immutable, previously verified setup
   record and its canonical construction-basis seed claim;
2. the compressed Nova proof verifies the exact number of homogeneous anchor
   steps from that seed and returns a final manifest and index matching the
   payload-derived values; and
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

Every construction receipt then uses one fixed public-anchor matrix. For each
ordered anchor it performs the following operations:

1. Parse the fixed-shape V4 proof witness and validate every scalar and
   secp256k1 point encoding.
2. Reconstruct the exact anchor circuit and statement binding from public
   receipt data. No prover-supplied circuit digest or acceptance bit is used.
3. Replay the V4 precommitment and typed Poseidon proof transcript,
   including canonical two-lane nonzero challenge selection.
4. Constrain the public DLog response against the exact normalized punishment
   key resolved for that anchor. The key is statement data, not a new payload
   field.
5. Compute the inner norm residual point and its compact generator-weight
   polynomials from the terminal scalars and folding challenges.
6. Reconstruct the exact coefficient commitment obligation and verify the
   constrained coefficient-opening reduction. This produces one leaf
   `PendingClaim`; it does not accept the child by itself.
7. Verify one ordered two-claim accumulation transition from the previous root
   and this anchor leaf. The output root becomes the next step's input.

The recurrence state has exactly 20 primary-field elements: the root point's
SEC1 prefix and x coordinate, its scale and 15 folding factors, one rolling
Poseidon manifest field, and the ordered anchor index. The affine y coordinate
is private and constrained by the curve equation and prefix. The initial state
is derived by absorbing the manifest domain and version, construction statement
digest, resolved setup-record digest, seed root, and payload count. Each step
absorbs the prior manifest, zero-based index, exact statement binding, V4
precommitment, coefficient commitment, and anchored offset used by that leaf.
Final verification requires the expected step count, manifest, and index. It
then decodes the root carried by the verified final state and passes it directly
to the native decision. No intermediate state is an acceptance result.

The version-two typed Poseidon framing is exact. `m0` is lane zero of challenge
zero after appending, in order:

```text
BYTES("Purify/Accountable/ConstructionParentManifest/v2/init")
U64(2)
BYTES(construction_statement_digest32)
BYTES(resolved_setup_record_digest32)
BYTES(canonical_registry_seed_root545)
U64(nonzero_payload_anchor_count_u32)
```

Step `i` uses the separate
`Purify/Accountable/ConstructionParentManifest/v2/anchor` byte-string domain,
then appends `FIELD(m_i)`, `FIELD(i)`, the 32-byte binding digest, scalar `d`,
coefficient-commitment point, and anchored-offset point before taking lane zero
of challenge zero. The verifier derives `m0`, starts only at index zero, and
iterates the authoritative payload order; neither value is supplied by the
prover.

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
variable transcript-binding pieces are implemented. The homogeneous public
anchor recurrence, verifier-derived 20-field state, exact-shape Nova lowering,
canonical compressed-proof codec, fixed-template Nova session, verifier-only
artifact format, and authenticated-root verifier are also implemented.
Canonical suite-ID framing and exact static setup selection reject a changed
relation, parameter digest, matrix dimensions, codec schedule, or
construction-version tuple. The qualified two-anchor fixture executes exact
setup, both full-scale folds, full Spartan IPA compression, canonical proof
verification, artifact serialization, and artifact reload. The artifact's
frozen external identity is 638,174,560 bytes (roughly 609 MiB) with its
expected tagged digest compiled into the loader. A private C ABI can return
only the proof-authenticated pending root; the public C++ API parses that root
against the fixed native basis and completes `decide()` before minting an
acceptance capability.

The historical secq SHA-256 gadget costs 30,952 multipliers per
compression block, plus eight multipliers per private input byte.
Replaying V3 required approximately 34 blocks per anchor, or about
1,052,368 SHA multipliers per anchor before point, scalar, reduction, or
transition constraints. That fallback did not meet the hundred-member
budget. V4 now has native and Rust typed Poseidon implementations, so
these SHA counts are not V4 estimates.
A V4 leaf by itself is still not a construction receipt. Independently
published child proofs remain off-chain witnesses. The candidate payload
carries each 192-byte anchor ciphertext and its 32-byte nonzero V4
precommitment. The verifier derives the
leaf's expected coefficient commitment and anchored offset from that
precommitment and the exact resolved statement, while the recurrence manifest
binds those same constrained values. This gives a 224-byte entry before the
fixed receipt header and compressed parent proof.

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
implemented. The selected production suite has completed the two-anchor
lifecycle through compression and canonical verification. The internal Nova
session checks the verifier-derived initial state, exact step count, state
continuity, and expected final state before and after compression. The private
C ABI exposes only the authenticated pending root, and the public C++ verifier
completes the mandatory native decision before returning acceptance.

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

The production-shape V4 public setup leaf is exactly 854,293 gates. The
historical hidden anchor leaf is exactly 949,880 gates. Both fall in the
standalone secq backend's 1,745-byte proof-length bucket. That bucket does not
predict compressed Nova size. These are leaf relation sizes, not the selected
public-anchor recurrence.

The complete selected recurrence is now frozen by relation ID:

```text
ecfd8e56084083ba9a94431fad5a5b1e0991d7597746440e76ccf77924444a66
```

Its source relation has 1,851,594 gates, 3,813,632 rows, and 14,293,837 terms.
Direct Nova lowering produces 1,851,594 variables, 1,962,058 constraints, and
a 12,552,747-nonzero upper bound. The raw step remains in the `2^21` bucket
with 135,094 constraints of headroom before Nova's fixed wrapper.

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
backend. The implemented fixed-template session owns one exact relation,
rejects structural drift, checks state continuity and the exact step count,
verifies the recursive result before compression, and verifies a canonical
fixed-length Spartan IPA proof against the exact initial and final states.
Canonical decoding rejects the wrong length, sequence schedule, malformed
field or point encodings, trailing bytes, and noncanonical re-encoding.
The suite can be consumed into a verifier-only context and serialized as a
versioned deployment artifact. Loading first authenticates the frozen
638,174,560-byte length and tagged digest
`7b2fcafb6475c870925c2c00b0ab9eba539bc540e34db14678cf005213bdebd5`,
then checks the suite ID, arity, payload length, and exact local profile. The
artifact remains an external deployment object; its roughly 609 MiB footprint
is not yet suitable for convenient embedding in the main binary.

Nova 0.76's fixed arity-20 wrapper adds exactly 13,566 primary constraints and
13,596 primary variables to this recurrence. The production primary
shape is therefore 1,975,624 constraints and 1,865,190 variables in `2^21`.
The secondary shape is fixed at 10,787 constraints and 10,769 variables in
`2^14`. These dimensions leave 121,528 primary constraints and 231,962 primary
variables of padded headroom. For the pinned canonical codec, they imply:

```text
1,676 + 20*32 + 290*(21 + 14) = 12,466 bytes
```

The proof has exactly 125 locally selected sequence lengths. The selected
native profile freezes public-parameter digest:

```text
b90f7e761288cc1fdb7abd16f4e0abbbe2c8d7c773f315a17f1d7c4f982f7900
```

Its suite ID is:

```text
116fbf3345173dbedfd53e3ebe0e2acbffe7b7719df794f6c7cfa27314bdd5aa
```

Exact setup, two ordered full-scale folds, Spartan IPA compression, and
canonical verification have qualified against the relation, parameter digest,
dimensions, complete codec schedule, and explicit
payload/statement/manifest/native-decision versions. The resulting positive
proof is 12,466 bytes. This is a selected library suite, not consensus or
enrollment activation.

The separate reduced-size 20-state, two-step session fixture exercises setup,
folding, recursive verification, compression, canonical encode/decode, and
compressed verification. Its primary shape is 13,606 constraints and 13,636
variables; its secondary shape is 10,787 constraints and 10,769 variables. Its
canonical proof is 10,436 bytes with 104 sequence lengths. Pinning the bounded-memory
Nova fork left its relation ID, public-parameter digest, dimensions, proof
length, and codec schedule unchanged.

Cargo pins the qualified bounded-memory fork at revision
`ef88da858d1b7ade8fe4b36b585436adbde672ae`. It releases `ShapeCS` before
commitment-key generation, shares one padded Spartan shape between
setup-created prover and verifier keys, and replaces duplicated sparse-matrix
field-element caches with compact classes over the existing CSR entries. Its
tests preserve the key bytes and verifier-key digest and pass the real
non-preprocessing Spartan IPA compression path. The exact-shape witness builder
also streams every later operation and row against the immutable template
instead of materializing a second relation. The two-anchor production
lifecycle qualified with this revision; those results do not establish proving
throughput or peak-memory bounds at 100 to 1,000 anchors.

A staged setup-only harness preserves the production ratios of variables,
constraints, and nonzeros. Every synthetic stage through `2^20` passed under
its memory ceiling with zero swap:

| Primary bucket | Constraints / variables | Proof bytes / sequences | Setup | Peak RSS |
| ---: | ---: | ---: | ---: | ---: |
| `2^16` | 61,738 / 59,055 | 11,016 / 110 | 4.22 s | 163,414,016 B |
| `2^17` | 123,476 / 117,318 | 11,306 / 113 | 7.08 s | 275,087,360 B |
| `2^18` | 246,953 / 233,843 | 11,596 / 116 | 12.54 s | 455,507,968 B |
| `2^19` | 493,906 / 466,892 | 11,886 / 119 | 23.80 s | 764,968,960 B |
| `2^20` | 987,812 / 932,991 | 12,176 / 122 | 46.06 s | 1,490,878,464 B |

The secondary shape remained fixed at 10,787 constraints and 10,769 variables.
Each stage also froze its deterministic public-parameter digest. These are
synthetic setup results, not production proofs.

The guarded production run completed exact native-profile setup, two ordered
folds, recursive verification, Spartan IPA compression, canonical compressed
verification, artifact serialization, and artifact reload. Qualification is
deliberately narrow: it proves the complete two-anchor path and freezes its
12,466-byte proof and external verifier identity. It does not measure issuance
at 100 to 1,000 anchors, provide a public issuance workflow or the distributed
child proving needed for shared custody, or make the roughly 609 MiB verifier
practical to embed.

For historical context, the earlier pre-canonical scaling probe used
independent multiplication gates and noncanonical bincode proof-object sizes:

| Gates | Bincode bytes | Primary constraints / variables | Pipeline | Peak RSS |
| ---: | ---: | ---: | ---: | ---: |
| 1,024 | 10,660 | 12,488 / 13,503 | 4.298 s | 143,409,152 B |
| 16,384 | 11,288 | 43,208 / 59,583 | 9.144 s | 289,062,912 B |
| 65,536 | 11,916 | 141,512 / 207,039 | 30.994 s | 737,148,928 B |

Those object sizes are retained only as historical feasibility evidence. They
do not size the selected receipt and are superseded for wire-format accounting
by the canonical codec above.

The heterogeneous public setup leaf is resolved by the immutable setup
registry described above. Per-anchor binding digests, precommitments,
punishment keys, coefficient commitments, and offsets are statement or
assignment values authenticated by the rolling manifest, so different valid
anchors use one exact public-anchor recurrence matrix. The setup leaf is not
padded into or repeated by that matrix.

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

That is 545 bytes in the native root codec. Nova already serializes its complete
final state and returns it after verification, so the receipt must not duplicate
those 545 bytes outside the compressed proof. The verifier converts the 18 root
state fields into the native codec and runs the linear decision. Moving that
decision inside the recurrence would instead make every parent proof pay for
the linear generator work.

The earlier nonrecursive secq backend had a compact logarithmic proof formula,
but it did not solve flat-circuit memory and is not the selected parent
backend. The current candidate receipt budget is:

```text
69 + 224 * anchor_count + 12,466
```

The 69-byte header, 224-byte entries, and exact 12,466-byte Nova envelope are
implemented transport components. The envelope is exactly `payload || proof`;
its parser establishes canonical syntax only. The proof shape is independent
of the number of folded steps. At 100 anchors the candidate total is therefore
34,935 bytes: 22,469 payload bytes plus the proof. No separate 545-byte root is
included. The Rust verifier returns that pending root only after checking the
proof and payload-derived final state. The public C++ verifier then parses it
against the fixed basis and completes mandatory native `decide()` before
returning `VerifiedConstructionReceipt`. Neither the compact size nor library
acceptance activates consensus.

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

The checked-in two-anchor adversarial vector covers the final case directly.
It preserves the positive vector's public construction inputs and passes the
selected recursive verifier, but authenticates a distinct pending root which
fails native `decide()`. The public C++ API rejects it before an acceptance
capability can be constructed.

Benchmarks must separately report public-parameter generation, folding,
compression setup, compression, recursive verification, compressed
verification, peak RSS, canonical proof bytes, payload bytes, root bytes, and
native-decision time for 1, 2, 100, and intended upper-bound workloads such as
1,000 anchors. Only the two-anchor full lifecycle is currently qualified.
