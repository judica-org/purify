# Algebraic accumulation V2

This suite is a distinct typed protocol. It does not reinterpret version-1
proofs. `AlgebraicStepProof` and `AlgebraicNormReductionProof` are separate
C++ types. Their codecs require version byte `0x02`. The older untyped
SHA-256 suite retains separate types and version byte `0x01`; it is not a
compatibility path for V4 receipts.

This suite reduces authenticated obligations to one final native
decision. It does not recursively prove their ancestry or turn
independently published child proofs into one constant-size receipt.
Native equation batching keeps the child proof payloads even when it
shares a final multiscalar multiplication.

All points are parsed as canonical compressed SEC1, or the unique 33-byte
zero identity, before transcript absorption. Scalars are canonical
secp256k1 group scalars. Byte strings, scalars, points, and integers use the
typed byte frames in `Sha256Transcript`.

The coefficient reduction accepts only `AlgebraicPreparedNorm`. Its
`prepared_binding` is the canonical nonzero scalar emitted by V4. The
SHA digest carried by `PreparedNorm` is not part of this suite. There is
no public factory which binds caller-supplied prepared components or a
caller-selected V4 scalar.

The internal V4 adapter consumes an opaque
`PreparedCircuitZkNormArgV4`. It checks every raw generator and its
transcript digest, replays the explicit-gamma residual, recomputes the
coefficient commitment, and emits the two Rust compact polynomial terms.
The purpose-owned caller selects the `Basis` semantic digest; V4 itself
authenticates the raw points, not arbitrary application-domain text.

Prepared objects may be reused. Safety comes from the exact bridge and
the reduction transcript's semantic-digest binding, not single use.
Outer preparation and adaptation are not acceptance. Successful
reduction verification, every authenticated step, and final `decide()`
remain mandatory.

## Opening base

Both relations derive an opening base only after fixing the claimed
evaluation. For basis digest `d`, role `r`, and index `i`:

```
seed_i = TaggedSHA256(
    "Purify/BPPP/OpeningGeneratorPairV2",
    d || LE64(r) || U8(i))
U_i = PublicHashToPoint(seed_i)
opening_digest = SHA256(
    state || pending ||
    "BYTE" || BE64(32) || d ||
    "OBAS" || BE64(r))
u = ClearBit255(opening_digest)
U = U_0 + u U_1
```

Role 1 is coefficient reduction and role 2 is accumulation. The opening
scalar must be nonzero. The pair must be non-identity and distinct, and `U`
must not be the identity. `U` is appended as a typed point after the
non-mutating `OBAS` fork. The exact pair derivation is shared with
`opening-base-v2`; no known discrete-log relation is introduced.

## Coefficient reduction transcript

The transcript order is:

1. bytes `Purify/BPPP/CandidateNormReduction/v2`;
2. bytes basis digest;
3. `u64` coefficient-opening round count;
4. scalar algebraic prepared binding;
5. point coefficient commitment;
6. the typed one-term tensor polynomial;
7. scalar claimed coefficient evaluation;
8. derive role-1 opening base and append point `U`;
9. for every round, append points `L`, `R`, then derive the challenge at the
   zero-based round index;
10. scalar terminal coefficient, point folded generator, point unshifted norm
    claim, typed norm polynomial, and typed folded polynomial;
11. derive the fusion scalar at index `round_count`.

The fusion scalar combines the original norm obligation and authenticated
coefficient-opening obligation into one pending claim. A successful short
verification is not final acceptance; `decide()` must still discharge the
resulting fixed-basis obligation.

## Accumulation-step transcript

This order exactly matches the Rust candidate parent relation:

1. bytes `Purify/BPPP/CandidateAccumStep/v1`;
2. bytes basis digest;
3. `u64` IPA round count and `u64` claim count;
4. for every ordered claim: point, term count, and each typed term's scalar
   scale, `u64` offset, factor count, and scalar factors;
5. derive batching scalar `beta` as challenge 0;
6. point batched commitment;
7. derive evaluation point `x` as challenge 1;
8. scalar batched evaluation `y`;
9. derive role-2 opening base and append point `U`;
10. for every round, append points `L`, `R`, then derive challenge
    `2 + round`.

Every challenge installs its full 256-bit SHA-256 digest as the next chain
state and clears pending data. The 255-bit scalar image is not appended: it
is already determined by that state.

Algebraic prepared binding, coefficient reduction, and accumulation steps all
reject bases requiring more than 24 full-basis IPA rounds. Accumulation steps
also enforce the parent relation's limit of 1,024 claims.

The terminal scalar and folded generator are checked by the short group
equation. The folded generator becomes the next pending claim.

## Cross-language fixture

`rust/receipt-cycle/tests/vectors/sha256_accumulation_v2.json` freezes the
complete norm, opening-base, fusion, and accumulation contexts. It is produced
independently by `tests/reference_sha256_accumulation.py`. Native tests bind
the complete deterministic proof encodings, while Rust tests replay every
typed challenge and opening-base fork from the same fixture.
