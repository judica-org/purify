# Algebraic accumulation V2

This suite is a distinct typed protocol. It does not reinterpret version-1
proofs. `AlgebraicStepProof` and `AlgebraicNormReductionProof` are separate
C++ types, and their codecs require version byte `0x02`. The accepted SHA-256
suite retains its existing types and version byte `0x01`.

All points are parsed as canonical compressed SEC1, or the unique 33-byte zero
identity, before transcript absorption. Scalars are canonical secp256k1 group
scalars embedded into the coordinate field. Byte strings, scalars, points,
and integers use the typed frames in `AlgebraicTranscript`.

The coefficient reduction accepts only `AlgebraicPreparedNorm`. Its
`prepared_binding` is a canonical nonzero scalar that the production V4
relation must emit; the SHA digest carried by `PreparedNorm` is not part of
this suite. The staged `bind_algebraic_prepared_norm` factory only constructs
a short-reduction statement. It does not authenticate a caller-supplied
binding to a V4 child proof, so an eventual acceptance API must call it only
after V4 verification and will replace or hide that raw factory.

## Opening base

Both relations derive an opening base only after fixing the claimed
evaluation. For basis digest `d`, role `r`, and index `i`:

```
seed_i = TaggedSHA256(
    "Purify/BPPP/OpeningGeneratorPairV2",
    d || LE64(r) || U8(i))
U_i = PublicHashToPoint(seed_i)
u = SelectNonzeroScalar(transcript.OBAS(d, r))
U = U_0 + u U_1
```

Role 1 is coefficient reduction and role 2 is accumulation. The pair must be
non-identity and distinct, and `U` must not be the identity. `U` is appended
as a typed point after the non-mutating `OBAS` squeeze. The exact pair
derivation is shared with `opening-base-v2`; no known discrete-log relation is
introduced.

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
9. for every round, append points `L`, `R`, squeeze challenge at the
   zero-based round index, and append the selected scalar;
10. scalar terminal coefficient, point folded generator, point unshifted norm
    claim, typed norm polynomial, and typed folded polynomial;
11. squeeze and append the fusion scalar at index `round_count`.

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
5. squeeze challenge 0 and append batching scalar `beta`;
6. point batched commitment;
7. squeeze challenge 1 and append evaluation point `x`;
8. scalar batched evaluation `y`;
9. derive role-2 opening base and append point `U`;
10. for every round, append points `L`, `R`, squeeze challenge `2 + round`,
    and append the selected scalar.

The native entry point enforces the parent relation's limits of 1,024 claims
and 24 IPA rounds.

The terminal scalar and folded generator are checked by the short group
equation. The folded generator becomes the next pending claim.

## Cross-language fixture

`rust/receipt-cycle/tests/vectors/algebraic_accumulation_v2.json` freezes the
complete norm, opening-base, fusion, and accumulation contexts. It is produced
independently by `tests/reference_algebraic_accumulation.py`. Native tests bind
the complete deterministic proof encodings, while Rust tests replay every
typed challenge and opening-base squeeze from the same fixture.
