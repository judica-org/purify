# Opening-base derivation V2

## Protocol boundary

Accumulation V2 derives an opening base in both places which run a public
IPA:

- `make_norm_context` for every coefficient-opening reduction;
- `make_step_context` for every accumulation transition.

V2 uses a transparent pair of public generators and a transcript-derived
scalar. The verifier derives the pair and the scalar; neither may be accepted
as an unconstrained prover input. V1 remains a separate proof format with a
separate parser and does not acquire V2 semantics.

## Transparent generator pair

For a fixed basis digest `d`, role `r`, and index `i` in `{0,1}`, define:

```text
s_i = TaggedSHA256(
    "Purify/BPPP/OpeningGeneratorPairV2",
    d || LE64(r) || U8(i))
U_i = PublicHashToPointV1(s_i)
```

Role 1 is coefficient reduction. Role 2 is accumulation. The derivation
rejects identity or duplicate points. It is transparent and reuses the exact
vendored hash-to-curve map while constructing the public circuit. The circuit
contains the resulting coordinates as constants. The verifier, not the
prover, derives those constants from the receipt version and exact basis
digest.

After the basis, role, complete claim data, batched commitment `C`, evaluation
challenge `x`, and claimed evaluation `y` have been absorbed, a distinct
opening-base fork computes:

```text
opening_digest = SHA256(
    state || pending ||
    "BYTE" || BE64(32) || basis_digest ||
    "OBAS" || BE64(role))
u = ClearBit255(opening_digest)
```

The derivation rejects zero. Clearing the high bit puts every accepted value
below the secp256k1 group order, so no modular reduction or retry is needed.
It does not advance the main transcript chain. Then:

```text
U = U_0 + u U_1
```

The relation rejects identity `U`. Both the pair derivation and the scalar
squeeze bind the role, so a reduction opening cannot be replayed as an
accumulation opening.

The main transcript uses the same typed, chained SHA-256 state machine.
Reduction and step proofs use version byte `0x02`, and their parsers reject V1
bytes. Native and constrained implementations replay the same transcript
preimages from shared vectors.

## Soundness argument

A single fixed independent `U` is conventional for an IPA. It is binding
under the discrete-log representation assumption when no party knows a linear
relation among `U` and the vector basis. In this protocol, `x` and every IPA
round challenge are also sampled after their preceding commitments, so using a
fixed `U` does not by itself expose a deterministic forgery.

The pair construction retains a stronger ordering property of V1. An invalid
claim fixed before `u` can contain chosen multiples of `U_0` and `U_1`, but it
cannot arrange their error to be a multiple of `U_0 + u U_1` without either:

- predicting the fresh nonzero `u`;
- finding a transcript collision; or
- knowing a discrete-log relation among `U_0`, `U_1`, and the basis.

For fixed nonzero error coefficients this succeeds for at most one `u`.
Security therefore uses the Fiat-Shamir random-oracle assumption plus the
algebraic-group/discrete-log independence of the domain-separated points.
The point pair must never be generated as known scalars times `G`.

Every coefficient IPA and every accumulation-step IPA is constrained
individually before it can contribute a pending claim. Reduction fusion uses a
later nonzero `chi`, and claim batching uses a nonzero `beta`. Reusing the
derivation scheme across proofs does not permit cross-proof error cancellation
because no verifier equation is omitted or combined before its own zero check.
The separate roles additionally prevent cross-protocol replay.

## Implementation cost

The pair construction needs one fixed-base scalar multiplication and one
point addition in the constrained relation. A fixed-base window gadget can
reduce that cost without changing the protocol. Production qualification
must measure the complete chained SHA-256 relation and this group operation;
gate counts from the removed field-hash design do not apply.

The vector file `opening_base_pair.txt` pins both role domains. The independent
stdlib Python reference reconstructs the tagged hashes, vendored SvdW maps,
point pair, scalar multiplication, and final compressed point. A native C++
test independently reaches the same points through `TaggedHash`,
`purify_bppp_public_hash_to_point`, and `purify_bppp_public_msm`.
