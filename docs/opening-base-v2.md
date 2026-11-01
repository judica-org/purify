# Candidate opening-base derivation

## Current boundary

The accepted accumulation format still derives a fresh point with
`purify_bppp_public_hash_to_point` in both places which run a public IPA:

- `make_norm_context` for every coefficient-opening reduction;
- `make_step_context` for every accumulation transition.

That construction hashes the complete opening statement before running the
vendored two-map SvdW generator function. Reproducing it exactly in the parent
therefore requires the exact SHA-256 transcript and three more SHA-256 calls
inside the generator map. Treating the resulting point as a prover input is
unsound.

The code in this change is a candidate V2 foundation. It does not change the
accepted V1 parser or claim that a V1 proof used the V2 relation.

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
vendored hash-to-curve map only while constructing the public circuit; SHA is
not evaluated by the circuit. The circuit contains the resulting coordinates
as constants. The verifier, not the prover, derives those constants from the
receipt version and exact basis digest.

After the basis, role, complete claim data, batched commitment `C`, evaluation
challenge `x`, and claimed evaluation `y` have been absorbed, a distinct
opening-base transcript item squeezes two coordinate-field lanes. Canonical
rejection selection returns the first lane in `[1,n-1]` as `u`. Then:

```text
U = U_0 + u U_1
```

The relation rejects identity `U`. Both the pair derivation and the scalar
squeeze bind the role, so a reduction opening cannot be replayed as an
accumulation opening.

The candidate no-SHA relation uses the typed Poseidon transcript. Activation
requires a matching native prover and verifier, new proof versions for both
reduction and step proofs, rejection of V1 bytes by V2 parsers and vice versa,
and native/Rust vectors over complete transcript preimages. Until those land,
V1 remains the only accepted suite.

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

## Alternatives

| Construction | Parent work | Security/review boundary |
| --- | ---: | --- |
| Fixed independent `U` | constant point | Standard IPA binding; no fresh post-claim point |
| `U_0 + u U_1` | scalar selection, one scalar multiplication, one add | Reuses existing scalar/group gadgets and preserves post-claim unpredictability |
| Poseidon-to-SvdW | two native-field maps and one add | Fewer expected gates, but introduces a bespoke algebraic hash-to-curve suite |
| Poseidon-to-RFC 9380 SSWU | hash-to-field, SSWU, isogeny, add | Familiar map, but Poseidon expansion is not the standardized secp256k1 suite |
| Exact V1 | several SHA blocks plus two SvdW maps | Exact today, but defeats the intended parent cost reduction |

The pair construction is preferred for reviewability. A fixed-base window
gadget can reduce its scalar-multiplication cost without changing the
protocol. The current generic scalar-multiplication probe uses 25,918 gates
and produces a 1,415-byte proof. Those figures are a baseline, not an
activation target: the fixed second generator permits constant precomputation
which the generic gadget does not exploit. Prover time and the optimized gate
count must be measured before activation.

The vector file `opening_base_pair.txt` pins both role domains. The independent
stdlib Python reference reconstructs the tagged hashes, vendored SvdW maps,
point pair, scalar multiplication, and final compressed point. A native C++
test independently reaches the same points through `TaggedHash`,
`purify_bppp_public_hash_to_point`, and `purify_bppp_public_msm`.
