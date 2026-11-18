# Algebraic accumulation V2

Algebraic accumulation reduces ordered V4 norm obligations to one fixed-basis
multiscalar multiplication (MSM). A pending claim `(T, f)` represents the
equation `T = MSM(K, coefficients(f))`. Application acceptance requires
authenticating the transitions that produced the claim and calling
`decide()` to check the equation. The
[construction receipt](construction-receipt.md#parent-relation-and-acceptance)
authenticates those transitions with a recursive parent proof.

## Basis and V4 preparation

A basis fixes nonzero power-of-two norm and linear lengths `g >= h`, a
semantic domain, and `D = 2*g` points `K = (G_i, H_i, padding)` from the
deterministic generator stream. The basis digest is tagged SHA-256 under
`Purify/BPPP/NormAccumBasisV2` over the length-prefixed domain, `g`, `h`,
and all `D` compressed SEC1 points. The length and dimensions are LE64.

[V4 preparation](sha256-circuit-transcript-v4.md#native-boundary-and-constrained-requirements)
authenticates the outer proof and produces the nonzero `prepared_binding`.
The accumulation adapter matches the exact raw basis points and their
digest, reconstructs the inner norm residual, and commits to the exact
canonical coefficient vector `c` as `Cc = <c, H>`. The reduction transcript
binds the application-selected semantic domain via the basis digest.

A compact term `(scale, offset, factors)` denotes
`scale * X^offset * product_j(1 + factors[j] * X^(2^j))`.
Write `B` for the standard generator, `a,b` for the terminal norm scalars,
`gamma_j` for the round challenges, and `C` for the combined commitment.
The residual `T` and the two raw-basis polynomial terms are given below.

```text
T = C + sum_j(gamma_j X_j + (gamma_j^2 - 1) R_j) - a^2 rho^(2g) B
f_G(X) = a rho^g lambda^-1 (1 + gamma_0 s^-1 X)
         product_(j>=1)(1 + gamma_j z^(-2^(j-1)) X^(2^j))
f_H(X) = b product_(j<log2(h))(1 + gamma_j X^(2^j))
f(X)   = f_G(X) + X^g f_H(X)
```

Here `lambda` and `z` are the V4 multiplication scale and ratio, and `s`
is the fixed even square root of -1. The pending equation still includes
the coefficient opening described below.

All transcript points are canonical compressed SEC1 or the unique 33-byte
zero identity. Scalars are canonical secp256k1 group scalars. Byte strings,
scalars, points, and integers use the typed frames in `Sha256Transcript`.

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

The transcript absorbs the following fields in order.

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

The coefficient opening uses the `H` slice of the basis. Its public tensor
weights are `w_i = product_j gamma_j^bit_j(i)` for `0 <= i < h`.
The IPA checks the short equation for `Cc + e U`, where `e = <c,w>`.
The norm claim then has point `T0 = T - b e B` and polynomial `f`.
The coefficient-opening claim has point `H_final` and polynomial
`X^g s_H`, where `s_H` encodes the IPA's generator-folding weights.
The final challenge `chi` binds both obligations. Reduction returns
`(T0 + chi H_final, f + chi X^g s_H)` as one pending claim.

## Accumulation-step transcript

The transcript absorbs the following fields in order.

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

The step combines the ordered claims into `C = sum_i beta^i T_i` and
`f = sum_i beta^i f_i`. With `y = f(x)`, it verifies an IPA for
`C + y U` over `K` and evaluation weights `(1, x, ..., x^(D-1))`.
The folded generator and its weight polynomial form the new pending claim.

## Inner-product opening

Both openings use half-splitting on witness scalars `v`, public weights
`w`, and the applicable basis slice `K`. Each round uses these equations.

```text
L  = <v_L, K_R> + <v_L, w_R> U
R  = <v_R, K_L> + <v_R, w_L> U
v' = t v_L + t^-1 v_R
w' = t^-1 w_L + t w_R
K' = t^-1 K_L + t K_R
P' = t^2 L + P + t^-2 R
```

Here `t` is the challenge derived after absorbing `L,R`. The verifier
checks `P_final = v_final * (K_final + w_final U)`. The term encoding the
remaining generator obligation has scale `product(t^-1)` and factors
`t^2` in reverse round order. The coefficient reduction places that term
at offset `g`, and the accumulation step uses offset zero.

## Wire encodings and decision

Both proof codecs require version byte `0x02`. The basis fixes the
round count and exact length.

```text
step      = 0x02 || (L33 || R33)[log2(D)] || terminal32 || folded_point33
reduction = 0x02 || evaluation32 || (L33 || R33)[log2(h)] ||
            terminal32 || folded_point33
root      = point33 || scale32 || factors32[log2(D)]
```

The root is a single term at offset zero. Its codec imports the basis
from the caller and validates only its shape and encodings. Receipt
verification authenticates the root and its ancestry before
`decide()` expands the coefficients and checks the fixed-basis MSM.

## Cross-language fixture

`rust/construction-parent/tests/vectors/sha256_accumulation_v2.json` freezes the
complete norm, opening-base, fusion, and accumulation contexts. It is produced
independently by `tests/reference_sha256_accumulation.py`. Native tests bind
the complete deterministic proof encodings. A constrained parent must replay
every typed challenge and opening-base fork from the same fixture.
