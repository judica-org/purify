# Public accumulation of norm obligations

`purify/accumulation.hpp` implements a public accumulation step for the
standalone BP++ norm verifier. A helper consumes completed public proofs,
combines their pending generator equations through a one-vector inner-product
opening, and produces one new pending equation. A final native MSM discharges
that equation. The helper never receives the original norm witnesses.

This is an accumulation component, not a compressed construction receipt.
Native callers still replay the child partial verifiers and every accumulation
transition. A future recursive proof must authenticate those computations
before their transcripts can be discarded. The existing experimental
arithmetic-circuit wrapper's soundness defects remain a separate prerequisite;
this implementation does not use that wrapper to prove accumulation.
It operates on already-public proof data and does not turn the standalone
norm argument into a zero-knowledge leaf.

## Exact grouping rule

A `Basis` fixes the norm length `g`, linear length `h`, semantic domain, and
deterministic generator stream. Both lengths are nonzero powers of two and
`g >= h`. Different canonical coefficient vectors `c`, `rho` values, initial
commitments and witnesses may share this basis. Different dimensions or
semantic domains may not. This does not combine different proof types by
silently interpreting their statements as equivalent.

Each child has a public coefficient-opening argument. Native preparation
reconstructs its coefficient commitment from the child's exact canonical `c`;
the caller cannot supply an unchecked replacement commitment. This removes
the previous requirement that every proof have the same `c`. Applications
still authenticate how their statement and transcript determine those values.

The semantic domain separates accumulation transcripts. The raw standalone
`NormArgProof` does not authenticate that domain. Applications must authenticate
the child statement and its role before calling `prepare_norm`, including
the exact manifest, coalition identity and context. A valid proof for a
subset does not establish coverage of an externally required manifest.

## Reduce a norm proof to one pending commitment

Use `B` for secp256k1's standard generator, and `G_i,H_i` for the norm bases.
Use the unshifted deterministic bases:

```
K = (G_0,...,G_(g-1), H_0,...,H_(h-1), padding...)
```

`K` has length `D=2g`. Padding uses further independent points from the
deterministic generator stream, with zero coefficients, never identity bases.
All basis points are finite. No trusted ceremony or secret setup is involved.

For terminal norm scalars `a,b` and the original low-bit-first folding
challenges `gamma_j`, define:

```
f_G(X) = a rho^(g-1) product_j(1 + gamma_j rho^(-2^j) X^(2^j))
f_H(X) = b product_(j<log2(h))(1 + gamma_j X^(2^j))
f(X)   = f_G(X) + X^g f_H(X)
```

Preparation uses the original transcript and compressed round-point parser to
compute the short side of the norm equation:

```
T = C + sum_j(gamma_j X_j + (gamma_j^2-1) R_j)
      - a^2 rho^(2g) B
```

The outstanding equation also contains the public coefficient evaluation:

```
w_i = product_(j<log2(h)) gamma_j^bit_j(i)
z = <c,w>
T0 = T - b z B = <coefficients(f), K>
```

`prepare_norm` returns a privately constructed `PreparedNorm`, containing the
authenticated coefficient commitment `Cc=<c,H>` and norm transcript binding.
It does not return an independently usable pending norm claim. Parsing a
changed statement may succeed while its equation is false, so preparation is
explicitly not acceptance.

## Public coefficient opening

`prove_norm_reduction` uses only the published `c` and norm proof to open:

```
Cc + z U = <c,H> + <c,w> U
```

The fresh opening point `U` binds the basis, exact prepared norm and claimed
evaluation `z`. The same half-splitting IPA used below applies to `c,H,w`.
It has `log2(h)` rounds. Its folded evaluation weight is computable without
expanding `w`; the serialized terminal scalar is instead the folded `c` value:

```
w_final = product_r(t_r^-1 + t_r gamma_(log2(h)-1-r))
```

After checking the short IPA equation, verification has two obligations:
the norm equation for `T0`, and the folded-H generator equation. The API
combines them with a fresh nonzero challenge `chi` derived after both complete
claims and the full norm/opening transcript are fixed:

```
T_combined = T0 + chi H_final
f_combined = f + chi X^g s_H
```

Here `s_H` is the compact polynomial of coefficient-opening generator weights.
`verify_norm_reduction` returns exactly one `PendingClaim`, containing these
three terms. A caller cannot accidentally retain the norm obligation while
dropping the coefficient-opening obligation. If either equation is false,
the fixed pair of errors cancels for at most one nonzero `chi`; Fiat-Shamir
composition still requires the stated random-oracle assumptions and review.

Coefficient preparation costs a native linear-size MSM per child. The public
opening prover also does linear generator work. The opening's short equation
uses logarithmically many proof points. A future recursive parent must
authenticate the derivation of `c` and `Cc`, including any dependence on child
messages. This native API has not compressed or eliminated that requirement.

The raw-basis digest uses `Purify/BPPP/NormAccumBasisV2`, binding the framed
semantic domain, `g,h` and all `2g` canonical points. The prepared statement
uses `Purify/BPPP/NormReduction/StatementV1` over that digest, `rho`, the initial
commitment, all `h` canonical coefficients, computed `Cc`, and the length-framed
original proof. Sizes are unsigned 64-bit little-endian; scalars are 32-byte
big-endian. Basis-authenticated dimensions fix the coefficient array's length.
The coefficient opening and fusion have separate `OpeningBaseV1`, `OpeningV1`
and `FusionV1` tags under `Purify/BPPP/NormReduction/`. Fusion includes the
complete opening bytes and both complete pending equations before sampling
`chi`. New nonzero challenges use canonical rejection sampling, never reduction
modulo the scalar field.

## Public accumulation step

The step consumes an ordered nonempty list of claims `(T_i,f_i)` on the same
basis. It hashes their complete canonical descriptions and the basis digest,
then derives a nonzero batching challenge `beta`:

```
C = sum_i beta^i T_i
f = sum_i beta^i f_i
```

After fixing these inputs, derive a nonzero evaluation challenge `x` and
compute `y=sum_i beta^i f_i(x)`. Each input polynomial is a sum of at most three
compact products, so evaluating it does not expand its coefficient vector.
Derive a fresh opening point `U` by the vendored hash-to-curve generator map,
binding the complete claim digest, `beta,C,x,y`. A fixed opening base, or a
claimed group result provided without its obligation, is not substituted.

The helper expands the public coefficients `v=coefficients(f)`, sets
`w=(1,x,...,x^(D-1))`, and proves the one-vector inner-product opening:

```
P = C + y U = <v,K> + <v,w> U
```

At each half-splitting round it publishes:

```
L = <v_L,K_R> + <v_L,w_R> U
R = <v_R,K_L> + <v_R,w_L> U
```

After deriving nonzero `t` from the preceding transcript and these points:

```
v' = t v_L + t^-1 v_R
w' = t^-1 w_L + t w_R
K' = t^-1 K_L + t K_R
P' = t^2 L + P + t^-2 R
```

The step verifier checks the final short equation using the terminal scalar
and claimed folded generator. It computes the compact polynomial `s` whose
coefficients are the generator-folding weights, and returns the new obligation
`K_final = <coefficients(s), K>`. Half-splitting consumes the highest index bit
first, so `s` stores the squared challenges in reverse round order and has
scale `product(t^-1)`.

This is the polynomial-opening accumulation approach described by
[Halo](https://eprint.iacr.org/2019/1021), the
[formal accumulation framework](https://eprint.iacr.org/2020/499), and the
[Pickles accumulation specification](https://o1-labs.github.io/proof-systems/pickles/accumulation/).
Our concrete transcript and norm adapter still require cryptographic review.
The intended argument uses discrete-log binding, random-oracle challenges,
polynomial identity testing and the IPA reduction. Batching has negligible
soundness error, not an unconditional implication for every random challenge.

## Final decision and native caller flow

`verify_step` returns another `PendingClaim`, with no conversion to accepted
status. `decide` expands its coefficients and checks one native fixed-basis
MSM. A successful decision discharges the supplied obligation; it does not
authenticate omitted ancestors or application metadata.

```
authenticate exact child statements and intended coverage
prepare_norm for each completed child
verify_norm_reduction for each public coefficient-opening proof
verify every public accumulation transition
decide the final pending claim
```

Inputs may be combined in one wide step or a tree. A 100-leaf binary tree has
99 combination steps and seven levels when odd final nodes are carried up.
Only the final node needs the full decision, but all transitions must be
verified. A root claim by itself is not evidence that those transitions ran.

The expensive generator work belongs to the public prover and final decision.
The step verifier performs work proportional to the number of input claims
times the logarithm of the basis dimension, plus a small proof-point MSM.
Basis generation, public-data hashing and native norm preparation are separate
costs; the benchmark reports them rather than counting only the short step.
All new group arithmetic is variable-time on public data. It is not a new
secret-key proving API.

## Canonical proof encodings

The authenticated basis determines the round count. Version 1 is:

```
version:u8 || (L33 || R33)[log2(D)] || terminal_scalar32 || folded_generator33
```

Scalars are canonical big-endian elements of secp256k1's scalar field. Points
are canonical compressed SEC1, or exactly 33 zero bytes for infinity. The
parser checks exact length before allocation and rejects unsupported versions,
noncanonical scalars/points, truncation and trailing bytes. Round infinity is
valid; basis generators and the original norm commitment must be finite.

The encoded step is `66*log2(D)+66` bytes, independent of its input-claim count:

| Norm length g | Padded basis D | Step bytes |
| ---: | ---: | ---: |
| 4,096 | 8,192 | 924 |
| 32,768 | 65,536 | 1,122 |

These are step bytes. They exclude retained child/transition statements,
application coverage and recovery ciphertexts. They are not a final on-chain
receipt size.

The separately typed coefficient-reduction codec uses:

```
version:u8 || z32 || (L33 || R33)[log2(h)] || terminal_scalar32 || folded_generator33
```

Its version is also 1, with an exact length of `66*log2(h)+98` bytes. At
`h=16384`, this is 1,022 bytes per child. The different exact lengths and
transcript domains prevent interpreting an accumulation step as a coefficient
opening. Both parsers validate syntax only. An application must still use
the appropriate verifier and finish with the accumulator decision.

These openings are additional public transition data. Native verification
retains them alongside the original child proofs; a final 1,122-byte step
does not replace that history. Recursive authentication is the remaining
mechanism needed to discard it in an on-chain construction receipt.

## Historical shared-coefficient measurements

These measurements describe the previous shifted-basis implementation at
commit `93e0bad`, before coefficient openings. They do not measure the
additional per-child preparation and opening work introduced here.

Single local runs on macOS arm64, AppleClang 16.0.0.16000026, C++20 Release
`-O3`, used `g=32768,h=16384,D=65536`. Both serialized steps were 1,122 bytes.
[Raw results](../bench/results/norm-accumulation-arm64.json) include setup,
codec and retained-input sizes. Peak memory was not measured.

| Stage | 2 inputs | 100 inputs |
| --- | ---: | ---: |
| Shared basis creation | 1.760 s | 1.715 s |
| Independent leaf publication, sequential | 2.959 s | 125.736 s |
| Public norm preparation | 0.257 s | 12.140 s |
| Public accumulation proving | 4.609 s | 4.217 s |
| Short step verification | 0.401 ms | 1.515 ms |
| Mandatory final decision | 327.873 ms | 284.398 ms |

The 100-input run retained 103,900 bytes of child norm proofs, or 110,400
bytes including their rho and initial commitments. The shared explicit
c-vector occupies 524,288 bytes in memory. Its meaning and derivation must be
authenticated; it is not included in the step wire size. The measurements
cover synthetic standalone norms, not encryption circuits or final receipts.
The small prover-time difference between runs is not evidence of speedup
with more inputs. Norm preparation still parses/hashes the original public
arrays for every child; that cost has not disappeared into the short verifier.

The commands below run the current varying-coefficient benchmark. Reproducing
the historical table requires checking out `93e0bad` first.

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DPURIFY_CXX_STANDARD=20 -DPURIFY_BUILD_BENCH=ON
cmake --build build --target bench_norm_accumulation -j 4
./build/bench_norm_accumulation --claims 2 --norm-size 32768 --linear-size 16384
./build/bench_norm_accumulation --claims 100 --norm-size 32768 --linear-size 16384
```

The benchmark bounds claims to 1,000 and norm length to 32,768. It clears
the original witness vectors before public accumulation begins. Its default
CTest workload does not include these large benchmark runs.

## Reproduction and completion boundary

```
cmake --build build -j 4
ctest --test-dir build -R norm_accumulation --output-on-failure
python3 tests/reference_norm_accumulation.py
```

The C++ suite covers independent public publication with different coefficients,
singleton/equal/unequal dimensions, 100 inputs and a binary tree, zero
coefficients and identity rounds, exact-basis and transcript binding, both
canonical codecs and fixed-proof mutation rejection.
The stdlib-only Python reference independently reconstructs generator mapping,
curve arithmetic, hashing and the complete small-fixture transcript. Its
canonical reduction SHA256 is
`430ba5e3a0183d278ad3cb5251d081f70b27586db3e407a899b59660c8d59d87`;
the final step SHA256 is
`b3a14ad17548fed019e02a5d90063be232826750d1f5987a72b22013585f7b1b`.

Remaining work for construction receipts is specific: repair/select a sound
leaf circuit argument; authenticate the frontend's coefficient derivation; constrain
partial verification and accumulation transitions in a recursive proof; bind
exact registry coverage; and enforce final accumulator decision. Encryption
privacy and signing security remain their own protocol obligations. Daybreak
work remains deferred.

Publishing a coefficient seed and binding it to the child transcript remains
a possible byte/preprocessing tradeoff. It requires a sound outer transcript
and an authenticated derivation; a seed alone does not establish the relation.
