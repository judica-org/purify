# Public accumulation of norm obligations

`purify/accumulation.hpp` implements a public accumulation step for the
standalone BP++ norm verifier. A helper consumes completed public proofs,
combines their pending generator equations through a one-vector inner-product
opening, and produces one new pending equation. A final native MSM discharges
that equation. The helper never receives the original norm witnesses.

This native helper is an accumulation component, not a compressed construction
receipt. Native callers using it alone still replay the child partial verifiers
and every accumulation transition. The selected construction-parent recurrence
now authenticates those computations recursively so their transcripts can be
discarded after receipt construction; its public C++ acceptance path still
completes the final native decision.

V4 is the candidate active circuit-leaf path. Its native producer,
preparer, verifier, and constrained relation are implemented. The
internal `prepare_v4_circuit_norm_for_algebraic_reduction` adapter
converts an outer-authenticated V4 leaf into the same algebraic
accumulation language. The result remains pending until coefficient reduction,
every accumulation transition, and `decide` succeed. This native adapter alone
does not turn an accumulation root into a recursive construction receipt; the
selected Nova parent and C++ acceptance boundary perform that separate
authentication.

## Exact grouping rule

A `Basis` fixes the norm length `g`, linear length `h`, semantic domain, and
deterministic generator stream. Both lengths are nonzero powers of two and
`g >= h`. Different canonical coefficient vectors `c`, `rho` values, initial
commitments and witnesses may share this basis. Different dimensions or
semantic domains may not. This does not combine different proof types by
silently interpreting their statements as equivalent.

The V4 adapter consumes only an opaque value returned by V4 preparation.
Preparation authenticates the outer transcript and, in public mode, the
batched DLog equation. It does not accept the inner norm argument. The
adapter then exact-matches the raw generator points and their digest
against the selected basis, replays the explicit-gamma residual,
recomputes `Cc` from the canonical coefficient vector, and emits the
exact two compact polynomial terms used by the constrained leaf.

The caller owns the basis semantic digest. V4 authenticates the raw
points and their digest, not arbitrary purpose text. The same
authenticated prepared obligation may be promoted under another semantic
digest when the raw points match. A coefficient-reduction proof for one
digest cannot replay under the other. Safety does not depend on
linearity or single-use ownership of the prepared value. The generic
`prepare_norm` API still requires its proof generators to equal the
basis directly and cannot bypass these checks.

### Historical V3 circuit adapter

The construction-specific V3 adapter accepts only the circuit API with
explicit public commitment points. It verifies the mandatory batched
DLog proof before producing a prepared norm, validates that the
circuit's raw generator-stream digest equals the selected basis, and
replays the complete outer transcript. The inner norm equation remains
pending until the normal coefficient opening and final decision run.

For norm index `i`, V3 uses the fixed even `s` with `s^2=-1` and the
public scales:

```
T_(2k)   = lambda z^k
T_(2k+1) = s lambda z^k
G'_i     = rho^(i+1) T_i^-1 G_i
```

If `a` is the terminal norm scalar and `gamma_j` are the inner folding
challenges, the adapter represents the same obligation on raw `G_i` with:

```
f_G(X) = a rho^g lambda^-1
         (1 + gamma_0 s^-1 X)
         product_(j>=1)(1 + gamma_j z^(-2^(j-1)) X^(2^j))
```

The `H` polynomial is unchanged. This historical compact mapping permits
independently published V3 proofs with different `rho,lambda,z` values
to enter one raw-basis accumulation bucket without accepting
caller-supplied generator scales. It is retained as a measured
predecessor, not the candidate receipt leaf.

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
uses logarithmically many proof points. The selected construction-parent
recurrence authenticates the derivation of `c` and `Cc`, including their
dependence on child messages. This native API alone has not compressed or
eliminated that requirement.

The raw-basis digest uses `Purify/BPPP/NormAccumBasisV2`, binding the framed
semantic domain, `g,h` and all `2g` canonical points. The prepared statement
uses `Purify/BPPP/NormReduction/StatementV1` over that digest, `rho`, the initial
commitment, all `h` canonical coefficients, computed `Cc`, and the length-framed
original proof. Sizes are unsigned 64-bit little-endian; scalars are 32-byte
big-endian. Basis-authenticated dimensions fix the coefficient array's length.
Legacy typed V3 preparation instead uses
`Purify/BPPP/CircuitNormReduction/StatementV3` and additionally binds the raw
generator digest, V3 challenge digest, `rho,lambda,z`, statement binding,
ordered public commitments, every outer proof field, reconstructed inner
commitment, coefficient vector and inner proof.
Candidate V4 preparation and its algebraic reduction use the typed
transcripts specified in
[algebraic accumulation V2](algebraic-accumulation-v2.md). Those
transcripts bind the V4 prepared result, purpose-selected basis digest,
and explicit-gamma reduction rather than reusing the V3 statement tag.
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
prepare each V4 leaf and run its exact algebraic adapter
verify_norm_reduction for each public coefficient-opening proof
verify every public accumulation transition
decide the final pending claim
```

The standalone generic path may use `prepare_norm`. The
construction-specific V3 adapter is a historical integration path, not
the candidate receipt flow.

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

A final one-term claim returned by `verify_step` has a separate unframed
encoding. The selected basis and receipt version supply its dimensions:

```
point33 || scale32 || factors32[log2(D)]
```

The polynomial offset is implicitly zero. Its exact length is
`65+32*log2(D)` bytes. The current anchor basis has `D=32768`, so its root
claim is 545 bytes. The encoding intentionally omits a basis digest; the
parent statement and receipt version must bind the exact basis supplied to
the parser.

Parsing a root claim establishes only canonical point and scalar encodings
and the required one-term shape. It does not authenticate child proofs or
accumulation transitions, and it is never acceptance. A compressed parent
must bind the exact parsed claim and its ancestry, after which the verifier
must still call `decide` for the mandatory final basis MSM.

These openings are additional public transition data. Native verification
retains them alongside the original child proofs; a final 1,122-byte step
does not replace that history. The selected recurrence implements recursive
authentication so this history can become a parent witness. The qualified
two-anchor Nova lifecycle compresses that witness history, and the public C++
acceptance path completes the final native decision before returning a
capability. A checked-in recursive-valid/nondeciding proof authenticates a
nondeciding pending root and is rejected specifically by that decision,
demonstrating why neither the native helper nor recursive verification alone
establishes acceptance.

## Historical generic varying-coefficient measurements

Single local runs at commit `691b219` on macOS arm64, AppleClang
16.0.0.16000026, C++20 Release `-O3`, used `g=32768,h=16384,D=65536`.
Every owner published a different canonical `c` vector. The original private
norm witnesses were erased before public preparation. Both final steps were
1,122 bytes; each coefficient opening was 1,022 bytes.
[Raw results](../bench/results/norm-accumulation-varying-c-arm64.json) include
all measured stages and public-input byte accounting. Peak memory was not
measured.

| Stage | 2 inputs | 100 inputs |
| --- | ---: | ---: |
| Shared raw basis creation | 1.747 s | 2.078 s |
| Independent leaf publication, sequential | 2.464 s | 133.444 s |
| Norm preparation and coefficient authentication | 0.364 s | 16.934 s |
| Public coefficient-opening proving | 2.767 s | 105.594 s |
| Short coefficient-opening verification | 1.001 ms | 41.435 ms |
| Public accumulation proving | 5.153 s | 4.784 s |
| Short accumulation verification | 0.461 ms | 1.761 ms |
| Mandatory final decision | 342.429 ms | 284.103 ms |

The 100-input run retained 52,428,800 bytes of explicit public coefficients,
103,900 bytes of child norm proofs, and 102,200 bytes of coefficient-opening
proofs. The full leaf records, including coefficients, rho and commitments,
occupied 52,539,200 bytes. Basis points are shared; coefficient commitments
are derived during preparation. These are retained public-data sizes, not
peak memory or a proposed on-chain encoding.

These runs use synthetic standalone Version 1 norm preparation. They
measure the public accumulation machinery, not V4 leaf preparation or a
complete construction receipt.

Coefficient authentication and opening generation still scale with the
number of children and their linear dimension. Native verification must
reconstruct authenticated prepared statements and verify every opening and
accumulation transition. The final short step alone is insufficient. The
small timing difference between the two shared-step prover runs does not
establish a speedup with more inputs. These synthetic norm measurements do
not measure a sound encryption circuit or its final recursive receipt.

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

The selected parent now authenticates the purpose-owned semantic digest and
frontend constants, constrains V4 preparation, reduction, and every ordered
accumulation transition, and binds exact registry coverage. The complete
two-anchor production lifecycle, frozen external verifier identity, private C
ABI, and public C++ recursive-plus-native acceptance path are implemented.
Remaining work is specific: independently review the V4 leaf and composition
arguments; implement distributed custody and share-preserving child proving;
resolve the correlated-key confidentiality argument; qualify operation at 100
to 1,000 anchors; and reduce or operationalize the roughly 609 MiB verifier. The
native V4 adapter remains a component of that path, not receipt acceptance by
itself.

The construction-specific V3 adapter previously demonstrated setup-proof
preparation and safe zero-extension into the anchor basis. That
historical result does not authenticate a V4 promotion or complete the
recursive parent. Encryption privacy, distributed proving, and signing
security remain their own protocol obligations.

Publishing a coefficient seed and binding it to the child transcript remains
a possible byte/preprocessing tradeoff. It requires a sound outer transcript
and an authenticated derivation; a seed alone does not establish the relation.
