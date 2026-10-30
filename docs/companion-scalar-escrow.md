# Scalar escrow for preexisting recovery roots

This candidate preserves **anchor-first creation**. An anchor's recovery root
`D` can exist before the coalition which will later accept its collateral.
The coalition publishes a companion encryption recipient `M`, proved to be
recoverable from its secp256k1 scalar `q`. A bridge encrypts the existing
root's secrets under `M`; it does not replace the existing anchor key.

```
existing anchors and independent recovery root D
    -> later coalition Q and authenticated encryption recipient M
    -> bridge encrypts D's secrets under M

extracted q -> recipient secrets m -> old root secrets d -> punishment keys
```

Using `M` directly as the anchor root is an optional bootstrap shortcut. It
requires choosing the initial coalition key before deriving those anchors.
The encryption bridge is what preserves flexible joining and growth.

This document specifies relations and records honest reference measurements.
It does not establish the experimental proof backend's soundness or ZK,
correlated-key privacy, a distributed setup/prover, or certificate validity.
It advances [scalar escrow #23](https://github.com/judica-org/purify/issues/23)
without enabling enrollment. The independent leaf experiment is in
[#37](https://github.com/judica-org/purify/pull/37).

## Groups, keys and canonical encodings

Write `(G,n)` for secp256k1's generator/order and `(Gi,li)` for Purify's
two companion groups. Purify arithmetic uses `F_n`; companion scalar orders
are different. In the current constants:

```
2^255 < l2 < n < l1
```

Companion secret components have canonical ranges `1..floor(li/2)` because
their public keys contain x-coordinates. Their 64-byte secret encoding is
the mixed-radix integer `(d1-1) + floor(l1/2)*(d2-1)`. Packed zero is valid
and represents `(1,1)`. It must never be reduced modulo `n`.

A public pair is packed as `x1 + n*x2` in 64 bytes. Validate the packed
range, both coordinate encodings, curve membership, finiteness and subgroup
membership before circuit construction. Ciphertext field elements have
canonical 32-byte encodings in `F_n`, including zero. The experiments use
typed field elements and do not add a production byte parser.

## Recoverable recipient setup

For the exact even-Y coalition point `Q=qG`, let:

```
h = floor(n/2)
a = min(q, n-q), with 1 <= a <= h
s = 0 if q=a, otherwise 1
q = (1-2s)*a mod n
Mi = x(aGi)
```

Recovery derives canonical recipient components
`mi = min(a, li-a)`. The first is always `a`; the second needs sign
normalization near the upper bound. The setup proof must bind the **same**
bounded integer `a`, Boolean sign `s`, both companion coordinates, and the
full secp output point `Q`. Checking only a field equality without the
integer bound leaves different representatives in different groups.

The test circuit allocates 255 Boolean bits for `x=a-1` and one sign bit
before any other multiplication gates. It compares `x` with `h-1` using an
MSB-first prefix comparison. With `eq=1` and `greater=0`, each bit computes
`one=eq*x_i`. If the bound bit is one, set `eq=one`; otherwise add `one` to
`greater` and set `eq=eq-one`. Only the first differing bit can contribute.
Constrain `greater=0`. This is an integer comparison: all inputs are Boolean
and `a` lies below `2^255<n`, so there is no field wrap.

The existing curve gadget consumes signed-window bits, not ordinary binary
bits. For `j=3,6,...,252`, recode the original `x` bits as:

```
b_j = 1-x_j
b_k = 1-x_j-x_k+2*x_j*x_k, for k=j-1,j-2
```

Bits 0, 253 and 254 are unchanged. This is checked against the independent
C `key_to_bits` implementation. Both companion multiplications consume the
same recoded vector. The output expression is `(1-2s)*a`, bound to `Q` via
the existing external-output proof interface.

The 255-bit restriction also matters for curve completeness. After `k`
regular signed windows the accumulated coefficient is nonzero, odd, and
has magnitude at most `2^(3k)-1`; the next window's magnitude is at least
`2^(3k)`. At the final addition the prefix magnitude is at most `2^252-1`
and the positive lookup is between `2^252` and `7*2^252+1`. Thus every
relevant nonzero sum/difference is at most `2^255`, below both group orders.
The affine x-denominators do not vanish. Extending the gadget directly to
256 bits would not inherit that argument.

**Conditional uniqueness:** assuming a sound proof with exact output
binding, finite `Q` fixes `q` modulo `n`. The bound and sign then uniquely
fix `a,s`, which fixes both recipient points and canonical components.
This mathematical implication is separate from proving that the current
experimental backend establishes its premise.

## Encrypt the old root, not the new coalition

Let the preexisting root contain canonical components `d1,d2` and public
coordinates `Di=x(diGi)`. For each component `j=1,2`, choose an independent
fresh ephemeral pair `r_j1,r_j2` and publish:

```
A_j = (x(r_j1 G1), x(r_j2 G2))
k_j = PurifyCombine(x(r_j1 M1), x(r_j2 M2))
c_j = d_j + k_j mod n
```

The bridge proof jointly constrains:

- Both plaintext bounds `1 <= di <= floor(li/2)` and the old root's points.
- Each ephemeral public pair and its shared-point multiplications under `M`.
- Both `c_j` equations, using exactly those bounded plaintext witnesses.

The transcript binds the suite/version, ordered ciphertext, recipient, old
root and application setup/purpose context. The reference circuit has ten
companion scalar multiplications: two for the old root and four for each
pad. Its only external output commitment is fixed to `G`, with a constrained
value of one. Encrypted plaintext relations are native field/curve equations,
not independently blinded Pedersen output values.

Decryption first verifies the bridge and checks that its secret opens `M`.
It computes `k_j=PurifyCombine(x(m1*A_j1), x(m2*A_j2))`, then `d_j=c_j-k_j`
in `F_n`. It strictly checks the canonical component ranges, packs them,
and requires their derived public root to equal the registered old `D`.

**Conditional validity:** the x-coordinates of the sender and receiver shared
points agree even if either public pair chooses the opposite point signs.
A satisfying encryption relation therefore decrypts to its exact bounded
`d1,d2`, and those scalars open `D`. This remains true if the prover already
knows the recipient secret. It does not rely on the recipient public key
being an unknown-log Pedersen generator.

The algebra follows the verifiable-encryption application proposed in
[MuSig-DN section 7](https://eprint.iacr.org/2020/1057), which leaves formal
treatment for future work. Encrypting both canonical companion components
and composing that encryption with the coalition setup is an adaptation,
not an application of an already proved complete protocol.

## Privacy, custody and ordering boundaries

Use independent fresh ephemeral pairs for both pads and every encryption.
Reusing one pair exposes plaintext differences. The transcript binds context,
but context does not change these pads. No general chosen-ciphertext security
or decryption-oracle service is claimed.

Recipient roots correlated with the secp coalition scalar need a privacy
argument covering all public group representations together. Independent
owner randomizers preserve conditional independence of the shared points;
that fact alone does not prove secrecy given the public ephemeral points.
Revealing a recipient component exposes `q` up to a few candidates checkable
against `Q`. Full coalition collusion can decrypt intentionally.

Setup must compute the canonical magnitude/sign of the aggregate scalar
without revealing it. Adding the original signing shares in the companion
groups does not handle the differing modular carries. Encrypting an old
distributed root also needs a share-preserving distributed prover. Neither
test implements those protocols; ordinary owners may encrypt roots they
already individually own, but a coordinator must not collect shared secrets.

Existing anchor IDs can participate in later coalition setup because their
keys are already fixed. Use an acyclic pre-anchor descriptor when creating
new derived anchor keys; an ID containing such a key cannot also be an input
needed to derive it. No anchor-first identity needs to be changed merely
to add a later encryption bridge.

Keep historical exposure rules: published bridges cannot be revoked by leave
or coalition destruction. Do not add new owners beneath a root reachable by
an old authority which lacks their required participation. A shared root
amortizes a bridge only when that common custody/exposure group already
exists; independently created roots do not become one root for free.

## Measured sizes and cost accounting

The test-local C++20 Release experiments measured:

| Component | Setup | One old-root bridge |
| --- | ---: | ---: |
| Padded gates | 2,048 | 8,192 |
| Native constraints | 4,710 | 18,325 |
| Inner proof bytes | 909 | 1,039 |
| Outer proof fields | 98 | 98 |
| Complete proof bytes | 1,007 | 1,137 |
| Ciphertext bytes | 0 | 192 |
| Proof plus ciphertext | 1,007 | 1,329 |

Setup additionally needs its 64-byte `M` and the registered `Q` (33 bytes
as a full point, or its existing authenticated x-only representation).
If `Q` is already registered, setup adds 1,071 bytes before context/framing.
The bridge's 192 bytes are two 64-byte ephemeral pairs and two 32-byte
field elements. Including both public roots adds 128 bytes, yielding 1,457
bytes before context. The fixture's 45-byte context gives 1,502 bytes;
this is not a complete registry or Bitcoin transaction format.

With setup shared across `R` independent old roots, incremental cryptographic
data is `1071 + 1329*R` bytes, excluding old root data, references, context,
consents and transport framing. A single shared root therefore adds about
2.4 KB for setup plus bridge. This does not meet a strict 1 KB coalition
record goal. For 100 anchors sharing that root the incremental amount is
24 bytes per anchor; for 100 independent roots it is about 1,340 bytes each.
Permanent anchor leaves remain additional historical data. The earlier
1,104-byte leaf measurement must not be hidden by calling the bridge small.

One AppleClang 16 / arm64 sample took about 0.87 seconds to prove setup and
0.38 seconds to verify it. Bridge proving took about 3.42 seconds and checked
verification/decryption 1.59 seconds. Proving excludes witness/circuit
construction; verification includes public circuit construction. These are
single centralized honest fixtures, not full setup, MPC or throughput
benchmarks. Proof repairs can change all size/timing estimates.

## Executable boundary and remaining work

`canonical_recovery_root_tests.cpp` checks the comparator, independent bit
recoding, both scalar signs, upper-bound companion normalization, a public
setup proof, and toy accountable extraction followed by root/leaf recovery.
`companion_scalar_escrow_tests.cpp` checks an old root chosen before its
recipient, exact decryption, changed public inputs and canonical plaintext
boundaries, including packed-zero `(1,1)`.

Run the registered suites with:

```
ctest --test-dir build -R 'canonical_recovery_root|companion_scalar_escrow' --output-on-failure
```

Both are test-local honest experiments with public toy secrets. They do not
validate decision certificates or application liability. The separate setup
must be authenticated before treating a recipient as controlled by a given
coalition, and all public evidence on the recovery path must remain available.

Before production use, review the complete proof system, exact setup-output
binding, composed privacy/validity, distributed generation, resource bounds,
and the actual punishment/redemption contracts. Recovery of a scalar is not
by itself a proof of forced economic loss under Bitcoin's spend rules.
Enrollment remains disabled, and Daybreak work remains deferred.
