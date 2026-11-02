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

The production API implements this relation as a fixed-size escrow record. It
does not establish correlated-key privacy, a distributed setup/prover, or
certificate validity. It advances
[scalar escrow #23](https://github.com/judica-org/purify/issues/23) without
enabling enrollment. The independent leaf experiment is in
[#37](https://github.com/judica-org/purify/pull/37).

V4 is the candidate active leaf path for a construction receipt. Native
V4 proof production, preparation, verification, and the algebraic
accumulation adapter are implemented. The fixed-size setup record and anchor
record version 3 both encode V4 proofs. Their historical hidden-output sizes
and timings below remain useful as an individual-proof baseline. The setup leaf
is handled once at registry creation, and the record-version-3 public anchor
leaf has been migrated into the homogeneous parent recurrence. That parent is
not fully compressed or activated as a production receipt.

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

A public pair is packed as `x1 + n*x2` in 64 bytes. The production parser
validates the packed range, both coordinate encodings, curve membership,
finiteness and subgroup membership before circuit construction. Ciphertext
field elements have canonical 32-byte encodings in `F_n`, including zero.

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

The setup circuit allocates 255 Boolean bits for `x=a-1` and one sign bit
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

Finite `Q` fixes `q` modulo `n`. The bound and sign then uniquely fix
`a,s`, which fixes both recipient points and canonical components. The
legacy V3 setup proof binds all of those outputs to the same witness.
Verification is the only constructor for `RecoveryBoundSigningRoster`;
anchor escrow creation does not accept an arbitrary recipient root.
Consequently a roster cannot register a hidden second-generator
component and later open a different recovery root while retaining the
typed capability.

The V4 candidate public setup leaf constrains the same circuit outputs
and its public-point DLog equation. The current roster constructor still
uses V3 verification until the fixed-record API is migrated.

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
- A fixed-domain Purify evaluation of the same plaintext witnesses, normalized
  to the even-Y BIP340 punishment scalar.

The transcript binds the suite/version, ordered ciphertext, recipient, old
root, exact canonical punishment key and application setup/purpose context. It
also binds the roster's even-Y `Q`, key-list hash, coalition-core digest, and
registered recovery root. The circuit has twelve companion scalar
multiplications: two for the old root, four for each pad, and two fixed-base
multiplications for the punishment evaluation. The two evaluation
multiplications reuse the old-root scalar bits and their bit-only lookup
products. The circuit's sole output is the normalized punishment scalar,
bound to canonical `02 || Kx` by V4 public-commitment mode and its 64-byte DLog
argument. Encrypted plaintext relations remain native field/curve equations,
not independently blinded Pedersen output values.

The complete V4 transcript and pending norm obligation still require
reduction, parent authentication, and the final accumulator decision.

`recover_escrowed_anchor` first verifies the bridge and checks that an exposed
coalition scalar opens the recovery-bound roster's exact `Q` and registered
`M`. It computes `k_j=PurifyCombine(x(m1*A_j1), x(m2*A_j2))`, then computes
`d_j=c_j-k_j` in `F_n`. It strictly checks the canonical component ranges,
packs them, and requires their derived public root to equal the registered
old `D`.

The x-coordinates of the sender and receiver shared points agree even if
either public pair chooses the opposite point signs. A satisfying encryption
relation therefore decrypts to its exact bounded
`d1,d2`, and those scalars open `D`. This remains true if the prover already
knows the recipient secret. It does not rely on the recipient public key
being an unknown-log Pedersen generator.

The algebra follows the verifiable-encryption application proposed in
[MuSig-DN section 7](https://eprint.iacr.org/2020/1057), which leaves formal
treatment for future work. Encrypting both canonical companion components
and composing that encryption with the coalition setup is an adaptation,
not an application of an already proved complete protocol.

## Privacy, custody and ordering boundaries

`create_anchor_escrow` samples one fresh 32-byte operating-system auxiliary
input for every encryption. It hashes that input together with the anchor
secret and complete pre-ciphertext statement into a randomness master.
Separate tags derive both ephemeral pairs, and a further tag including the
final ciphertext binding derives the proof seed. A repeated context does not
reuse pads when the operating-system input changes, while a changed context
cannot reuse pads even under repeated auxiliary input. Reusing an entire
derived ephemeral pair would expose plaintext differences.

Exact validity and post-conflict extraction follow from the setup and anchor
proofs. Pre-conflict confidentiality is a separate claim: it relies on a
correlated-key, adaptive multi-user Purify/DH assumption for the public secp
and companion representations. No general chosen-ciphertext security or
decryption-oracle service is claimed.

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

## Historical hidden-output sizes and current cost accounting

The test-local C++20 Release experiments measured:

| Component | Setup | One old-root bridge |
| --- | ---: | ---: |
| Padded gates | 2,048 | 8,192 |
| Native constraints | 4,710 | 18,325 |
| Inner proof bytes | 844 | 974 |
| Outer proof fields | 162 | 98 |
| Complete proof bytes | 1,006 | 1,072 |
| Ciphertext bytes | 0 | 192 |
| Proof plus ciphertext | 1,006 | 1,264 |
| Historical versioned fixed record | 1,007 | 1,265 |

Setup additionally needs its 64-byte `M` and the registered `Q` (33 bytes
as a full point, or its existing authenticated x-only representation).
If `Q` is already registered, setup adds 1,071 bytes including the 64-byte
root and proof version byte. The 1,265-byte anchor figure was the historical
hidden-output record. The current public-commitment anchor record adds the
32-byte DLog nonce and 32-byte DLog response, for 1,329 bytes. Its 192-byte
ciphertext is two 64-byte ephemeral pairs and two 32-byte field elements.
The record does not repeat the 64-byte root, canonical 32-byte punishment
key, or 32-byte application-context digest; all are authenticated public
inputs.

With setup shared across `R` independent old roots, current incremental
cryptographic data is `1071 + 1329*R` bytes when roots, punishment keys, and
context are authenticated by reference. One setup plus one bridge is 2,400
bytes. For 100 independent anchors under one coalition, amortizing setup gives
1,339.71 bytes per anchor before roots, references, consents, and transport
framing. Permanent anchor leaves remain additional historical data.

One AppleClang 16 / arm64 Release sample of the V3 tree took about 2.95
seconds to prove setup and 0.52 seconds to verify it. The first anchor escrow
in its focused suite took about 9.21 seconds to prove and 2.19 seconds to
verify. These are centralized honest fixtures run while other sanitizer work
was active, not an MPC or throughput benchmark. Proving includes witness and
public-circuit construction; verification includes public-circuit
construction. Treat the timings as reproducibility samples, not performance
guarantees.

## Executable boundary and remaining work

`canonical_recovery_root_tests.cpp` checks the comparator, independent bit
recoding, both scalar signs, upper-bound companion normalization, a public
setup proof, and toy accountable extraction followed by root/leaf recovery.
`anchor_escrow_tests.cpp` checks the production fixed-size codec, an old root
chosen before its recipient, exact same-slot scalar extraction followed by
verified decryption, fresh encryption randomness, roster/context/root/
ciphertext substitutions, and malformed public encodings. The lower-level
`companion_scalar_escrow_tests.cpp` additionally checks exact decryption,
changed public inputs, and canonical plaintext boundaries, including
packed-zero `(1,1)`. It also extracts a recipient from
toy accountable responses, decrypts the old root, and matches two independent
owners' punishment scalars from owner-side, old-root and recovered-root
computations. Nonce evidence and setup authentication remain external
prerequisites; those toy responses are not accepted decision certificates.

Run the registered suites with:

```
ctest --test-dir build -R 'canonical_recovery_root|anchor_escrow|companion_scalar_escrow' --output-on-failure
```

The suites use public toy secrets. They do not validate decision certificates
or application liability. The separate setup must be authenticated before
treating a recipient as controlled by a given coalition, and all public
evidence on the recovery path must remain available.

The individual-proof validity path now binds the exact setup and escrow
outputs. Production deployment still requires independent cryptographic
review, a distributed setup/prover, explicit resource bounds, authenticated
coalition registration, and reviewed punishment/redemption contracts.
Recovery of a scalar is not by itself a proof of forced economic loss under
Bitcoin's spend rules. Enrollment remains disabled while the distributed
setup and prover are not implemented.

The next [construction receipt experiment](construction-receipt.md)
treats the setup and encryption proofs as out-of-band inputs to a public
assembler. V4 is the candidate child relation for that design. The
intended on-chain receipt retains the ciphertexts and replaces the child
proofs with one parent proof. The recurrence and selected profile are
implemented; exact setup and one full-scale fold have qualified, and the proof
shape and authenticated-root verifier are fixed. Full native-profile
compression and the C ABI/native acceptance path remain incomplete; the
historical V3 sizes above are not an estimate of the parent's size or prover
cost.
