# Recovery roots for compact punishment-key escrow

This is a candidate design for [scalar escrow](https://github.com/judica-org/purify/issues/23),
not an enrollment format or a completed security argument. The budget is about
1 KB per anchor, including its amortized setup/proof cost. A roughly 1 KB
**additional coalition record** is a separate, more ambitious target; it must
not hide historical anchor records from Bitcoin-only synchronization costs.

The accountable-signature code recovers a coalition scalar. It does not yet
prove that this scalar unlocks any anchor's punishment key. There are two
distinct claims to implement and review:

1. An accepted anchor leaf recovers its exact punishment scalar from its
   registered recovery-root secret.
2. An accepted coalition bridge recovers that exact root secret from the
   extracted coalition scalar.

## Separate permanent leaves from coalition bridges

Let `Q = qG` be the even-Y secp256k1 coalition key. A recovery root has a public
key `D` and secret `d`, with its own explicitly specified group and encoding.
Several anchors can publish permanent leaves under the same `D`. A later
coalition publishes one verifiable encryption of `d` under `Q` for that root:

```
two accepted conflicting responses
    -> exact coalition scalar q
    -> verified bridge decrypts recovery-root secret d
    -> each verified leaf recovers its punishment scalar p_i
    -> application validates the actual collateral spend relation
```

One common root permits one bridge. Independent per-anchor roots require one
bridge each. Several historical roots require several direct bridges, or a
bridge to an older coalition key whose retained subtree reaches those roots.
A proof hash or root identifier cannot replace the ciphertexts, leaves, and
verification material on that path. Require an authenticated, acyclic graph;
each edge must authorize exposure in its declared direction.

The distinction matters for the meaning of "1 KB per coalition":

```
permanent bytes = sum(anchor leaf data + leaf proof + metadata)
new bytes      = sum(root bridge ciphertext + bridge proof + references)
sync bytes     = all required permanent and historical new bytes
```

Leaving cannot erase an already published decryption edge. Bound graph depth,
the number of reachable leaves, and total verification/recovery work before
turning this into a consensus format.

## Derive new punishment keys from the recoverable secret

Freedom to choose new punishment keys can remove an encrypted scalar from
each leaf. It does not remove the proof connecting the public punishment key
to the derived secret. This construction does not import an existing arbitrary
punishment key; that requires actual plaintext encryption.

The most direct conceptual example uses a secp256k1 root `D = dG`. An owner
chooses fresh `r`, publishes `A = rG`, and privately computes `S = rD`. Define:

```
k = H_scalar(suite, pre-anchor context, D, A, S)
p = k if kG has even Y, otherwise -k mod n
P = pG
```

Reject zero `k`. Recovery computes `S = dA` and derives the same canonical `p`.
The owner knows `r,p` without receiving `d`. This avoids the explicit inverse
equation of public additive tweaks. It still needs an appropriate DH/KDF
privacy argument; the equations alone do not prove that privacy.

The leaf proof must establish knowledge of `r` satisfying **all** of the
equations, including the KDF and exact output key. Publishing `S` to use a
simple public DLEQ proof would disclose `p` immediately. The 33-byte `A` and
32-byte x-only `P` therefore are not a complete verifiable escrow.

With this root type, initially choosing `D = Q` needs no bridge. A successor
with an independently formed `Q_new` still needs a genuine encryption of the
old `d`, unless collateral moves or a separately reviewed authority-transfer
protocol is used. There is no free one-way public affine key rotation.

This secp256k1 example is not automatically cheap in the existing circuit:
curve coordinates use the secp256k1 base field, while Purify's arithmetic uses
its scalar field. Hashing a hidden shared point adds another circuit cost.

## Native Purify companion roots

A better leaf experiment uses Purify's two companion groups. Denote their
generators and orders by `(G1, l1)` and `(G2, l2)`. These are **not** the
secp256k1 generator/order `(G,n)`:

```
root secret:  1 <= d1 <= floor(l1/2), 1 <= d2 <= floor(l2/2)
root public:  D1 = d1G1, D2 = d2G2
owner secret: 1 <= r1 <= floor(l1/2), 1 <= r2 <= floor(l2/2)
leaf public:  A1 = r1G1, A2 = r2G2
shared:       S1 = r1D1, S2 = r2D2
raw output:   k = PurifyCombine(x(S1), x(S2)) in F_n
punishment:   P_raw = kG
```

Recovery computes `S1 = d1A1` and `S2 = d2A2`; their x-coordinates agree even
when packed companion points choose the opposite sign. Validate the exact
companion curve, subgroup, finite-point, scalar, and packed encoding rules.
The existing secret codec uses the mixed-radix integer
`(d1 - 1) + floor(l1/2) * (d2 - 1)` in 64 bytes. Packed zero is the valid
pair `(1,1)`. The bridge must recover this exact canonical pair; reducing
its encoding modulo the secp256k1 order would destroy information. The
half-order convention removes the scalar-sign ambiguity of x-only roots.
Reject zero output. Preserve the full `P_raw` when binding the proof; canonical
even-Y scalar recovery can negate `k` afterward using its public parity.

This is the shape of Purify's verifiable-encryption application, specialized
to choosing the output key instead of encrypting a preselected scalar.
[MuSig-DN, section 7](https://eprint.iacr.org/2020/1057.pdf) discusses that
application but leaves its formal treatment for future work. That discussion
is not a proof of this layered protocol.

The current `circuit_main` already computes four scalar multiplications:
`r1G1`, `r2G2`, `r1m1`, and `r2m2`, reusing each secret's bit decomposition.
Its public inputs `m1,m2` can be the recipient points `D1,D2` in a test-local
construction. Thus both the ephemeral public keys and shared-secret output
can be constrained; proving just the output without the `A1,A2` relations
would be insufficient. High-level nonce APIs normally derive these inputs
from topic hashes, so their wrapper is not an escrow API.

Unlike hash-derived nonce bases, recovery-root bases have known discrete logs
to an authorized distributed set. The review must cover chosen/correlated
recipient keys and the actual two-source extractor assumptions. An honest
proof fixture cannot establish these properties. The full suite, recipient
points, ephemeral points, output point and pre-anchor context must be bound
to the proof transcript. Proof context binding does not itself turn the
extractor into a context-dependent KDF; fresh owner randomizers are required.

This root is two companion scalars, not one secp256k1 scalar. It cannot simply
be set equal to `Q`. The initial bridge, root setup, and later growth bridges
must account for both secrets and their different orders. No participant
should learn the complete root during setup if the stated threat model
requires every affected owner's participation before exposure.

## Bridge correctness must tolerate a malicious recipient

Require validity even when the bridge prover knows `q` and the root secrets:

```
VerifyBridge(Q, D, ciphertext, proof, context) = accept
and qG = Q
    => Decrypt(q, ciphertext) yields valid root secrets opening exactly D
```

The proof must bind suite, recipient, root, purpose, immutable setup context,
and all ciphertext components. The root codec must recover scalars, not only
their already public curve points. Plain EC ElGamal of `dG` fails this goal.
An honest round trip is necessary but does not establish this validity game.
Recipient-secret-known validity and malicious-key-generation variants are
explicitly distinguished in
[Takahashi--Zaverucha](https://cic.iacr.org/p/1/1/3/pdf).

In particular, do not use `Q` as a supposedly binding Pedersen generator in a
separate range proof: a malicious coalition knows `log_G(Q)`. A chunked
construction needs one joint encryption/range/key-binding relation, or
independent binding commitments with a sound common-witness link.

Each owner can create its leaf locally. Bridging an old distributed root
without first reconstructing it requires a distributed encryption/proving
protocol. This is separate work from both local leaf proving and the
per-block nonce MPC. There is no routine decryption-share service in this
design. A full authorized set can voluntarily reconstruct its secrets; VE
does not make decryption possible only after a conflicting signature.

## Preserve participation through every historical edge

A root's exposure set must be immutable, unless a later addition explicitly
accounts for **every** historical authority that can recover it. For the
original no-framing goal, the useful baseline is:

- Growth retains old roots for existing anchors and creates fresh roots for
  new anchors. Appending a new owner to an old root would allow an old
  coalition to expose that new owner's key without their participation.
  A successor must not add an edge from an old authority to a root containing
  new owners unless it satisfies their participation requirement. Adding
  those owners to the current roster does not change historical authorities.
- Every authority that can reach a root must include the required participation
  of every still-liable owner beneath it. Consent to a smaller authority is
  a weaker delegation guarantee; it does not satisfy "others cannot extract
  me unless I participate."
- A successor bridge is permanent. Destruction, leaving, and switching the
  selected coalition do not revoke old authorities or protect later deposits
  using the same punishment key.
- One invalid leaf prevents that anchor's admission. A proposed coalition
  cannot activate with missing required members; existing unrelated valid
  leaves do not become invalid merely because another leaf fails.

Compute a pre-anchor setup descriptor from the root, network/suite, and
already chosen signing, owner/authentication and redemption identities. Derive
leaf punishment keys next; compute final anchor/registration identifiers last.
Neither the leaf derivation nor initial roster ordering can depend on a final
anchor ID which itself contains the derived punishment key.

## Size candidates and limits

All figures below exclude application metadata unless stated. Calculations
are not proof benchmarks.

| Candidate | Size observation | Missing or changed property |
| --- | --- | --- |
| Bitwise ElGamal with joint OR/link proof | 41,536 bytes for one secp scalar | Correctness comparison, outside the budget |
| Eight 32-bit ElGamal chunks | 528 ciphertext bytes; eight separate range commitments add 264 bytes | Compressed joint proof still needed; simple separate links already exceed the remaining budget |
| Secp DH-derived leaf | 65 bytes for `A,P` | Actual foreign-field DH/KDF/output proof unmeasured |
| Native companion leaf | 1,007-byte honest proof plus 97 bytes of ephemeral/output data | Slightly over the target before metadata; proof security and bridge remain open |
| Public affine `P = Q + hG` | No VE proof | Knowing any `p` reveals `q`; owners cannot retain independent punishment secrets |
| Schnorr adaptor penalty authorization | About 64--65 bytes plus transaction data | Authorizes a particular spend, not arbitrary future deposits or recovery-root secrets |

For 100 anchors, a 1 KiB-per-anchor budget leaves 23,200 bytes for a joint
proof after 792 bytes each of 32-bit chunk ciphertexts and range commitments.
This makes a compressed proof worth investigating, not already implemented.
Public batch verification does not reduce stored proof bytes. A joint private
prover or a reviewed public recursion scheme would be additional work.

Recovering a 32-bit chunk by baby-step--giant-step needs a reusable 65,536-entry
baby table and up to 65,536 giant steps. Eight chunks across 100 anchors can
require about 52.4 million giant steps. Benchmark and cap that recovery cost.
These secp scalar calculations do not directly size a two-companion-scalar
bridge or prove a cross-group plaintext relation.

Public additive key derivation is compact but reversible, as in the
nonhardened-child caveat in
[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
Adaptor signatures can unlock a fixed transaction without exposing its owner
key, but [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
binds the current outpoint even with `ANYONECANPAY`. Removing output
commitments with `SIGHASH_NONE` permits redirection; it does not enforce a
burn or cover unknown future outpoints.

## Honest native-leaf measurement

`tests/recovery_root_tests.cpp` builds the recipient-point circuit directly,
using independent public toy seeds for the root and leaf owner. It checks
both directions of shared-output computation, the exact raw secp point,
external BIP340 normalization, and verification using public inputs only.
Substituting the context, root, ephemeral key or output point rejects the
unchanged proof. Noncanonical companion public encodings reject before
circuit construction.

The C++20 Release experiment has 2,048 padded gates and 4,117 constraints.
The existing masked backend reduces it to `n = 8192`, `l = c = 4096`:

| Component | Measured bytes |
| --- | ---: |
| Inner norm proof | 909 |
| Outer commitments and scalar (`A`, `S`, `t2`) | 98 |
| Complete proof | 1,007 |
| Packed leaf ephemeral pair | 64 |
| Full raw punishment point | 33 |
| Leaf payload | 1,104 |
| Test-only version and fixed-length framing | 5 |
| Complete measurement envelope | 1,109 |
| Shared public recovery root, stored separately | 64 |
| Context/root references, registry metadata and outer bridge | Not included |

The 1,104-byte leaf is already 80 bytes above 1 KiB before framing, metadata
or the bridge. For 100 such leaves the measurement envelopes plus one shared
root occupy 110,964 bytes, still excluding those additional costs. One cold
AppleClang 16 / arm64 run took about 911 ms to prove and 568 ms to verify;
proving excluded witness/circuit construction, while verification included
circuit reconstruction and public-point checks. This single sample is not
a complete setup, throughput or 100-party performance result.

Run `build/purify_tests --suite recovery_root` to print dimensions, byte
counts and local timings. CTest selects it with `-R recovery_root`.
The size envelope is a test-local measurement, not a
versioned public codec. The circuit's context is transcript-bound; the
underlying scalar does not change merely because that context changes.

This experiment does **not** prove a bridge, use an extracted secp coalition
scalar to recover a companion root, or test a distributed root setup. It
uses known toy root secrets and honest zero-blind output witnesses. The
current proof backend's unresolved soundness and exact output-binding work
remains a prerequisite for using any of these byte measurements in a protocol.

## Remaining patch boundaries

1. Reduce and measure the complete leaf/bridge budget using the actual
   relation. Keep experiments test-local; no enrollment or wallet changes.
2. Review chosen-root privacy, the extractor, exact scalar-output binding,
   and the underlying proof construction. Honest zero-blind witnesses do not
   prove that a malicious prover cannot change the output opening.
3. Specify and measure the outer bridge's two-scalar, cross-group relation
   and distributed generation. Compare genuine VE backends under the full
   public-data budget, rather than quoting a compressed decryption artifact
   which omits verification evidence.
4. Bind the recovered scalar to the application's final punishment/spend key
   and independently controlled redemption role. Reconcile funding, signing,
   owner exit, root selection and historical exposure before activation.

Recovering a valid punishment scalar establishes a cryptographic spending
capability. It does not by itself establish a forced economic loss against a
competing owner or a fully malicious authorized coalition. Enrollment remains
disabled pending these proof and application gates.
