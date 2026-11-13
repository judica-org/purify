# Distributed coalition recovery setup

This document specifies the selected public-aggregation protocol for creating
a coalition recovery root. It replaces the centralized proof that derived a
recovery root directly from the aggregate MuSig scalar. No party reconstructs
that aggregate scalar during formation, and the protocol needs neither a
general MPC prover nor encrypted signing shares.

## Scalars and groups

Let:

- `p` be the secp256k1 group order;
- `G` be the secp256k1 generator;
- `(G1,n1)` and `(G2,n2)` be the two Purify companion groups;
- `P_i = x_i G` be member `i`'s exact compressed signing key; and
- `a_i` be its BIP327 coefficient after aggregate-key parity
  normalization.

`SigningRoster` already stores the parity-adjusted `a_i`. Define the effective
MuSig share:

```
q_i = a_i x_i mod p
```

and its unique centered integer representative:

```
t_i = q_i                    when q_i <= (p - 1) / 2
t_i = q_i - p                otherwise
```

Thus `-(p-1)/2 <= t_i <= (p-1)/2`, `t_i != 0`, and `t_i mod p = q_i`.
Using the centered representative is essential. Interpreting the unsigned
secp representative `p-m` on a different-order companion curve would not be
equivalent to `-m`.

## Two-phase formation

The recovery root is part of Char's coalition manifest, while the proof for a
member contribution is bound to the core derived from that manifest. Formation
therefore has two explicit phases:

1. Fix the ordered `SigningRoster`.
2. Each member calls `derive_recovery_root_share()` with that roster, its exact
   index, and its own signing secret, then publishes the resulting 66-byte
   share.
3. Anyone aggregates the ordered shares into the provisional recovery root
   `M`, which the application commits in its manifest.
4. After the one-shot permit, formation core, and nonce-host list are fixed,
   each member calls `prove_recovery_root_contribution()` for that formation.
5. The assembler requires the proof record to contain the exact share from
   phase two, verifies every ordered proof, and requires the finalized
   aggregate root to equal the manifest root.

Phase-one shares are deterministic public points, not authorization. They do
not reveal a member secret, and no participant or assembler combines secret
scalars. The post-formation proof recomputes the same share from its private
witness and binds it to the permit, core, roster index, and nonce hosts. This
breaks the manifest/core dependency without an MPC proving round.

## Independent member contribution

Member `i` publishes the exact full companion points:

```
T_i1 = t_i G1
T_i2 = t_i G2
```

Each point uses a 33-byte compressed encoding. The sign bit is part of the
statement; x-only member shares cannot be added safely.

The BP++ relation proves, from one magnitude and sign witness, that:

```
q_i G = a_i P_i
T_i1  = t_i G1
T_i2  = t_i G2
```

The secp output is bound to the exact weighted compressed point, including an
odd SEC1 prefix. It must not be independently normalized to even Y. The two
companion multiplications use the existing bounded 255-bit signed-window
relation, then conditionally negate both full points with the same sign bit.

The Fiat-Shamir binding includes:

- the protocol version;
- the one-shot formation permit and immutable coalition core;
- the ordered roster hash, count, and member index;
- the exact member key and parity-adjusted coefficient;
- the normalized aggregate key and its parity state;
- the nonce-host commitment; and
- both exact full companion points.

Consequently the proof is authorization for one formation, not a reusable
same-scalar proof.

The selected production relation has:

| Property | Value |
| --- | ---: |
| Semantic multiplication gates | 1,442 |
| Padded gates | 8,192 |
| Norm vector elements | 16,384 |
| Norm rounds | 14 |
| Full contribution record | 1,203 bytes |

The record contains one version byte, 66 bytes of companion points, and a
1,136-byte proof body. The 8,192-gate padding deliberately matches anchor
escrow leaves so one homogeneous parent recurrence and one accumulation basis
can consume both proof types.

## Public aggregation

Before formation, anyone may compute the provisional root from the ordered
public shares. After formation, the same computation is authoritative only
after verifying one contribution for every roster member in exact roster
order:

```
T1 = sum_i T_i1
T2 = sum_i T_i2
M  = (x(T1), x(T2))
```

The published contribution points and their proofs make this aggregation
noninteractive. An untrusted assembler can verify and add them without any
process learning the aggregate signing scalar.

`M` is the existing 64-byte Purify recovery-root encoding used by anchor
escrow. The implemented aggregate type rejects an empty list, invalid count,
malformed or wrong-subgroup point, and an infinite aggregate on either
companion curve. Point addition cannot detect omissions, duplicates, or
reordering. `verify_distributed_recovery_setup()` first requires the exact
roster count, verifies one contribution at every roster index, and only then
returns a move-only result containing both the recovery-bound roster and exact
full-point aggregate. The public aggregate function remains nonauthorizing.

The aggregate retains the full `T1,T2` points even though the long-lived
recovery root retains only their x coordinates. The mixed construction parent
authenticates every exact signed share before reconstructing this aggregate.

## Recovery after a conflict

Let:

```
S = sum_i t_i
q = S mod p
```

Two accepted conflicting coalition responses expose the normalized aggregate
scalar `q`. Since every centered share is bounded, the hidden signed carry is
in the exact interval:

```
-ceil(N / 2) <= k <= floor((N - 1) / 2)
S = q + k p
```

Recovery tests each candidate against both exact full aggregate points:

```
(q + k p) G1 == T1
(q + k p) G2 == T2
```

This gives `N` candidates when `N` is even and `N + 1` when `N` is odd. The
implementation walks them by repeated addition of the public points `p G1`
and `p G2`; it does not need a signed 263-bit secret-scalar multiplier.

Exactly one candidate must match. Two different carries matching either exact
full point would make `(k-k')p` divisible by that companion curve's order,
which is impossible over the bounded `uint32_t` roster interval.

After finding `S`, reduce it modulo each companion order, reject zero, and
center each residue:

```
z_j = S mod n_j
m_j = min(z_j, n_j - z_j)
```

Pack `(m1,m2)` with the canonical Purify mixed-radix encoding, derive the
public root, and require an exact match to `M` before decrypting any anchor
escrow.

## Mixed parent receipt

Member contributions remain out of band. The compact construction payload
retains, for each member, only its 66-byte share and 32-byte circuit
precommitment. The mixed recurrence starts from the canonical all-zero
545-byte claim, processes every setup leaf in roster order, then every anchor
leaf, and authenticates one final pending claim. Acceptance requires both the
recursive proof and the native final accumulation decision.

The post-cutover payload shape is:

```
version8 || recovery_root64 || setup_count32be || anchor_count32be
|| setup_entry[98 * N] || anchor_entry[128 * A]
```

The qualified mixed parent proof is 15,076 bytes:

```
15,149 + 98*N + 128*A bytes
```

At 100 setup members and 100 anchors this is 37,749 bytes. Payload v4,
statement v5, manifest v3, the checked mixed fixtures, proof length, suite,
and external verifier identity are qualified together. The stale centralized
artifact is not accepted.

## Security boundary

The construction relies on BP++ zero knowledge and knowledge soundness,
BIP327 rogue-key resistance, and discrete-log hardness in secp256k1 and both
Purify companion groups. It also makes an explicit auxiliary-input
assumption: recovering a common high-entropy scalar remains hard when its
public representations in all three groups are available.

Archived member contributions extend companion-curve security to individual
MuSig shares. A discrete-log break on either companion curve recovers `t_i`,
then `q_i`, then `x_i = a_i^-1 q_i mod p`. The previous aggregate setup
already placed the coalition aggregate key behind the companion curves; this
distributed construction extends that failure domain to member keys. This is
the principal tradeoff against a larger independently random encrypted-share
construction.

The roster and coefficients must be fixed before contributions are accepted.
A rushing last member cannot cancel an honest companion share while proving
the same fixed weighted secp discrete log without solving that companion
discrete log.

A fully malicious roster can pool its signing shares and learn the coalition
key without a conflict; no setup protocol can prevent that. With at least one
honest high-entropy member, the aggregate remains hidden under the stated
cross-group assumption.

Economic weight is not part of this cryptographic roster. If a member's anchor
becomes broken or has zero weight, Char assigns it zero economic weight but
does not delete or reorder its signed contribution. Historical receipt
verification and recovery continue to use the exact immutable signing roster.

The recovery root is deterministic for a roster. Binding a contribution to a
formation permit prevents transplanting it to a different permit. Purify does
not prove UTXO existence, consumption, or same-permit uniqueness; Char must
enforce one-shot permit consumption and permanent replay rules. A coalition
whose aggregate signing scalar has leaked must rotate signing keys before
reforming, because the same roster would reproduce an already compromised
recovery authority.

