# Anchor punishment-key escrow

Anchor escrow version 4 encrypts one existing BIP340 punishment scalar to a
coalition recovery root. It does not encrypt the anchor's Purify key and does
not derive the punishment key from that key.

Let:

- `M = (M1, M2)` be the coalition recovery root;
- `D` be the advertised anchor or nonce-host root;
- `k` be the anchor's normalized, even-Y BIP340 punishment scalar;
- `K = 02 || x(kG)` be its registered punishment public key; and
- `e = (e1, e2)` be a fresh Purify ephemeral secret with public root
  `E = (x(e1 G1), x(e2 G2))`.

The ciphertext is:

```
E
c = k + Combine(x(e1 M1), x(e2 M2))
```

The zero-knowledge relation proves that the same signed-window witnesses
`e1,e2`:

1. open the two coordinates of `E`;
2. produce the shared pad against `M`; and
3. satisfy the ciphertext equation for a scalar committed in public slot 0.

The public-commitment DLog proof binds slot 0 to the exact compressed point
`K`. Consequently an accepted record proves encryption of the registered
punishment scalar, rather than merely encryption of some scalar with a
prover-chosen public point.

`D` is authenticated statement metadata only. It is included in the v4
randomness statement, proof binding, and construction-receipt statement, but
there is deliberately no circuit relation between `D` and `k`. The anchor may
therefore retain its independent Purify nonce-host secret after its punishment
key is exposed. The public API rejects `D == M`, ruling out the detectable
case in which coalition exposure would directly reconstruct the advertised
anchor key as the coalition recovery key.

## Canonical key handling

`AnchorPunishmentKey::from_secret()` accepts a nonzero secp256k1 scalar and
normalizes it to the even-Y BIP340 representative. Proof creation accepts this
move-only typed key; there is no public API that derives it from an anchor
root.

Recovery first authenticates the complete escrow statement. The standalone
centralized recovery API derives the coalition recovery key directly from the
exposed coalition signing scalar. The selected construction path uses the
distributed setup instead and resolves the bounded centered-share carry
against the authenticated full companion-point aggregate. It then decrypts
`c` and checks both:

1. the decrypted 32 bytes already equal the normalized even-Y secret bytes;
2. that secret produces the exact registered x-only punishment key.

The first check is important: x-only public keys alone cannot distinguish
`k` from `-k`. A malleated ciphertext that decrypts to the odd-Y
representative is rejected before the public-key comparison.

## Transcript and framing

The scalar-only cutover is a new protocol suite. Old records are not accepted.

| Item | Selected value |
| --- | --- |
| Escrow record version | 4 |
| Construction payload version | 4 |
| Escrow binding domain | `Purify/Accountable/AnchorEscrow/v4` |
| Construction statement domain | `Purify/Accountable/ConstructionReceiptStatement/v5` |
| Accumulation domain | `Purify/Accountable/ConstructionLeafAccumulation/v1` |
| Parent-prover fixture frame | `Purify/Nova/Wit3` |

The randomness-statement, randomness-master, ephemeral, and proof-seed tags
also use their corresponding `/v4` domains. The proof suite requires the
modern tagged field-hash mode. A legacy-field-hash build may parse transport
syntax but rejects v4 proof construction, verification, preparation, and
recovery.

## Circuit and wire size

The semantic relation has 2,030 multiplication constraints and 510 signed
window bits. Lowering allocates one additional assignment gate for the output
scalar, so the circuit contains 2,031 gates before explicit padding to 8,192.
This retains the 16,384-element, 14-round norm-proof profile.

One independent escrow record is 1,233 bytes:

```
1 version + 96 ciphertext + 1,136 proof
```

The ciphertext is one 64-byte ephemeral root followed by one 32-byte masked
scalar. A construction payload is:

```
73 + 98*S + 128*A bytes
```

Each 98-byte setup entry contains a full signed recovery share and its exact
precommitment. Each 128-byte anchor entry contains the 96-byte ciphertext and
exact v4 circuit precommitment. Anchor references, roots, punishment keys, and
context digests are resolved from the registry and authenticated by the
construction statement rather than duplicated in the compact payload.

## Exposure boundary

Coalition-key exposure recovers each enrolled punishment scalar. The generic
Purify leaf does not associate that scalar with a roster member. Char must
bind each member's BIP340 roster point to the punishment key resolved for that
member's anchor. With that registry invariant, the recovered punishment
scalar is also the member response key. It is deliberately not the anchor's
Purify nonce-host secret.

The distinction matters for liveness. A public nonce proof exposes the nonce
point, not its scalar, so the response key and proof alone cannot produce a
response. A replacement can recover the raw nonce from an accepted response
for that exact nonce set, or use separately retained nonce-secret material.
Future slots still need the nonce-host secret, retained prepared nonces, or an
explicit exposed-member verifier rule. Otherwise the coalition must reform.
That runtime policy is outside the v4 leaf relation.

The construction parent acceptance API requires both recursive verification
and the native accumulation decision. The mixed profile and external verifier
identity are qualified, and artifact-backed acceptance exercises both stages.
Recursive validity never substitutes for the final native decision.
