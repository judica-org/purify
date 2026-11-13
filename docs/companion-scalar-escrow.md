# Scalar escrow for existing anchors

This document records the design choice behind the selected
[anchor punishment-key escrow](anchor-punishment-relation.md).

An anchor's nonce-host secret and exposed punishment role are separated:

```
anchor root D       = existing Purify nonce-host identity
punishment key K    = existing normalized BIP340 key
coalition root M    = recipient derived from the coalition scalar
```

Coalition formation does not require regenerating `D`. The anchor owner
publishes a v4 proof that the scalar behind `K` is encrypted to `M`. The
advertised anchor root remains authenticated registry metadata. Char derives
its BIP340 signer from the nonce-host secret, but exposure is deliberately
one-way: learning that BIP340 scalar does not reveal the Purify secret.

## Why the escrow contains one scalar

The earlier prototype encrypted the full two-scalar `GeneratedKey` behind
`D`, then derived a punishment key from that recovered secret. That design:

- exposed the anchor's nonce-host secret when the coalition key leaked;
- required two ephemeral roots and two masked scalars;
- needed an additional constrained derivation relation; and
- coupled future nonce-host operations to the slashing key.

Version 4 removes that coupling. Its ciphertext is one Purify ephemeral root
and one masked secp256k1 scalar. The proof binds the decrypted scalar directly
to the registered even-Y BIP340 punishment point. The former record-v3,
1,329-byte full-root format is superseded and is not accepted as v4.

## Publication flow

Each owner can produce its child record independently:

1. resolve the exact recovery-bound coalition roster and recipient `M`;
2. select the already registered typed punishment key `k,K`;
3. bind the anchor reference/root and application context;
4. encrypt `k` to `M` with a fresh hedged ephemeral key;
5. prove the ciphertext relation and public output `K`; and
6. distribute the child record out of band.

The construction assembler needs only public records. It does not receive
`k`, the ephemeral secret, the coalition scalar, or the anchor's Purify
secret. It prepares each child proof, builds the ordered public payload, and
uses the parent proving path to authenticate the accumulated obligations.

The compact receipt payload retains the ciphertexts because later recovery
must work from Bitcoin and authenticated registry data after the out-of-band
children disappear. Hashes of unavailable ciphertexts would be insufficient.

## Recovery boundary

After a valid same-slot conflict exposes the coalition scalar `q`, recovery:

1. verifies `q` against the registered recovery setup, using direct
   derivation for the current centralized setup or the authenticated full
   share aggregate and bounded carry search for distributed setup;
2. verifies the child proof, or consumes a verified construction parent;
3. derives the coalition recovery key from `q`;
4. decrypts each punishment scalar; and
5. checks its exact normalized bytes and registered x-only public key.

The protocol rejects an advertised anchor root equal to the coalition
recovery root. This prevents the detectable alias where revealing `q` itself
would reconstruct the anchor's full Purify key. The protocol cannot prove
abstract independence of separately encoded secrets, but it does not create a
derivation path between them.

Published escrow is intentionally persistent. Leaving a coalition does not
erase a historical ciphertext or remove liability for statements made while
the receipt was active. Activation, expiry, stake accounting, and formation
UTXO rules belong to the Char registry and consensus layers.

## Size

For `N` anchors:

| Object | Bytes |
| --- | ---: |
| One ciphertext | 96 |
| One independent child record | 1,233 |
| One compact payload entry | 128 |
| Compact payload | `69 + 128*N` |

The 32 bytes after each payload ciphertext are its exact circuit
precommitment. The independent 1,136-byte proof payload is an out-of-band
input to construction and is not repeated in the compact payload.

The final construction proof is additional to `69 + 128*N`. Its qualified
profile and verifier artifact are properties of the parent backend, not of
the scalar ciphertext.

## What exposure does and does not provide

Char must bind the recovered punishment key to that member's BIP340 coalition
signing point. With that invariant it recovers the response scalar. An
authorized public nonce proof is not itself usable nonce material: it exposes
the point, not the raw nonce. A prior accepted response for the same nonce set
can reveal that nonce, and separately retained nonce secrets remain usable.
The punishment scalar is not the anchor's Purify nonce-host secret, so it
cannot produce fresh registered nonce proofs.

Char must either reform the coalition once pre-authorized nonce material is
exhausted or define an explicit exposed-member nonce rule tied to an
authenticated exposure record. Such a rule must not be silently inferred from
successful v4 decryption.
