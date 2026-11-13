# Public construction receipts for coalition escrow

A construction receipt is intended to compress independently published
coalition setup and anchor-escrow proofs into one authenticated parent result.
Child proofs are distributed out of band. The compact public payload retains
the data required to recover punishment keys after coalition exposure.

The native scalar-only anchor leaf and C++ two-stage acceptance boundary are
implemented. The current recurrence still derives its seed from the separate
centralized setup proof and processes only anchor leaves. Its matching
scalar-only verifier artifact is not qualified or published, so there is not
yet a production-accepted recursive receipt. The mixed distributed-setup
parent described below remains the cutover target.

Transparent setup is required. The selected parent path uses the accumulated
BP++ obligations as the authenticated recurrence input and requires a native
final decision. Recursive verification without that decision is not receipt
acceptance.

## Publication flow

The coalition publishes setup contributions for the exact ordered roster,
coalition core, nonce-host commitment, and recovery root `M`. Every anchor
owner independently publishes:

- its anchor reference and advertised root `D_i`;
- its registered BIP340 punishment key `K_i`;
- its application context;
- a 96-byte ciphertext `E_i`; and
- a v4 child proof binding the ciphertext to `M` and `K_i`.

An assembler may receive child records in any order, but the registry supplies
the authoritative ordered manifest. The assembler cannot omit, duplicate, or
substitute anchors and still produce the same construction statement.

Owners do not reveal their punishment keys, Purify keys, or the coalition
scalar to the assembler. They do not participate in a second proving round.

## Compact payload

Construction payload version 3 is:

```
version8 || recovery_root64 || count32be || entry[0] || ...
```

Each 128-byte entry is:

```
ephemeral_root64 || masked_punishment_scalar32 ||
circuit_precommitment32
```

The total serialized size is:

```
69 + 128*N bytes
```

The payload contains the ciphertexts, not merely their hashes, so Bitcoin-only
recovery remains possible if the out-of-band child proofs disappear. Anchor
references, advertised roots, punishment keys, and contexts are resolved from
the authenticated registry rather than duplicated in every compact entry.

## Authenticated statement

`construction_receipt_statement_digest()` uses
`Purify/Accountable/ConstructionReceiptStatement/v4` and commits to:

1. the exact serialized payload;
2. the immutable resolved setup-record digest; and
3. for each entry in payload order, the unique anchor reference, exact anchor
   root, exact compressed even-Y punishment key, and context digest.

The statement rejects a count mismatch, repeated anchor reference, repeated
anchor root, or repeated punishment key. The setup digest must resolve the
payload recovery root one-to-one to the registry record containing the exact
roster, coalition core, nonce-host commitment, and setup context.

The advertised anchor root is metadata authenticated by this statement and by
the child v4 binding. It is not a witness from which the punishment key is
derived. Child APIs also reject an anchor root equal to the coalition recovery
root, preventing the detectable recovery-key alias.

## Parent relation and acceptance

For verified ordered setup and anchor records, native preparation produces one
pending algebraic obligation per child. Parent constants are derived from the
same public circuit, ciphertext or full share, public output, context, and
child precommitment. The planned mixed recurrence starts from the canonical
empty claim and authenticates every setup leaf, every anchor leaf, the ordered
manifest, each transition, and the final claim.

The current anchor-only recurrence instead consumes a seed produced by the
independently verified centralized setup record. It does not recursively prove
that setup record.

The acceptance boundary is deliberately two-stage:

1. verify the purpose-specific recursive parent proof for the exact statement;
2. run the native accumulation decision for the authenticated final claim.

Only the conjunction returns a `VerifiedConstructionReceipt`. A claimed child
verification result, unconstrained Fiat-Shamir challenge, or recursive proof
without the final decision is insufficient.

## Recovery

After valid same-slot conflicting coalition certificates expose `q`:

```
q
 -> verify the registered coalition recovery root
 -> authenticate the construction receipt
 -> decrypt every payload ciphertext
 -> validate exact normalized punishment-secret bytes
 -> validate every registered punishment public key
```

The recovery path needs the compact payload, registry resolution, and accepted
parent result. It does not need the original child proof packets.

Char must bind each recovered punishment key to that member's BIP340 coalition
point. Recovery intentionally does not reveal the anchor's Purify nonce-host
secret. A public nonce proof is not secret nonce material. An accepted prior
response can reveal the raw nonce for that exact nonce set; future slots still
need retained nonce secrets, the nonce-host secret, or an explicit
exposed-member policy authenticated by the exposure record.

## Version boundary

The scalar-only protocol is an incompatible cutover:

| Component | Version/domain |
| --- | --- |
| Anchor escrow record | 4 |
| Construction payload | 3 |
| Anchor binding and randomness | `/v4` |
| Construction statement | `/v4` |
| Anchor accumulation basis | `/v4` |
| Parent-prover witness frame | `Purify/Nova/Wit2` |

Record v3, payload v2, old statement digests, old accumulation parameters, and
the `Wit1` parent fixture are not compatibility inputs. The Rust recurrence,
qualification vectors, relation ID, and verifier artifact must be regenerated
against this exact version set before release; old artifacts cannot qualify
the new statement.

## Size accounting

The public construction envelope contains:

```
69 + 128*N + size(parent_proof)
```

This excludes registry data already addressed by the statement, Bitcoin
carrier framing, and out-of-band child records. Each independent child record
is 1,233 bytes, but its 1,136-byte proof portion is consumed during
construction rather than repeated in the compact payload.

Parent proof and verifier-artifact sizes belong to the selected recurrence
profile and must be reported from the matching post-cutover qualification.
Numbers from the superseded full-root child relation are not estimates for the
v4 scalar-only profile.

## Integration boundary

Proof verification does not define coalition activation, consent, expiry,
stake accounting, conflict validity, or Bitcoin punishment spending rules.
Those remain Char registry and consensus responsibilities. In particular:

- the authoritative manifest must come from deterministic registry state;
- registry resolution must be immutable for the receipt's lifetime;
- a historical receipt remains usable after a member leaves;
- exposure must be established by the certificate-conflict rules; and
- accepted recovery must feed the actual punishment path before enrollment is
  enabled.

The parent proof compresses the cryptographic construction statement; it does
not replace these consensus checks.
