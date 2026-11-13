# Public construction receipts for coalition escrow

A construction receipt is intended to compress independently published
coalition setup and anchor-escrow proofs into one authenticated parent result.
Child proofs are distributed out of band. The compact public payload retains
the data required to recover punishment keys after coalition exposure.

The mixed distributed-setup relation, native leaf adapters, recursive verifier
boundary, and fixture codec are implemented. The matching verifier artifact
has not been requalified or published, so there is not yet a
production-accepted recursive receipt. The old centralized, anchor-only
artifact is deliberately rejected.

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

Construction payload version 4 is:

```
version8 || recovery_root64 || setup_count32be || anchor_count32be
|| setup_entry[0] || ... || anchor_entry[0] || ...
```

Each 98-byte setup entry is:

```
full_signed_recovery_share66 || circuit_precommitment32
```

Each 128-byte anchor entry is:

```
ephemeral_root64 || masked_punishment_scalar32 ||
circuit_precommitment32
```

The total serialized size is:

```
73 + 98*N + 128*A bytes
```

The payload contains the ciphertexts, not merely their hashes, so Bitcoin-only
recovery remains possible if the out-of-band child proofs disappear. Anchor
references, advertised roots, punishment keys, and contexts are resolved from
the authenticated registry rather than duplicated in every compact entry.

## Authenticated statement

`construction_receipt_statement_digest()` uses
`Purify/Accountable/ConstructionReceiptStatement/v5` and commits to:

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

For ordered setup and anchor records, native preparation produces one pending
algebraic obligation per child. Parent constants are derived from the same
public circuit, ciphertext or full share, public output, context, and child
precommitment. The mixed recurrence starts from the canonical all-zero
545-byte claim, authenticates every setup leaf in roster order, then every
anchor leaf in registry order, and returns one final pending claim. There is no
centralized setup proof, caller-provided seed, or proof promotion step.

The public manifest binds both phase counts. The recurrence is homogeneous and
has no phase field; the C++ verifier enforces the boundary by deriving exactly
`N` typed setup descriptors followed by exactly `A` typed anchor descriptors.

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
point. After the conflict has exposed the coalition signing scalar, selected
receipt recovery reveals only the enrolled punishment/signing scalars. It
never reveals an anchor's Purify nonce-host secret. A public nonce proof is not
secret nonce material. An accepted prior response can reveal the raw nonce for
that exact nonce set; future slots still need retained nonce secrets, the
nonce-host secret, or an explicit exposed-member policy authenticated by the
exposure record.

## Version boundary

The scalar-only protocol is an incompatible cutover:

| Component | Version/domain |
| --- | --- |
| Anchor escrow record | 4 |
| Recovery contribution record | 1 |
| Construction payload | 4 |
| Anchor binding and randomness | `/v4` |
| Construction statement | `/v5` |
| Construction leaf basis | `Purify/Accountable/ConstructionLeafAccumulation/v1` |
| Construction manifest | `Purify/Accountable/ConstructionParentManifest/v3/{init,leaf}` |
| Parent-prover witness frame | `Purify/Nova/Wit3` |

Old payloads, statement digests, accumulation parameters, centralized seeds,
and `Wit1`/`Wit2` parent fixtures are not compatibility inputs. The verifier
artifact must be regenerated and qualified against this exact version set
before release; old artifacts cannot qualify the new statement.

## Size accounting

The public construction envelope contains:

```
73 + 98*N + 128*A + size(parent_proof)
```

This excludes registry data already addressed by the statement, Bitcoin
carrier framing, and out-of-band child records. Each anchor record is 1,233
bytes and each setup contribution is 1,203 bytes; their proof bodies are
consumed during construction rather than repeated in the compact payload.

The envelope currently reserves the prior 15,076-byte proof length, giving the
provisional total `15,149 + 98*N + 128*A`. This is transport scaffolding, not a
new qualification result. Parent-proof and verifier-artifact sizes must be
re-pinned from the matching post-cutover qualification.

## Integration boundary

Proof verification does not define coalition activation, consent, expiry,
stake accounting, conflict validity, or Bitcoin punishment spending rules.
Those remain Char registry and consensus responsibilities. In particular:

- every raw anchor remains an implicit one-member coalition when no explicit
  coalition covers it;
- a zero-weight or broken member contributes zero economic weight without
  being deleted from or reordering the immutable signing roster;
- the authoritative manifest must come from deterministic registry state;
- registry resolution must be immutable for the receipt's lifetime;
- a historical receipt remains usable after a member leaves;
- exposure must be established by the certificate-conflict rules; and
- accepted recovery must feed the actual punishment path before enrollment is
  enabled.

The parent proof compresses the cryptographic construction statement; it does
not replace these consensus checks.
