# One-shot Bitcoin coalition formation

Accountable proofs already bind a 32-byte coalition core. A Bitcoin registry
can make that core non-replayable by deriving it from a predecessor output that
the formation transaction consumes. Bitcoin then supplies the one-time
linearization point; Purify supplies the cryptographic context binding.

This design prevents stale formation consent from reviving a dissolved
coalition. It does not prevent every member from deliberately forming a new
coalition with a fresh permit and fresh consent.

## Formation identity

`accountable::CoalitionFormation` first derives a manifest-independent permit
identifier, then the coalition core:

```text
permit_id = TaggedSHA256(
              "Purify/Accountable/CoalitionPermit/v1",
              bitcoin_genesis_hash32 ||
              deployment_id32 ||
              permit_txid32 ||
              permit_vout_u32le)

D = TaggedSHA256(
      "Purify/Accountable/CoalitionFormation/v1",
      permit_id || manifest_digest32)
```

Every field has fixed width. `bitcoin_genesis_hash32` and `permit_txid32` are
the raw `uint256` bytes emitted by Bitcoin consensus serialization. They are
not RPC display-order hex. The explicit genesis hash prevents cross-network
replay. `deployment_id32` separates Char deployments sharing one Bitcoin
network.

The permit is the exact pre-existing output consumed by the transaction that
finalizes formation. It is not an output of that transaction. Hashing the
formation transaction's own txid would be circular because that transaction
commits the record containing `D` and its dependent proofs.

The canonical formation claim declares this exact outpoint. A transaction may
have any number of inputs; Char does not infer the permit from input position
or select the first otherwise-eligible input. It instead requires that one of
the transaction's inputs exactly matches the outpoint declared by the claim.

`manifest_digest32` commits the canonical, immutable, acyclic formation
intent. The Char manifest should include every semantic identity and policy
field not bound independently, including its version, ordered members, bond
references, signing and management keys, nonce-host keys, and lifecycle
policy. It must exclude:

- the formation transaction ID or witness transaction ID;
- any setup proof whose transcript contains `D`;
- anchor ciphertexts or proofs generated from a roster containing `D`;
- a complete-record hash containing those dependent values; and
- any receipt or certificate that commits `D`.

A separate record-body hash may authenticate ciphertexts, proofs, and carrier
framing. Its preimage excludes the authorizations themselves. Each member
formation authorization binds both `D` and that exact record-body hash. The
aggregate slashable signing key is not a formation or management authorization
key: exposure of that scalar must not let an attacker register a fresh
instance.

## Char acceptance rule

Purify validates the null-outpoint boundary and derives `D`. It cannot decide
whether a Bitcoin transaction actually consumed the permit. Char accepts a
formation only when all of these conditions hold:

1. The canonical record and all member authorizations validate.
2. The record's `D` recomputes from the manifest and the declared permit.
3. The transaction completing the record consumes that exact permit.
4. That transaction contains exactly one formation claim for `permit_id` in
   this deployment.
5. Confirmation and epoch-delay rules make the record active only at their
   specified boundary.

The fourth rule covers two different manifests placed in the same transaction.
Bitcoin's double-spend rule covers claims placed in conflicting transactions;
only the transaction in the canonical chain can complete formation. No second
historical uniqueness index is needed beyond ordinary canonical-chain state.

If a large record is assembled from earlier chunks, those chunks have no
registry effect. The final transaction must spend the permit and commit the
complete canonical record. Keeping completion at this one linearization point
avoids a separate reservation or rollback protocol.

The registry state for one core is monotonic within a canonical history:

```text
unseen -> pending -> active -> dissolved
```

There is no `dissolved -> active` transition. A destroy message binds `D`, is
authorized by the separate management role, and changes only future
eligibility after the protocol delay. It does not erase old escrow,
certificates, signing reservations, or liability. A replacement is a new
formation with a fresh permit, a new `D`, and fresh member authorization.

A destroy is valid only after its formation has completed earlier in Bitcoin
transaction order. A destroy in the formation transaction or before formation
is invalid, including in an earlier transaction of the same block. Multiple
valid destroys are idempotent and cannot move the first effective destruction
boundary. Within a block, Char applies transactions in Bitcoin block order and
records within one transaction in their canonical carrier order.

## Replay and chain behavior

- Copying an old record into a later transaction fails because the later
  transaction does not consume the bound permit.
- Substituting a fresh permit changes `D`, invalidating the old setup,
  escrow, nonce, response, and member-authorization contexts.
- Reposting the original transaction cannot create a second transition in one
  valid Bitcoin history because its input is already spent.
- Fee replacement may preserve `D` when it preserves the permit, manifest,
  and authenticated record-body commitment. Fee and change edits outside that
  committed body require no fresh member authorization. The canonical
  confirmed transaction supplies the inclusion position.
- A disconnect rolls formation and destruction state back with the Bitcoin
  block. Re-inclusion on the replacement branch is ordinary canonical-chain
  processing, not resurrection in one history.
- Spending the permit elsewhere aborts formation. That is a liveness failure,
  not an ambiguous registry state.

An entirely malicious roster can always use a fresh UTXO and authorize a new
instance. Preventing that would require a permanent ban keyed by a stable
member or roster identity, adding the historical proving surface this design
is intended to avoid. The enforceable invariant is that old consent and old
proofs cannot authorize a new instance.

## Light-client boundary

The consumed-permit rule is a positive, transaction-local check. A syncing
client verifies the complete formation commitment and finds the exact permit
among that transaction's inputs. It does not prove that a referenced state
coin remains unspent, nor search for a global first-registration winner.

This assumes the client follows a Bitcoin chain whose transactions satisfy
Bitcoin consensus. A full validator proves that the permit was a live UTXO. An
SPV client instead assumes the most-work header chain contains only valid
transactions; finding the prevout in `vin` is not an independent UTXO proof.

A txid Merkle proof alone does not authenticate SegWit witness bytes. A block
witness commitment is not by itself a convenient per-transaction witness
proof. The simplest light-client format places the complete-record commitment
in txid-committed output data. A witness carrier requires full witness data or
an equally explicit authenticated proof. Purify deliberately does not select
that carrier.

A confirmed formation permit is the operational default. An unconfirmed
permit is cryptographically valid but parent replacement or malleation can
invalidate expensive proofs prepared against its transaction ID.

The derivation adds no proof or receipt bytes. The genesis and deployment are
protocol constants, and the permit is serialized once by the formation claim.
A carrier need not repeat them inside every dependent proof while still
recomputing `D` at the registry boundary.
