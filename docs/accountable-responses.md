# Verified coalition nonce responses

The accountable response API connects the ordered signing roster, exact
PureSign++ deterministic-nonce proofs, scalar-only responses, and conflict
extraction. The accepted-response path uses capability types with private
constructors; a caller cannot promote an arbitrary nonce point or scalar into
an accepted response. The optional recovery-root setup is not required for
this path.

## Registered nonce hosts

Each roster member has one ordered `puresign_plusplus::PublicKey` bundle. The
32-byte `NonceHostCommitment` hashes a domain-separated fixed encoding of the
roster key, list hash, member count, every full 33-byte member key, and every
96-byte host bundle. Construction rejects:

- a host/member count mismatch;
- duplicate Purify roots;
- malformed bundle keys; and
- any member key other than the even point `02 || bundle.bip340_pubkey`.

`bind_formation_nonce_hosts` is the Bitcoin registration constructor. It
validates the ordered host bundles, computes this exact commitment, and binds
the result to a typed one-shot `CoalitionFormation`. The lower-level
`bind_nonce_hosts` accepts an already authenticated raw core for generic
protocols and resolved registry data; it does not establish formation replay
resistance. Both return `NonceHostBoundSigningRoster`, which retains the
coalition core digest alongside the roster and host commitment. The optional
recovery-root setup produces the stronger `RecoveryBoundSigningRoster`, which
is also usable anywhere the base nonce-host-bound capability is required.

## Proof-attested full nonces

For one `ConflictContext`, `nonce_evaluation_input` derives the 32-byte
PureSign++ topic from the exact aggregate key `Q`, host commitment `U`,
coalition core digest, and slot. `verify_coalition_nonce_set` first requires
all three registry values to match its nonce-host-bound roster, then requires
exactly one topic `NonceProof` for every ordered host and verifies all of them.
It retains each proof's full 33-byte `commitment_point`, sums those exact
points, and rejects an aggregate at infinity.

Success returns `VerifiedCoalitionNonceSet`. Its constructor is private and it
stores `Q`, `U`, the coalition core digest, the derived topic, and every full
nonce point. It cannot be reused with another roster, core, or slot. X-only
equality is insufficient: an opposite-Y point is a different nonce and
rejects.

PureSign++ exposes two nonce-scalar views deliberately. `scalar()` is the
even-Y BIP340 normalization. `raw_scalar()` is the scalar for the proof's full
compressed `commitment_point`; it negates the normalized scalar for an odd
point. Accountable response creation must use `raw_scalar()`.

## Scalar-only response acceptance

`PartialResponse` contains only the canonical scalar `sigma_i`. For member
`i`, with full public key `P_i`, effective roster coefficient `b_i`, verified
raw nonce `R_i`, and statement challenge `e`, acceptance checks:

```text
R_i = sigma_i*G - (e*b_i)*P_i
```

`aggregate_responses` requires one partial in roster order, checks every
equation against the verified nonce set, sums the scalars, and reconstructs:

```text
sigma = sum_i sigma_i mod n
R     = sigma*G - e*Q
```

The reconstructed full point must equal the set's exact aggregate nonce.
Success returns `VerifiedScalarResponse`, not a naked accepted scalar. The
wire response remains 32 bytes; nonce proofs and host bundles are separate
certificate inputs.

`verify_scalar_response` performs the same final acceptance when a caller
already has an aggregate scalar. This closes the fresh-nonce attack by an
all-malicious roster: a scalar formed with another nonce reconstructs a
different full point and cannot become a second accepted response for the
fixed proof set.

## Typed conflict extraction

`recover_verified_same_slot_key` accepts only two `VerifiedScalarResponse`
values. It requires identical `Q`, `U`, coalition core digest, slot, and exact
full aggregate nonce, plus distinct bodies and challenges. It performs the
public extraction equation and verifies the exact point `qG = Q`. Success
returns an `ExposedCoalitionKey` containing the exact aggregate scalar and its
registry bindings. Deployments that registered a recovery root can validate
that scalar against the stronger `RecoveryBoundSigningRoster` before
companion-key or anchor recovery.

The lower-level `reconstruct_nonce` and `recover_same_slot_key` helpers remain
available for algebraic vectors. They do not create the accepted capability
types and must not be used as certificate-acceptance shortcuts.

## Remaining protocol obligations

These APIs establish deterministic-nonce proof acceptance, exact response
composition, and cryptographic conflict extraction. They do not by themselves
establish registration authorization, member consent, semantic conflict,
liability, durable pre-release signing state, or transport policy. The
optional recovery-root setup prover currently receives the aggregate scalar
centrally; a distributed setup protocol is a separate requirement for
deployments that choose the experimental general-escrow path. It is not a
dependency of accountable response extraction. A final recursive certificate
and the secret multiparty signing protocol also remain separate components.

The focused tests cover honest singleton and multi-member flows, odd raw nonce
parity, missing/swapped/reordered proofs and hosts, duplicate hosts, changed
`Q`/`U`/core/slot, replay across separately bound cores with the same `Q` and
`U`, opposite full-point parity, scalar-only aggregation, attempted fresh
nonces by an all-malicious roster, typed extraction, and recovery-root opening.
