# Scalar-only accountable signature transcript

This contract defines the public transcript, 32-byte response codec, and key
recovery equation for
[Purify issue #20](https://github.com/judica-org/purify/issues/20). The typed
response API composes it with the ordered coalition roster and exact
PureSign++ nonce proofs. It does not implement the secret multiparty signer,
transport, durable release state, semantic conflict policy, or a final
recursive certificate.

`accountable::reconstruct_nonce` remains a low-level algebra primitive: it
returns a point, not an accepted signature. The proof-attested path uses
`VerifiedCoalitionNonceSet` and `VerifiedScalarResponse`, whose constructors
are private and whose verifiers check the exact external nonce points.

The [ordered roster](accountable-rosters.md) and
[verified response helpers](accountable-responses.md) implement public-key
aggregation, nonce-proof acceptance, response equations, and typed conflict
extraction for this transcript.

## Public context and exact encoding

Let `n` be the secp256k1 group order and `G` its standard generator. The
registered signing key is `Q = qG`, represented as exactly 32 big-endian
x-coordinate bytes with an even-Y lift. The private signing scalar must
correspond to that same lift. Non-lifting or out-of-range coordinates reject.
No caller-selected key tweak is supported by this transcript.

`U` is exactly 32 bytes committing to the registered, ordered PureSign++ hosts
and roster. `D` is exactly 32 bytes committing to the immutable coalition core
and pre-proof setup context. Neither contains secret material. The application
must authenticate `Q`, `U`, and `D` against its fixed registry or snapshot and
verify member consent and registration authorization. Hashing arbitrary values
does not establish those facts.

`T` is a nonempty canonical application conflict-slot encoding. It must bind
the application suite and version, domain, applicable electorate, epoch or
slot, and handoff context required by the accountability contract. Competing
decision bodies for one slashable slot use exactly the same `T`. A
message-dependent candidate hash, local attempt ID, proof randomizer, tree
identifier, or certificate batch must not create a fresh slot.

`m` is the canonical semantic decision body, supplied as an arbitrary byte
span. This layer permits an empty body; the application decides which bodies
and conflicts are admissible. Both byte spans must remain alive during API
calls.

Define `len64(x)` as the length of `x` encoded in eight unsigned big-endian
bytes. Lengths above `2^64-1` reject. Define:

```text
C = Q_x[32] || U[32] || D[32] || len64(T) || T
S = C || len64(m) || m
tagged(tag, x) = SHA256(SHA256(tag) || SHA256(tag) || x)

nonce_input = tagged("Purify/Accountable/Nonce/v2", C)
e = int_be(tagged("Purify/Accountable/Challenge/v2", S)) mod n
```

The literal tags are ASCII without a terminator. There are no omitted framing
bytes or native-endian integers. The tags separate nonce evaluation from the
signature challenge. An honest signer and verifier reject the negligible
`e = 0` case rather than changing `T` or adding an attempt counter.

`nonce_evaluation_input` supplies `nonce_input` to every registered
PureSign++ host. The body and proof encoding never enter this input.
`verify_coalition_nonce_set` requires exactly one proof per ordered host,
verifies each proof for this input, retains its exact full compressed point,
and sums those points without x-only normalization.

## Scalar trace and reconstructed nonce

For a raw deterministic nonce `r_T`:

```text
sigma = r_T + e*q mod n
R = sigma*G - e*Q
```

`ScalarSignature` parses exactly 32 unsigned big-endian bytes in `[0,n)`. It
rejects overflow, short encodings, and trailing data. Zero is a valid response
encoding; validity still requires the nonce proof. Its complete serialization
is those 32 bytes, with no prefix, nonce point, proof, or alias field.

`reconstruct_nonce` computes `e` from the full context and body, lifts `Q` to
its even-Y point, and returns the exact 33-byte compressed representation of
`R`. It rejects infinity. Both even and odd `R` are meaningful; the raw nonce
is not negated or normalized. The typed verifier does not accept either sign
interchangeably.

This transcript does not alter the existing BIP340 PureSign formats or claim
that those signatures satisfy this construction. It uses separate v2 tags and
has no backward-compatibility codec.

## Proof-attested response interface

The accepted-response path begins with a `NonceHostBoundSigningRoster`, the
exact `nonce_input`, and one `NonceProof` for every ordered host.
`verify_coalition_nonce_set` verifies those proofs and returns a
`VerifiedCoalitionNonceSet` bound to `Q`, `U`, `D`, `T`, and every full nonce
point. Missing, reordered, substituted, opposite-sign, or wrong-topic points
reject.

`verify_partial_response` checks one member's scalar against its verified
nonce and roster coefficient. `aggregate_responses` checks one partial per
member and returns a `VerifiedScalarResponse` only if the reconstructed
aggregate point equals the proof-attested sum. `verify_scalar_response`
provides the same final check for an already aggregated scalar.

Only the signature challenge excludes `R`. Each nonce proof still binds its
exact full point and proof transcript. Omitting `R` from the 32-byte scalar
response therefore does not let a caller substitute a fresh nonce in the
typed acceptance path.

## Conflict extraction and low-level helpers

Given two accepted conflicting responses with the same `Q`, `U`, `D`, `T`,
and raw nonce, and distinct challenges:

```text
q = (sigma - sigma') * inverse(e - e') mod n
```

`recover_verified_same_slot_key` accepts only two
`VerifiedScalarResponse` values. It requires identical registry bindings,
slot, and exact full aggregate nonce, rejects equal bodies or challenges, and
checks the recovered full point against the even-Y `Q`. Success returns an
`ExposedCoalitionKey`; it does not decide whether the bodies are semantically
conflicting or whether a penalty is authorized.

`recover_same_slot_key` implements the same algebra under one caller-supplied
context. It checks the recovered point and common nonce, but accepts no proof
capability. Together with `reconstruct_nonce`, it remains available for
vectors and low-level analysis and must not be used as a certificate-acceptance
shortcut.

Registration authorization, semantic conflict, and liability remain
application rules. A matching signing key alone is insufficient across slots,
because arbitrary future slots do not generally share `r_T`.

## Signing obligations

The library does not yet provide the secret multiparty signing protocol. Each
participant must durably authorize the exact body and challenge and validate
proof readiness before releasing a partial response. Session reservation,
abort handling, transport, and release policy belong to that signer.

A complete protocol argument must also cover malicious enrollment, concurrent
sessions, aborts, and adaptive transcript choices. Signing shares, PureSign++
host secrets, punishment scalars, and transport keys remain distinct roles,
including for a singleton coalition.

## Independent vectors and validation

`python3 tests/reference_accountable_vectors.py` independently regenerates the
public transcript vectors embedded in `accountable_signature_tests.cpp`. The
fixtures use toy public scalars and compare exact v2 transcript hashes, scalar
bytes, full nonce points, and low-level key recovery in both response orders.

The accountable-response suite separately exercises proof-attested singleton
and multi-member acceptance, exact nonce parity, fresh-nonce rejection, typed
responses, and typed extraction. These tests do not establish registration,
semantic conflict, or a complete multiparty security proof.

Run the focused suites with:

```text
cmake --build build --parallel 4
ctest --test-dir build \
    -R '^purify.tests.(accountable_signature|accountable_response)$' \
    --output-on-failure
```
