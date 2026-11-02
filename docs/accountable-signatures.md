# Scalar-only accountable signature transcript

This contract defines the public transcript, 32-byte response codec, and key
recovery equation for
[Purify issue #20](https://github.com/judica-org/purify/issues/20). The typed
response API composes it with the ordered coalition roster and exact
PureSign++ nonce proofs. It does not implement the secret multiparty signer,
MuSig2 transport, durable release state, semantic conflict policy, or a final
recursive certificate.

`accountable::reconstruct_nonce` remains a low-level algebra primitive: it
returns a point, not an accepted signature. Production leaf acceptance uses
`VerifiedCoalitionNonceSet` and `VerifiedScalarResponse`, whose constructors
are private and whose verifier checks the exact external nonce points.

The [ordered roster](accountable-rosters.md) and
[verified response helpers](accountable-responses.md) implement public-key
aggregation, nonce-proof acceptance, response equations, and typed conflict
extraction for this transcript.

## Public context and exact encoding

Let `n` be the secp256k1 group order and `G` its standard generator. The registered
signing key is `Q = qG`, represented as exactly 32 big-endian x-coordinate bytes
with an even-Y lift. The private signing scalar must correspond to that same
lift. Non-lifting or out-of-range coordinates reject. No caller-selected key
tweak is supported by this candidate transcript.

`U` is exactly 32 bytes committing to the registered, ordered Purify hosts and
roster. It contains no secret material. `D` is exactly 32 bytes committing to
the immutable coalition core and pre-proof setup context. The application must
authenticate `Q`, `U`, and `D` against its fixed registry/snapshot and verify
the roster's canonical encoding, member consent, key aggregation rules, and
key/host associations. Hashing arbitrary commitments does not establish any of
those facts. Registration and rogue-key defenses remain separate requirements.

`T` is a nonempty canonical application conflict-slot encoding. It must bind the
application suite/version, domain, applicable electorate, epoch/slot and handoff
context required by the accountability contract. Competing decision bodies for
one slashable slot use exactly the same `T`. A message-dependent candidate hash,
local attempt ID, proof randomizer, tree identifier, or certificate batch must
not provide a fresh slot. An epoch change alone cannot override the handoff
contract for an unresolved slot.

`m` is the canonical semantic decision body, supplied as an arbitrary byte span.
This layer permits an empty body; the application decides which bodies and
conflicts are admissible. Both byte spans must remain alive during API calls.

Define `len64(x)` as the length of `x` encoded in eight unsigned big-endian bytes.
Lengths above `2^64-1` reject. Define:

```
C = Q_x[32] || U[32] || D[32] || len64(T) || T
S = C || len64(m) || m
tagged(tag, x) = SHA256(SHA256(tag) || SHA256(tag) || x)

nonce_input = tagged("Purify/Accountable/Nonce/v2", C)
e = int_be(tagged("Purify/Accountable/Challenge/v2", S)) mod n
```

The literal tags are ASCII without a terminator. There are no omitted framing
bytes or native-endian integers. The tags separate nonce evaluation from the
signature challenge and identify this candidate version. The application suite
is additionally bound through `T`; these bytes are not yet a frozen consensus
format. An honest signer and verifier reject the negligible `e = 0` case rather
than changing `T` or adding an attempt counter to retry the same decision.

`nonce_evaluation_input` supplies the 32 bytes to each registered PureSign++
host. The body and proof representation never enter this input.
`verify_coalition_nonce_set` requires exactly one proof per ordered host,
verifies each proof for this input, retains its exact full compressed point,
and sums those points without x-only normalization. Host enrollment and
application authorization remain registration policy; the relationship
between accepted proof outputs and the aggregate nonce is enforced here.

## Scalar trace and reconstructed nonce

For a raw deterministic nonce `r_T`:

```
sigma = r_T + e*q mod n
R = sigma*G - e*Q
```

`ScalarSignature` parses exactly 32 unsigned big-endian bytes in `[0,n)`. It
rejects overflow, short encodings and trailing data. Zero is a valid response
encoding; validity still requires the nonce proof. Its entire serialization is
those 32 bytes, with no prefix, nonce point, proof, or hidden alias field.

`reconstruct_nonce` computes `e` from the full context and body, lifts `Q` to its
even-Y point, and returns the exact 33-byte compressed SEC1 representation of
`R`. It rejects infinity. Both even and odd `R` are meaningful outputs; the raw
nonce is not negated or normalized. The typed verifier does not accept either
sign interchangeably. Since nonzero `e` and a valid `Q` make `-eQ` nonidentity,
`sigma = 0` is handled normally as `R = -eQ`.

The new trace codec does not alter the existing BIP340 PureSign formats or
claim that those signature proofs satisfy this construction. It is a separate
experimental protocol with its own tags and no backward-compatibility codec.

## Implemented nonce-proof interface

The verifier receives the authenticated host roster, the exact
`nonce_input`, the full reconstructed point `R`, the selected proof suite and
completed proof bytes. The proof must establish the required relation against
that external point. `verify_coalition_nonce_set` supplies this interface for
PureSign++ and rejects missing, reordered, substituted, opposite-sign, or
wrong-topic points. The scalar response carries no duplicate `R`; verification
reconstructs it from `sigma`, `e`, and `Q` and compares the exact full point.

Only the signature challenge excludes `R`. The nonce proof's Fiat-Shamir
transcript still binds `R`, its circuit/relation, generators, host/context
inputs, and all commitments needed by the construction. V3 commits raw
circuit coordinates before deriving fold weights and binds each advertised
public point through a transcript-derived batched DLog check. In the
random-oracle and algebraic-group model, the latter adds approximately
`(m-1)/q` soundness loss for `m` batched openings. A later recursive parent
must prove acceptance of this same statement and its semantic coverage; it
cannot repair an unsound leaf relation.

The earlier generic arithmetic wrapper permitted output blinding and therefore
did not establish this exact-point property merely because its honest prover
used a zero blind. The V3 public-point proof and typed nonce-set verifier close
that leaf-level gap. This does not by itself authenticate coalition
registration or prove that two bodies are economically slashable.

## Conditional extraction and signing obligations

Given two fully accepted conflicting endorsements with the same `Q`, `U`, `D`,
`T`, a proven common raw nonce, and distinct challenges:

```
q = (sigma - sigma') * inverse(e - e') mod n
```

`recover_same_slot_key` implements the algebraic part of this operation under
one supplied `Q/U/D/T` context. It rejects equal challenges before inversion and
compares the full recovered public point against the even-Y lift of `Q`. It
never normalizes a recovered `-q` into an accepted result. Exact `qG = Q` implies
that the two reconstructed nonce points are equal; checking
`sigma - e*q != 0` then excludes a common nonce at infinity without repeating
the point reconstructions. A zero response remains permitted when that common
nonce is finite. The returned 32 bytes are derived entirely from public inputs.

Recovery through this low-level algebra helper establishes the exposed scalar,
not certificate acceptance, semantic conflict, or liability. Production code
uses `VerifiedCoalitionNonceSet`, `VerifiedScalarResponse`, and
`recover_verified_same_slot_key` from the
[verified response API](accountable-responses.md). Those capability types bind
the accepted PureSign++ proofs and exact full nonce before extraction.
Arbitrary future slots do not generally share `r_T`; a matching signing key
alone is insufficient.

The helper propagates context/challenge errors. Equal challenges return
`BindingMismatch`; a zero or wrong recovered key returns `EquationMismatch`;
a common nonce at infinity returns `RangeViolation`. It intentionally accepts
no proof bytes because it is retained as a low-level vector primitive, not the
production acceptance entry point.

No-framing for one honest member, malicious enrollment, concurrent sessions,
abort, and adaptive proof/transcript choices remains to be established for the
complete protocol. Signing shares, Purify host secrets, punishment scalars and
transport keys must retain their distinct roles, even for a singleton. The
future signer needs owned secret types and a reviewed aggregation protocol;
the public `FieldElement` arithmetic used by the reference tests is not that
secret-key interface.

`e` can be reserved before the aggregate nonce is known. This does not authorize
early partial release. Each participant still needs durable authorization for
the exact body/challenge and the reviewed nonce/proof protocol readiness
boundary before exposing a partial. Storage, reservation, abort and release
semantics belong to the later signer integration.

## Independent vectors and validation

`python3 tests/reference_accountable_vectors.py` uses Python integers,
`hashlib`, and independent affine secp256k1 arithmetic to regenerate the public
vectors embedded in `accountable_signature_tests.cpp`. It uses the public toy
key `q = 3` and raw nonce `r = 6`; the nonce has odd Y. It checks both reconstruction
equations, and the C++ tests compare exact transcript hashes, scalar bytes and
full nonce points before checking exact key recovery in both response orders.

These are algebraic and encoding fixtures, not accepted cryptographic
certificates or evidence of proof soundness. They require no private deployment
keys, signer service, or proof backend. Additional tests cover field boundaries,
length framing, invalid context, zero responses, infinity rejection, and changed
statement reconstruction. The zero-challenge branch is specified but has no
engineered hash preimage or test-only injection hook.

Run the focused C++ suite with:

```
cmake --build build --parallel 4
ctest --test-dir build -R '^purify.tests.accountable_signature$' \
    --output-on-failure
```
