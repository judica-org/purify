# Scalar-only accountable signature transcript

This experimental contract implements the public transcript, response codec,
and algebraic key recovery for
[Purify issue #20](https://github.com/judica-org/purify/issues/20). It does not
implement a production signer, a nonce-proof verifier, MuSig aggregation, or a
security proof. In particular,
`accountable::reconstruct_nonce` returns an algebraic point, never a successful
signature-verification result. Live use awaits the reviewed leaf relation,
signature/proof composition, private multiparty protocol, and durable signing
rules.

## Public context and exact encoding

Let `n` be the secp256k1 group order and `G` its standard generator. The registered
signing key is `Q = qG`, represented as exactly 32 big-endian x-coordinate bytes
with an even-Y lift. The private signing scalar must correspond to that same
lift. Non-lifting or out-of-range coordinates reject. No caller-selected key
tweak is supported by this candidate transcript.

`U` is exactly 32 bytes committing to the registered, ordered Purify hosts and
roster. It contains no secret material. The application must authenticate `Q`
and `U` against its fixed registry/snapshot and verify the roster's canonical
encoding, member consent, key aggregation rules, and key/host associations.
Hashing an arbitrary `U` does not establish any of those facts. This first
implementation treats it as an opaque commitment; registration and rogue-key
defenses remain separate requirements.

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
C = Q_x[32] || U[32] || len64(T) || T
S = C || len64(m) || m
tagged(tag, x) = SHA256(SHA256(tag) || SHA256(tag) || x)

nonce_input = tagged("Purify/Accountable/Nonce/v1", C)
e = int_be(tagged("Purify/Accountable/Challenge/v1", S)) mod n
```

The literal tags are ASCII without a terminator. There are no omitted framing
bytes or native-endian integers. The tags separate nonce evaluation from the
signature challenge and identify this candidate version. The application suite
is additionally bound through `T`; these bytes are not yet a frozen consensus
format. An honest signer and verifier reject the negligible `e = 0` case rather
than changing `T` or adding an attempt counter to retry the same decision.

`nonce_evaluation_input` supplies the 32 bytes to the reviewed Purify relation.
The body and proof representation never enter this input. A coalition's
independent hosts evaluate the same input, and the intended relation fixes the
sum of their raw outputs modulo `n`. Host enrollment and the relationship
between this sum and accepted proof outputs remain proof obligations.

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
nonce is not negated or normalized. The later verifier must not accept either
sign interchangeably. Since nonzero `e` and a valid `Q` make `-eQ` nonidentity,
`sigma = 0` is handled normally as `R = -eQ`.

The new trace codec does not alter the existing BIP340 PureSign formats or
claim that those signature proofs satisfy this construction. It is a separate
experimental protocol with its own tags and no backward-compatibility codec.

## Required nonce-proof interface

The later verifier must receive the authenticated host roster, the exact
`nonce_input`, the full reconstructed point `R`, the selected proof suite and
completed proof bytes. The proof must establish the required relation against
that external point. A prover-supplied replacement point or unchecked point
stored inside a wrapper cannot satisfy this interface. Final proof framing must
omit a duplicate `R` before claiming the full 32-byte-per-response saving.

Only the signature challenge excludes `R`. The nonce proof's Fiat-Shamir
transcript must still bind `R`, its circuit/relation, generators, host/context
inputs, and all commitments needed by the selected construction. A later
recursive parent proves acceptance of that same reviewed statement and its
semantic coverage; it cannot repair an unsound leaf relation.

An acceptable composition needs either exact-output nonce-proof uniqueness or
a reviewed combined signature/proof argument sufficient for extraction. The
generic arithmetic Pedersen-output backend permits output blinding; using a
zero blind in an honest prover does not alone establish that every accepted
point is the intended raw nonce. This implementation neither demonstrates a
break nor resolves that obligation. See
[leaf soundness](https://github.com/judica-org/purify/issues/21).

## Conditional extraction and signing obligations

Given two fully accepted conflicting endorsements with the same `Q`, `U`, `T`
and a proven common raw nonce, and distinct challenges:

```
q = (sigma - sigma') * inverse(e - e') mod n
```

`recover_same_slot_key` implements the algebraic part of this operation under
one supplied `Q/U/T` context. It rejects equal challenges before inversion and
compares the full recovered public point against the even-Y lift of `Q`. It
never normalizes a recovered `-q` into an accepted result. Exact `qG = Q` implies
that the two reconstructed nonce points are equal; checking
`sigma - e*q != 0` then excludes a common nonce at infinity without repeating
the point reconstructions. A zero response remains permitted when that common
nonce is finite. The returned 32 bytes are derived entirely from public inputs.

Recovery success establishes the exposed scalar, not certificate acceptance,
semantic conflict, or liability. Before using it for a penalty, the caller must
authenticate both endorsements' contexts, verify their nonce proofs, and apply
the conflict and liability rules. Arbitrary future slots do not generally share
`r_T`; a matching signing key alone is insufficient. Interpreting both responses
under the caller's context does not authenticate that context for either one.

The helper propagates context/challenge errors. Equal challenges return
`BindingMismatch`; a zero or wrong recovered key returns `EquationMismatch`;
a common nonce at infinity returns `RangeViolation`. It does not accept proof
bytes or claim to enforce the unresolved nonce relation.

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
