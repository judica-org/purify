# Public construction receipts for coalition escrow

This construction builds on
[companion scalar escrow](companion-scalar-escrow.md). Native V4 leaves and
their typed accumulator adapter are implemented. Nova 0.76 is the selected
transparent folding backend. The homogeneous public-anchor recurrence,
canonical compressed-proof codec, fixed-template Nova session, selected
native profile, verifier-only artifact format, and authenticated-root verifier
are implemented. A deterministic two-anchor fixture has qualified exact
production-profile setup, two ordered full-scale folds, Spartan IPA
compression, canonical compressed-proof verification, verifier-artifact
serialization, and artifact reload. The artifact identity is frozen as an
external 638,174,560-byte object, and a private C ABI plus public C++ API now
complete recursive verification and the mandatory native decision before
returning an acceptance capability. The envelope parser by itself remains
syntax-only transport. Consensus activation and enrollment remain disabled.

Transparent setup is a hard requirement for the completed library: public
parameters must not depend on a trusted ceremony or retained trapdoor. This
requirement is separate from zero knowledge. Child proofs must still protect
the owners' secrets; an outer proof whose witnesses are public need not hide
those witnesses merely to satisfy the setup requirement.

Library acceptance establishes proof validity and exact ancestry. It does not
implement distributed setup or share-preserving child proving, resolve custody
of a shared coalition scalar, or establish the still-unresolved correlated-key
confidentiality argument for the secp256k1 and companion-group representations.
Qualification covers two anchors, not throughput or memory bounds at 100 to
1,000 anchors. The roughly 609 MiB external verifier is too large for convenient
embedding without further size work.

## Publication and recovery

The coalition setup proof is published once through its immutable,
Bitcoin-replayable registry record. Each root owner independently distributes
its anchor-encryption proof out of band. An assembler starts from the
registry's verified construction-basis seed root and uses the independent
anchor proof bodies as witnesses. Owners do not reveal secrets or participate
in another proving round.

The candidate on-chain object contains a versioned setup reference and entry
count, each ordered 192-byte ciphertext with its 32-byte V4 precommitment `d`,
and one compressed Nova proof. Resolved anchor references, roots, and contexts
are statement data rather than duplicated wire fields. The independent proof
bodies are not on-chain payloads.

Bitcoin-only verification and recovery must remain possible after the children
are unavailable. The final proof authenticates the construction; the ciphertexts
and their exact root associations provide the data needed for recovery. A hash
of unavailable ciphertexts cannot fulfill this requirement.

For an already registered exact coalition point `Q=qG`, a receipt must
establish:

1. Its recovery root resolves to one immutable setup-record digest and
   canonical, previously decided construction-basis seed root.
2. For every listed anchor, the private V4 encryption-proof witness accepts for
   the exact recipient, resolved root, ciphertext, and enrollment context.
3. Exactly `N` homogeneous recurrence steps connect that registry seed to the
   expected final manifest and a root returned by compressed verification.
4. The ordered list covers the externally authorized manifest with no
   duplicate, omitted, substituted, or extra roots.

Setup-proof acceptance, typed basis promotion, seed standardization, and the
seed's native decision are immutable registry-registration checks. They are not
repeated inside every receipt.

The assembler may receive packets in any order. Reordering delivery does not
require new owner proofs. The application supplies the authoritative manifest;
an assembler-selected subset cannot establish that all intended collateral was
enrolled. Changing a receipt's manifest changes its statement.

The reference experiment uses one shared context for setup and bridge proofs;
their existing tagged hashes already separate the two relations. The final
parent must bind that context and the complete ordered statement. Child contexts
must not depend on receipt arrival order or the random bytes of other proofs.
Consent, activation, stake accounting and historical liability remain registry
rules, not consequences of proof verification.

## Statement and proof boundary

Let `pi_setup` and `pi_i` be completed independent proof bodies. The selected
boundary is:

```
Registry creation:
    seed = VerifyAndPromoteSetup(Q, M, setup_context, pi_setup)
    Decide(seed)

Construction receipt:
    z_0 = RegistrySeedState(seed, setup_digest, statement_digest, N)
    for i in 0..N:
        z_{i+1} = VerifyAnchorAndAccumulate(z_i, statement_i, d_i, pi_i)
    VerifyCompressedNova(z_0, z_N, N)
    Decide(z_N.root)
```

The setup proof is not repeated inside the homogeneous anchor matrix. Every
anchor step uses the same matrix and manifest-binds the exact statement digest,
`d`, coefficient commitment, and anchored offset used by its leaf equations.

The final verifier authenticates the statement and verifies a proof of this
relation. Calling the ordinary C++ child verifiers before signing or hashing a
packet is not such a proof. Neither is taking a claimed verification result,
Fiat-Shamir challenge, or elliptic-curve sum as an unconstrained witness.

All child acceptance checks must be represented: canonical encodings and point
validation, exact proof lengths, transcript challenges and rejection rules,
output binding, arithmetic reductions, and the final group equations. Public
preprocessing is useful only when the final verifier authenticates or recomputes
it; a prover-supplied precomputed result is not trusted.

Use a reviewed composition argument, including its knowledge/extraction and
random-oracle requirements. A parent cannot repair an unsound child relation.
The V4 relation retains both soundness repairs. It commits the raw
circuit coordinates before the folding challenges and maps the reduced
opening back to those committed coordinates with exact reciprocal
generator scaling. Its batched Schnorr equation binds
every advertised public point to the scalar used by the circuit.

The executable attack fixture now rejects the previously accepted
adaptive folding forgery. The public and hidden V4 relations bind their
exact public outputs. Those checks are evidence for the intended
relation. They are not a substitute for an independent V4
knowledge-soundness or zero-knowledge proof. A parent must constrain the
complete V4 typed Poseidon transcript and preserve its random-oracle and
algebraic-group assumptions. Removing ZK from a parent whose witnesses
are public does
not remove those obligations. No production receipt or enrollment
may rely on the reference assembler alone.

Conditional recovery remains:

```
valid same-slot conflicting certificates -> extracted q
q -> canonical recipient secrets -> decrypt each old root -> punishment keys
```

The current honest fixtures exercise extraction algebra and recovery. They do
not validate full decision certificates or establish forced economic loss under
Bitcoin spending rules. Arbitrary misbehavior does not necessarily reveal `q`.
Published escrow cannot be revoked cryptographically by leaving a coalition.

## Size target

The V4 setup record is 1,007 bytes, alongside a 64-byte public
recipient, for 1,071 bytes when the coalition point is already registered.
Each fixed public-commitment anchor-escrow record is 1,329 bytes: one version
byte, a 192-byte ciphertext and a 1,136-byte V4 proof payload. The latter adds
the 32-byte DLog nonce and 32-byte response which bind the circuit output to
the canonical punishment key. These are comparison sizes, not V4 parent
measurements. The superseded initial goal assumed a final proof could replace
every setup and escrow proof while retaining only the ciphertexts:

```
64 + 192*N + size(final_proof)
```

Here `N` counts independently encrypted recovery roots, not necessarily
anchors. The version-2 payload codec is `69 + 224*N` bytes: one version byte,
the 64-byte recovery root, a four-byte entry count, and one 224-byte entry per
anchor. Each entry appends the validated V4 circuit precommitment needed to
derive the expected coefficient commitment and anchored offset to its
ciphertext.

Payload framing remains version 2 because those bytes and field semantics are
unchanged. `ConstructionReceiptStatement/v3` and the selected parent suite ID
version the authenticated interpretation that now includes each resolved
punishment key.

Registry resolution is historical and one-to-one: a recovery root cannot be
reassigned after publication, and one setup-record digest cannot alias another
recovery root because the recovery root is part of its preimage. Zero is
reserved for an unresolved lookup and rejects. The receipt code binds the
resolved digest. Consensus verification must authenticate that historical
lookup; application policy separately decides whether the resolved coalition
is authorized.

The selected versioned target is:

```
69 + 224*N + 12,466
```

Each 224-byte entry is one 192-byte ciphertext plus one nonzero 32-byte
precommitment `d`. The 69-byte header selects the immutable setup record and
fixes the ordered entry count. The setup lookup also returns the nonzero digest
of the exact immutable record. Its preimage includes the recovery root, ordered
roster, coalition core, nonce-host commitment, setup context, and registry
schema version. Resolved setup and anchor metadata remain off wire but are
bound into the construction statement and initial manifest.

The current native root codec is 545 bytes for the 32,768-point anchor basis.
Compressed Nova serializes its complete final state and returns it only after
successful verification. The Rust verifier checks the payload-derived final
manifest and index, reconstructs the authenticated pending root, and exposes
only its canonical 545-byte encoding. The receipt therefore does not duplicate
that root outside the proof. The public C++ verifier parses the returned root
against the fixed basis and discharges it with `decide()` before constructing
`VerifiedConstructionReceipt`. Exact setup confirms
a `2^21` primary shape, a `2^14` secondary shape, and a canonical 12,466-byte
proof with 125 fixed sequence lengths. The proof size is independent of the
number of folded steps. At 100 anchors the candidate total is therefore 34,935
bytes: 22,469 payload bytes plus the proof. The exact native envelope codec now
encodes `payload || proof`; parsing it establishes only canonical syntax, not
proof validity or consensus acceptance. The two-anchor qualification does not
measure 100-anchor proving cost. The pre-Nova transport which appends a separate
545-byte root is obsolete and is rejected.

The typed native setup path reconstructs the exact setup record, verifies its
V4 reduction, promotes the pending claim to the construction basis,
standardizes it through the one-claim 15-round transition, and runs the
mandatory native decision. Registry creation stores the resulting 545-byte
seed root. Promotion is not exposed for generic claims.

A construction receipt begins from that authenticated seed. The checked-in
Rust recurrence now verifies homogeneous public V4 anchor leaves and constrains
the public DLog equation under the exact resolved punishment key. That key is
already bound through the construction statement and initial manifest, so the
migration added no payload field and does not repeat the public setup leaf. The
historical setup-first native assembly remains useful as a test oracle, not as
the selected recursive shape.

The integrated V4 adapter checks the raw-generator bridge, gamma
residual, coefficient commitment, and compact polynomial terms. Focused
hidden and public tests require reduction verification and final
`decide()`. This authenticates a pending obligation, not its recursive
ancestry.

Consents and existing anchor leaves remain contextual data. The verified final
state already removes the root's 545 bytes from the wire. Moving the final
basis decision inside the parent would remove the external native decision,
not any receipt bytes, while adding the linear fixed-basis work to every parent
proof.

The selected recurrence is fixed by relation ID:

```text
ecfd8e56084083ba9a94431fad5a5b1e0991d7597746440e76ccf77924444a66
```

Its source relation has 1,851,594 gates, 3,813,632 rows, and 14,293,837 terms.
Direct Nova lowering produces 1,851,594 variables, 1,962,058 constraints, and
a 12,552,747-nonzero upper bound. Nova's arity-20 wrapper gives the confirmed
primary dimensions 1,975,624 constraints and 1,865,190 variables; the secondary
dimensions are 10,787 and 10,769.

The selected profile freezes public-parameter digest
`b90f7e761288cc1fdb7abd16f4e0abbbe2c8d7c773f315a17f1d7c4f982f7900`
and suite ID
`116fbf3345173dbedfd53e3ebe0e2acbffe7b7719df794f6c7cfa27314bdd5aa`.
Exact setup, two ordered full-scale folds, Spartan IPA compression, and
canonical verification have qualified against those values. The positive
12,466-byte proof is checked in. The frozen external verifier artifact is
638,174,560 bytes with tagged digest
`7b2fcafb6475c870925c2c00b0ab9eba539bc540e34db14678cf005213bdebd5`;
the loader authenticates both before decoding. A private C ABI returns only the
authenticated pending root, while the public C++ API rebuilds the typed inputs,
verifies the parent, and completes native `decide()` before returning
acceptance. A separate checked-in proof preserves the same public two-anchor
construction and passes recursive verification but produces a root which fails
the native decision, so it is rejected before acceptance. These results do not
activate consensus, qualify operation at 100 to 1,000 anchors, or make the
roughly 609 MiB verifier convenient to bundle.

## Historical V2 public-prehashing experiment

The earlier V2 transcript separated statement-only preprocessing from
proof-dependent hashing. In that obsolete reduction, `rho`, the ordered
generators and the coefficient vector depended only on the circuit and public
statement. They did not depend on the child's `A`, `S`, `t2` or folding
messages. Its digest was:

```
D = TaggedHash("Purify/BPPP/NormArg/PublicDataV1",
    rho32 || norm_count64le || generator_count64le || generators33[]
    || coefficient_count64le || coefficients32[])
```

Points use canonical compressed SEC1 encodings; scalars use canonical big-endian
32-byte encodings. The norm transcript starts with a different domain tag,
`Purify/BPPP/NormArg/TranscriptV1`, followed by `D || commitment33`. Existing
ordered round messages and challenge extraction then continue normally.

The native V2 verifier recomputed `D`; it did not accept an unchecked
assembler-supplied digest. That split was not a soundness repair. V3 fixes the
raw witness before sampling its folding challenges, so its dependencies differ
from the profiler below. Static generators and genuinely statement-fixed data
can still be prehashed where a final verifier authenticates them, but the V2
counts must not be used as a V4 recursive-verifier estimate.

Source-derived SHA-256 compression counts for that obsolete wrapper,
including challenge forks and the first outer challenge attempt, are:

| Child | Padded gates | Public bytes hashed outside | Previous layout | Factored layout |
| --- | ---: | ---: | ---: | ---: |
| Recipient setup | 2,048 | 536,632 | 8,414 | 30 |
| One root encryption | 8,192 | 2,146,360 | 33,570 | 34 |

For that wrapper, one setup plus two encryption children went from 75,554 to
98 proof-dependent blocks; 100 encryption children go from 3,365,414 to 3,430.
Those counts do not imply that a V4 receipt needs only 98 or 3,430
blocks. They rely on the obsolete statement-only reduction
coefficients and a superseded transcript. Public hashing moved; it did
not disappear, and
it remains part of full verifier cost. Tagged midstates were treated as
constants. These are historical source-derived workloads, not measured parent
gates or a final proof-size estimate.

The previous layout placed the variable commitment before the public arrays,
so those arrays could not be prehashed as an independent SHA-256 prefix. The
profiler retains that historical layout only for comparison, not compatibility.

Purify's key/nonce relation avoids hashing secret material by combining public
hash-to-curve preprocessing with constrained secret scalar multiplication. It
does not remove the proof system's Fiat-Shamir hash. An off-chain child proof
becomes a witness to its parent, so the child's proof-dependent challenges
still require constrained derivation. The SHA-256 experiment measures that
part of the existing verifier; it does not select SHA-256 for the final parent.
A reviewed circuit-friendly transcript hash could remove the SHA-256-specific
gadget, but requires an explicit suite, parameters and security argument.
Purify's PRF security alone does not justify substituting Purify for this
random-oracle role.

The verifier also performs secp256k1 group operations. Its coordinate field is
different from the scalar field used by the existing Purify arithmetic circuit.
The companion-curve gadgets cannot be substituted for secp256k1 point arithmetic.
Canonical non-native arithmetic and complete handling of group edge cases are
additional work; SHA-256 alone is not a recursive verifier.

The historical inner checks had 12,288 setup and 49,152 encryption
fixed-generator terms before any separately reviewed batch optimization. A
parent backend must satisfy the transparent-setup requirement; its feasibility
does not follow from the small child transcripts.

### Full verifier circuits and accumulation are different designs

These counts describe executing the current child verifier. They are not a
lower bound for transparent recursive composition. In particular, they do not
model Halo-style accumulation of an inner-product verification obligation.

An IPA verifier's expensive final generator combination can be represented as
a commitment to a polynomial whose evaluation is cheap to compute from the
folding challenges. A recursive proof checks the small part of verification
and the transition to a new accumulator. The final verifier must discharge the
remaining linear-time generator check. Omitting that final check is unsound;
repeating it inside every recursive circuit is not the only design. This is
the route described in the [Halo2 recursion explanation](https://zcash.github.io/halo2/background/recursion.html)
and formalized by [accumulation schemes](https://eprint.iacr.org/2020/499).

Bulletproofs' inner-product machinery is part of that lineage. The BP++ weighted
norm argument has related folding structure, but its smaller proofs and support
for joint aggregation do not by themselves specify a public accumulator for
completed BP++ circuit proofs. Adapting the accumulation route requires an exact
reduction/accumulator relation, transcript, final decision procedure and security
argument for that relation. The native
[norm accumulator](norm-accumulation.md) now implements partial norm
verification, public coefficient openings for varying `c`, a typed V4
raw-basis adapter, accumulation transitions and a mandatory final
decision. Its API
requires all child statements and transition transcripts. It does not implement
their recursive authentication by itself. The selected Rust recurrence now
constrains that ancestry, and the C++ acceptance path completes the final native
decision. The concrete protocol still requires independent cryptographic
review. The historical workload profiler does not model those recursive
transitions. Neither native accumulation nor batch verification alone is a
compressed construction receipt.

The selected implementation boundary and its mandatory explicit root claim are
specified in the
[recursive construction receipt boundary](recursive-parent-receipt.md).

Release qualification must account separately for public
parameters, folding, compression, native final decision, authenticated
manifest, and production peak memory. The fixed recurrence and canonical proof
codec are now measured components rather than open design choices. Direct
recursive verification remains a comparison point, not an unmade backend
choice. The overall library path authenticates the resolved setup separately;
the parent authenticates every V4 anchor leaf and ordered transition.
Consensus activation remains a separate application decision.

Anchor escrow record version 3 fixes punishment-key derivation to
`k_raw = PurifyEval(d, "Purify/Accountable/AnchorPunishmentKey/v1")`, followed
by even-Y BIP340 normalization. The verifier reconstructs the two public
hash-to-curve bases outside the circuit; no hash of the unknown root secret is
required. The circuit reuses the root's `d1,d2` bit witnesses and publicly
commits the normalized scalar to the exact canonical punishment key. No anchor
descriptor or final anchor ID enters this derivation, so there is no circular
identifier dependency.

An owner who does not know a shared root would still need distributed
evaluation and proving, so this relation cannot silently change shared-root
custody into individual custody. The fixed punishment input is
domain-separated from signing-nonce topics, and root reuse retains every
historical escrow authority's exposure. The current canonical aggregate
`q`-to-recipient construction requires distributed proving to avoid
reconstructing `q` at a coordinator, and its correlated-key privacy argument
remains unresolved. This is a requirement of that construction, not a claim
that every possible recipient setup must use MPC. An alternative relation
must establish its own public recovery, custody and privacy guarantees before
replacing it.

## Implementation milestones

1. Completed: share the setup and encryption verifiers and exercise assembly
   using only public child packets.
2. Completed as a historical cost study: profile verifier hashing and implement
   a constrained SHA-256 experiment with independently checked outputs.
3. Completed for individual V4 leaves: native production and
   verification, matching Rust relations, and the typed native
   accumulator adapter.
   Reduction verification and final `decide()` remain mandatory.
4. Completed internally: the fixed homogeneous public-anchor recurrence,
   canonical Nova codec, verifier-derived initial and expected final states,
   exact-step enforcement, and allocation-light exact-shape witness reuse.
5. Completed for the selected native profile: static relation, parameter and
   suite identities, exact setup, two ordered full-scale folds, Spartan IPA
   compression, canonical verification, artifact serialization, and reload.
6. Completed for library acceptance: the exact `payload || proof` envelope,
   frozen external verifier identity, private C ABI, and public C++ API which
   completes native `decide()` before returning a capability. Checked-in
   positive and recursive-valid/nondeciding proofs exercise both sides of that
   boundary.
7. Remaining: independently review V4 composition and correlated-key
   confidentiality; implement distributed setup, custody, and share-preserving
   child proving; qualify resource use at 100 to 1,000 anchors; reduce or
   operationalize the roughly 609 MiB verifier; and integrate the accepted
   certificate with registry and Bitcoin punishment rules before enrollment.
   Do not expose proving through an RPC before those resource and correctness
   gates pass.

No receipt should be accepted merely because its public inputs passed the
reference assembler.

## Running the experiments

The historical construction fixture shares the legacy child verifiers through
test-only helpers. It runs V3 predicates and does not exercise V4; it is not
the selected parent proof or an independent security argument. Its assembler
accepts the externally supplied ordered roots and public packets; its signature
accepts no secret, witness assignment or callback to a participant. The tested
mutations reject incomplete coverage, duplicate roots, crossed child proofs,
and changed recipients, coalitions, contexts or ciphertexts.
After preparation, recovery uses only the statement and extracted toy scalar;
it does not retain the child proofs. This historical model is not a substitute
for the selected qualified parent verifier and native-deciding acceptance API.

The two-root fixture has 3,281 bytes of out-of-band child proofs and a 662-byte
public statement, including full roots, the coalition point, context and framing.
Its recipient and ciphertext portion is 448 bytes. No final proof is included
because this historical fixture predates and does not invoke the Nova session.

The SHA-256 fixture constrains symbolic input bits and bounded 32-bit additions,
checks padding boundaries against the independent C hash, and produces a V3
proof for that standalone relation. A recursive verifier must also connect
those input bits to the exact child transcript; the standalone hash relation is
insufficient.

An earlier AppleClang 16 / arm64 C++20 Release run measured the `abc` relation
at 32,768 padded gates and a 1,267-byte V2 transcript, with about 13.76 seconds
generating it and 5.40 seconds running its acceptance predicate. Those timings
exclude circuit/witness construction and must not be attributed to V3. Message
lengths 0, 3 and 55 use 32,768 padded gates; lengths 56 and 64 require two SHA-256
blocks and 65,536 gates. These are historical standalone hash-relation
measurements, not an extrapolated size or runtime for a complete receipt.

The larger honest circuit exposed a fixed 16 MiB BP++ scratch allocation that
could not hold its live vector copies. The accompanying resource fix reserves
an overflow-checked dimension-dependent frame in addition to MSM work space,
for both cached and uncached calls. It changes allocation capacity, not the
proof relation or transcript.

```
python3 tests/reference_receipt_verifier_cost.py --self-test --roots 2
python3 tests/reference_receipt_verifier_cost.py --roots 100
ctest --test-dir build -R 'construction_receipt|receipt_sha256' --output-on-failure
```

The general composition approach is described in
[Recursive Proof Composition without a Trusted Setup](https://eprint.iacr.org/2019/1021).
[BP++](https://eprint.iacr.org/2022/510) supports joint proving and aggregation;
BP++ aggregation itself is not a compressor for these completed Fiat-Shamir
proofs. The implemented compressor is the selected qualified Nova parent
described above.
