# Public construction receipts for coalition escrow

This is the next experiment after
[companion scalar escrow](companion-scalar-escrow.md). It fixes the intended
statement and public-data flow. Native V4 leaves and their typed native
accumulator adapter are implemented, but the compressed parent is not.
Enrollment remains disabled pending review and application integration.

Transparent setup is a hard requirement for the completed library: public
parameters must not depend on a trusted ceremony or retained trapdoor. This
requirement is separate from zero knowledge. Child proofs must still protect
the owners' secrets; an outer proof whose witnesses are public need not hide
those witnesses merely to satisfy the setup requirement.

## Publication and recovery

The coalition distributes its recipient-setup proof **out of band**. Each root
owner independently distributes an encryption proof and ciphertext out of band.
An assembler uses those public objects to construct the final receipt. Owners
do not send secrets to the assembler or participate in another proving round.

The intended on-chain object contains the coalition reference, recipient `M`,
an ordered list of recovery-root references and ciphertexts, application context,
and one final proof. The independent child proofs are not on-chain payloads.
They are witnesses for the final prover, although they contain no additional
secret inputs and may be distributed publicly.

Bitcoin-only verification and recovery must remain possible after the children
are unavailable. The final proof authenticates the construction; the ciphertexts
and their exact root associations provide the data needed for recovery. A hash
of unavailable ciphertexts cannot fulfill this requirement.

For an already registered exact coalition point `Q=qG`, a receipt must establish:

1. The recovery root resolves to one immutable setup-record digest and exact
   roster, core, nonce-host commitment, setup context, and registry version.
2. The setup proof accepts for that exact `Q`, recipient `M`, and setup context.
3. For every listed root `D_i`, its encryption proof accepts for the exact
   `M`, `D_i`, ciphertext `E_i`, and enrollment context.
4. The list covers the externally authorized manifest exactly, with no duplicate
   roots, omissions, substitutions, or extra entries. Public references resolve
   to the same roots used by the child verifiers.

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

Let `pi_setup` and `pi_i` be completed independent child proofs. The intended
parent relation is the conjunction:

```
VerifySetup(Q, M, setup_context, pi_setup)
AND for every i:
    VerifyEscrow(M, D_i, E_i, enrollment_context, pi_i)
```

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

The legacy V3 setup record is 1,007 bytes, alongside a 64-byte public
recipient, for 1,071 bytes when the coalition point is already registered.
Each fixed anchor-escrow record is 1,265 bytes: one version byte, a
192-byte ciphertext and a 1,072-byte proof payload. These are comparison
sizes, not V4 parent measurements. If a final parent proof replaces the
setup and escrow proofs while retaining the ciphertext format,
incremental data with an explicit recipient would be approximately:

```
64 + 192*N + size(final_proof)
```

Here `N` counts independently encrypted recovery roots, not necessarily
anchors. The implemented canonical payload is `69 + 192*N` bytes: one version
byte, the 64-byte recovery root, a four-byte entry count, and the ciphertexts.
The recovery root selects the authenticated coalition setup. That lookup must
also return a nonzero, 32-byte digest of the exact immutable setup record. Its
canonical preimage includes the recovery root, ordered roster, coalition core,
nonce-host commitment, setup context, and registry schema version. The setup
digest and deterministically ordered anchor references, roots, and contexts
stay off wire but are bound into the receipt statement digest.

Registry resolution is historical and one-to-one: a recovery root cannot be
reassigned after publication, and one setup-record digest cannot alias another
recovery root because the recovery root is part of its preimage. Zero is
reserved for an unresolved lookup and rejects. The receipt code binds the
resolved digest; the application remains responsible for authenticating the
registry lookup that supplied it.

The selected accumulator boundary additionally carries a 545-byte final root
claim for the current 32,768-point anchor basis. It is not proof acceptance:
the parent must authenticate the claim's complete ancestry, and the native
verifier must discharge it with `decide()`. The present concrete target is:

```
69 + 192*N + 545 + size(final_parent_proof)
```

The canonical envelope now implements that concatenation exactly, with no
additional length or wrapper fields. The payload entry count determines the
`69 + 192*N` prefix, the receipt version fixes the 545-byte root, and all
remaining bytes are the parent proof. Parsing validates payload and root-claim
syntax and bounds the proof transport; it is not receipt acceptance. The
purpose parent verifier must bind the exact envelope and the native verifier
must still decide the parsed root.

The legacy typed path prepares the exact 1,007-byte setup proof on its
fixed 8,192-point basis and verifies its coefficient-opening reduction.
It promotes the still-pending obligation into the exact prefix of the
construction basis.
Promotion is not exposed for generic claims: the public method reconstructs
the roster, recovery root, setup proof, and reduction before changing bases.
The typed native assembly owns that setup capability together with one payload,
the resolved setup-record digest, its resulting statement digest, and its
ordered resolved manifest. An anchor reduction can enter only at its exact
index, with the payload ciphertext and resolved root/context fixed there.
Missing, repeated, out-of-range, and ciphertext-substituted leaves cannot
produce the ordered setup-first leaf list.
An honest promoted setup claim has been folded, encoded as the 545-byte root,
parsed, and discharged by the final MSM. The recursive parent must still prove
that same setup preparation, reduction, promotion, and every anchor transition;
the native test alone is not a compressed receipt.

The integrated V4 adapter checks the raw-generator bridge, gamma
residual, coefficient commitment, and compact polynomial terms. Focused
hidden and public tests require reduction verification and final
`decide()`. This authenticates a pending obligation, not its recursive
ancestry.

Consents and existing anchor leaves remain contextual data. Moving the final
basis decision inside the parent could remove the 545 bytes, but would add the
linear fixed-basis work to the parent relation.

The transparent secq proof transport is implemented, but the complete parent
relation has not been implemented or measured. A 1-2 KB complete parent proof
remains a target, not a result. Direct proofs of combined native relations and
public proofs of already completed proofs also have different prover costs.
Combining all native witnesses centrally would not satisfy the required public
assembler interface.

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
their recursive authentication, and the concrete protocol still requires
cryptographic review. The historical workload profiler does not model those
recursive transitions. Neither native accumulation nor batch verification
alone is a compressed construction receipt.

The selected implementation boundary and its mandatory explicit root claim are
specified in the
[recursive construction receipt boundary](recursive-parent-receipt.md).

Before selecting a replacement backend on cost grounds, evaluate this route
alongside direct recursive verification. Account separately for the recursive
circuit, final verifier, public accumulator bytes and authenticated manifest.
Curve cycles and a suitable transcript can reduce recursive arithmetic
costs. The scalar-field circuit and historical SHA-256 choices do not
define the only possible transparent implementation. An accumulator
still needs sound child
proofs and a parent which authenticates every V4 leaf and transition.

Anchor punishment-key derivation is also a design variable in this pre-release
protocol. Public descriptors and hash-to-curve bases may be derived outside the
circuit when the verifier can reconstruct them exactly. A hash of an unknown
secret cannot be lifted on that basis. Any replacement leaf relation must still
let the owner derive its key and the recovered root derive the exact same
punishment scalar, while retaining the intended custody and exposure rules.

For independent owner-held roots, a candidate leaf is
`k = Purify(d, public_anchor_descriptor)`, with registered root `D`. Both the
owner and anyone recovering `d` can evaluate `k`. Its public hash-to-curve bases
come from an acyclic descriptor containing the suite, network, root and relevant
owner/refund identities plus a uniqueness salt, not the final anchor ID that
already contains the derived key. This could replace the fresh 64-byte public
ephemeral pair in the earlier leaf experiment; descriptor/reference costs and
the exact `kG` binding proof remain. It is a candidate, not an implemented leaf
or deployed anchor format. An owner who does not know a shared root would need
distributed evaluation, so this substitution cannot silently change shared-root
custody into individual custody. Anchor-key topics must be domain-separated
from signing-nonce topics, and root reuse retains every historical escrow
authority's exposure. The current canonical aggregate `q`-to-recipient
construction requires distributed proving to avoid reconstructing `q` at a
coordinator, and its correlated-key privacy argument remains unresolved. This
is a requirement of that construction, not a claim that every possible
recipient setup must use MPC. An alternative relation must establish its own
public recovery, custody and privacy guarantees before replacing it.

## Implementation milestones

1. Completed: share the setup and encryption verifiers and exercise assembly
   using only public child packets.
2. Completed as a historical cost study: profile verifier hashing and implement
   a constrained SHA-256 experiment with independently checked outputs.
3. Completed for individual V4 leaves: native production and
   verification, matching Rust relations, and the typed native
   accumulator adapter.
   Reduction verification and final `decide()` remain mandatory.
4. Remaining: choose and review the parent relation/backend. Implement canonical
   child parsing, transcript replay and constrained curve verification; benchmark
   one setup plus two encryption children before scaling to 100.
5. Remaining: establish composition and correlated-key privacy security,
   implement distributed setup/proving, and integrate accepted certificate
   recovery with the registry and Bitcoin punishment path before enrollment.

No receipt should be accepted merely because its public inputs passed the
reference assembler.

## Running the experiments

The construction fixture shares the legacy child verifiers through
test-only helpers. It runs V3 predicates and does not exercise V4; it
is not the missing parent proof or an independent security argument. Its
assembler accepts
the externally supplied ordered roots and public packets; its signature
accepts no secret, witness assignment or callback to a participant. The tested
mutations reject
incomplete coverage, duplicate roots, crossed child proofs, and changed
recipients, coalitions, contexts or ciphertexts.
After preparation, recovery uses only the statement and extracted toy scalar;
it does not retain the child proofs. This models a future accepted receipt,
not a substitute for its missing verifier.

The two-root fixture has 3,281 bytes of out-of-band child proofs and a 662-byte
public statement, including full roots, the coalition point, context and framing.
Its recipient and ciphertext portion is 448 bytes. No final proof is included
in those statement measurements because the parent is not implemented.

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
that does not provide an implemented public compressor for these completed
Fiat-Shamir proofs.
