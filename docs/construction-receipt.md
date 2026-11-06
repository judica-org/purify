# Public construction receipts for coalition escrow

This began as the design experiment after
[companion scalar escrow](companion-scalar-escrow.md). The implementation now
has a transparent SHA-256 Nova parent backend and a qualified 15,076-byte proof
profile. A private purpose-specific C ABI backs the public C++ verifier, which
requires both recursive verification and native accumulation decision before
returning a verified receipt. Neither backend qualification nor that local
acceptance path enables enrollment or establishes the child proof system's
security.

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

1. The setup proof accepts for the exact `Q`, recipient `M`, and setup context.
2. For every listed root `D_i`, its encryption proof accepts for the exact
   `M`, `D_i`, ciphertext `E_i`, and enrollment context.
3. The list covers the externally authorized manifest exactly, with no duplicate
   roots, omissions, substitutions, or extra entries. Public references resolve
   to the same roots used by the child verifiers.

The registry record supplying that setup should derive its coalition core from
the [one-shot Bitcoin formation](coalition-formation.md) rule. Its resolved
setup digest must retain that exact core and formation record. This changes no
parent-proof field: the construction statement already authenticates the
resolved setup digest, while the child setup and escrow relations already bind
the coalition core.

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
The current experimental circuit wrapper has identified structural soundness
defects: its constraint-folding challenges precede a commitment to the original
witness, and acceptance of the reduced norm equation does not establish that
its coordinates belong to the original circuit reduction's image. These are
not merely missing documentation or an outstanding general audit. Running this
acceptance predicate does not establish a sound verifiable-encryption proof.

The native relations and honest round trips remain reference experiments. A
sound replacement must also establish exact secp output binding and the claimed
privacy properties. Recursively proving acceptance of the current defective
wrapper would preserve its defects. Removing ZK from a parent whose witnesses
are public does not remove these obligations. No production receipt, nonce
certificate or enrollment may rely on the current wrapper.

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

The current experimental wrapper serializes an honest setup transcript in
1,007 bytes, alongside a 64-byte public recipient. Each bridge has a
1,137-byte honest transcript and 192-byte ciphertext. These are measurements of
the defective wrapper, not sizes of an established sound argument. If a sound
final proof replaces the setup and bridge transcripts while retaining this
ciphertext format, incremental data with an explicit recipient would be:

```
64 + 192*N + size(final_proof)
```

Here `N` counts independently encrypted recovery roots, not necessarily anchors.
Root/coalition references, context, framing, consents and existing anchor leaves
are additional. The reference statement includes full public roots instead of
assuming an unimplemented on-chain index; its serialized size is therefore
larger than this incremental formula.

The qualified parent proof is 15,076 bytes, not the original 1-2 KB target.
Its 693,735,316-byte local verifier artifact expands to 3,206,748,264 bytes.
These measurements qualify the selected recursive backend; they do not resolve
the child argument's security review, distributed proving, or a production
assembler-prover API. Public witness reconstruction currently exists only in
test helpers. Combining all native witnesses centrally would not satisfy the
required public assembler interface.

## Public prehashing measured in the current wrapper

The revised experimental transcript separates statement-only preprocessing
from proof-dependent hashing. In the current defective outer reduction, `rho`,
the ordered generators and the coefficient vector depend only on the circuit
and public statement. They do not depend on the child's `A`, `S`, `t2` or folding
messages. The implemented digest is:

```
D = TaggedHash("Purify/BPPP/NormArg/PublicDataV1",
    rho32 || norm_count64le || generator_count64le || generators33[]
    || coefficient_count64le || coefficients32[])
```

Points use canonical compressed SEC1 encodings; scalars use canonical big-endian
32-byte encodings. The norm transcript starts with a different domain tag,
`Purify/BPPP/NormArg/TranscriptV1`, followed by `D || commitment33`. Existing
ordered round messages and challenge extraction then continue normally.

The native verifier recomputes `D`; there is no API accepting an unchecked
assembler-supplied digest. For this current data flow, a parent verifier could
likewise recompute it from the authenticated public statement and bind it to
the constrained child transcript. Proof-dependent commitment/round hashing
would remain inside the parent circuit.

That split is not a security repair. Fixing the original witness before random
constraint folding can make challenges and reduction coefficients depend on
child-proof messages. Such data cannot then be treated as statement-only public
preprocessing merely because the current wrapper does so. Static generators
and genuinely statement-fixed data can still be prehashed where the final
verifier authenticates them. A sound replacement must specify its actual
dependencies before any recursive workload estimate is accepted.

This is a new experimental transcript, not an alternate verifier for old
proofs. PureSign++ nonce-proof encoding advances to version 2 and rejects
version 1. The outer signature container layout is unchanged. Domain separation
and canonical public-data binding distinguish these transcript bytes; they do
not fix the witness-ordering or reduction-image defects.

Source-derived SHA-256 compression counts for this experimental wrapper,
including challenge forks and the first outer challenge attempt, are:

| Child | Padded gates | Public bytes hashed outside | Previous layout | Factored layout |
| --- | ---: | ---: | ---: | ---: |
| Recipient setup | 2,048 | 536,632 | 8,414 | 30 |
| One root encryption | 8,192 | 2,146,360 | 33,570 | 34 |

For this wrapper, one setup plus two encryption children goes from 75,554 to
98 proof-dependent blocks; 100 encryption children go from 3,365,414 to 3,430.
Those counts are not a claim that a sound recursive receipt needs only 98 or
3,430 blocks. They rely on the current statement-only reduction coefficients
and must be recomputed for the sound replacement. Public hashing has moved,
not disappeared, and remains part of full verifier cost. Tagged midstates are
treated as constants. These are source-derived experimental workloads, not
measured parent gates or a final proof-size estimate.

The previous layout placed the variable commitment before the public arrays,
so those arrays could not be prehashed as an independent SHA-256 prefix. The
profiler retains that historical layout only for comparison, not compatibility.

### Historical backend-selection assessment

Purify's key/nonce relation avoids hashing secret material by combining public
hash-to-curve preprocessing with constrained secret scalar multiplication. It
does not remove the proof system's Fiat-Shamir hash. An off-chain child proof
becomes a witness to its parent, so the child's proof-dependent challenges
still require constrained derivation. The original SHA-256 experiment measured
that workload but did not by itself select a final backend.

The qualified profile now explicitly selects the chained SHA-256 transcript.
Its native Nova `StepCircuit` relation implements canonical non-native
secp256k1 arithmetic and complete group-edge handling, and the production
archive verifies the resulting frozen Nova profile. This establishes the
implemented validity path; it does not supply the missing independent child and
composition security review. Purify's PRF security would not justify replacing
the selected random oracle without a new suite and security argument.

The historical inner checks had 12,288 setup and 49,152 encryption
fixed-generator terms before separately reviewed batch optimization. Those
measurements motivated the accumulation design but do not estimate the
qualified parent prover from the small experimental child transcripts.

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
verification, public coefficient openings for varying `c`, accumulation
transitions and a mandatory final decision. Its API requires all child
statements and transition transcripts. The selected SHA-256 Nova recurrence
now authenticates those transitions, but it does not repair an unsound child
argument, and the concrete protocol still requires cryptographic review.
Neither native accumulation nor batch verification alone is a compressed
construction receipt.

The selected backend takes this accumulation route. Its cost accounting keeps
the recursive circuit, final verifier, public accumulator bytes, and
authenticated manifest separate. Other curve cycles or transcript suites may
reduce recursive arithmetic costs, but would define new protocol profiles. The
selected accumulator still needs sound child proofs and cannot repair the
current outer-circuit wrapper.

Anchor punishment-key derivation was also a design variable. The selected leaf
now derives `k = Purify(d, punishment_domain)` under one fixed domain and
constrains the exact public `kG`; public hash-to-curve bases are reconstructed
outside the circuit. See
[the anchor punishment-key relation](anchor-punishment-relation.md). This avoids
hashing an unknown secret in-circuit but introduces the documented related-output
security assumption.

An owner who does not know a shared root still needs distributed evaluation, so
this choice cannot silently change shared-root custody into individual custody.
Anchor-key topics remain domain-separated from signing-nonce topics, and root
reuse retains every historical escrow authority's exposure. The aggregate
`q`-to-recipient construction requires distributed proving to avoid
reconstructing `q` at a coordinator, and its correlated-key privacy argument
remains unresolved.

## Implementation status

Completed validity work includes public child-packet assembly, independently
checked SHA-256 transcripts, canonical child parsing, constrained secp256k1
verification, the authenticated manifest recurrence, transparent Nova
qualification, fixed accepted and nondeciding proof vectors, and the public C++
recursive-plus-native acceptance boundary.

Remaining production work is narrower but security-critical:

1. Repair or independently justify the child argument and review the V4 leaf,
   accumulation, composition, and related-output assumptions.
2. Implement distributed setup, custody, and share-preserving proving without
   reconstructing coalition secrets at a coordinator.
3. Publish the authenticated verifier artifact through an immutable release
   channel and qualify resource behavior at 100 to 1,000 anchors, including
   distribution and startup.
4. Integrate accepted certificate recovery with registry, consensus, redemption,
   and punishment rules before enabling enrollment.

No receipt should be accepted merely because its public inputs passed the
reference assembler. Backend qualification does not replace the remaining
composition and protocol review.

## Running the experiments

The construction fixture shares the exact existing child verifiers through
test-only helpers. It runs their experimental acceptance predicates; it does
not establish sound proof acceptance. Its assembler accepts the externally
supplied ordered roots and public packets; its signature accepts no secret,
witness assignment or callback to a participant. The tested mutations reject
incomplete coverage, duplicate roots, crossed child proofs, and changed
recipients, coalitions, contexts or ciphertexts.
After preparation, recovery uses only the statement and extracted toy scalar;
it does not retain the child proofs. This historical fixture models the public
data flow; it is not the qualified recursive verifier or receipt acceptance.

The two-root fixture has 3,281 bytes of out-of-band child proofs and a 662-byte
public statement, including full roots, the coalition point, context and framing.
Its recipient and ciphertext portion is 448 bytes. Those historical statement
measurements exclude the separately qualified 15,076-byte parent proof.

The removed standalone SHA-256 fixture constrained symbolic input bits and
bounded 32-bit additions, checked padding boundaries against the independent C
hash, and produced an honest transcript for that locally checked relation. It
did not establish a sound proof of a hash preimage through the current wrapper.
That standalone hash relation was insufficient; the qualified recurrence
separately connects the exact chained transcript to its constrained child
relation.

An AppleClang 16 / arm64 C++20 Release run measured the `abc` relation at 32,768
padded gates and a 1,267-byte experimental transcript, with about 13.76 seconds
generating it and 5.40 seconds running its acceptance predicate. Those timings
exclude circuit/witness construction. Message
lengths 0, 3 and 55 use 32,768 padded gates; lengths 56 and 64 require two SHA-256
blocks and 65,536 gates. These are standalone hash-relation measurements using
the defective wrapper, not an extrapolated size or runtime for a sound complete
receipt.

The larger honest circuit exposed a fixed 16 MiB BP++ scratch allocation that
could not hold its live vector copies. The accompanying resource fix reserves
an overflow-checked dimension-dependent frame in addition to MSM work space,
for both cached and uncached calls. It changes allocation capacity, not the
proof relation or transcript.

```sh
ctest --test-dir build --output-on-failure \
  -R '^purify\.tests\.construction_receipt(_codec)?$'
```

The general composition approach is described in
[Recursive Proof Composition without a Trusted Setup](https://eprint.iacr.org/2019/1021).
[BP++](https://eprint.iacr.org/2022/510) supports joint proving and aggregation;
that does not provide an implemented public compressor for these completed
Fiat-Shamir proofs.
