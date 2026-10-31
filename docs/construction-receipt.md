# Public construction receipts for coalition escrow

This is the next experiment after [companion scalar escrow](companion-scalar-escrow.md).
It fixes the intended statement and public-data flow. It does not implement a
compressed receipt, enable enrollment, or establish the proof systems' security.

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
The existing setup's exact secp output binding and the experimental BP++
backend's soundness/ZK remain open review gates. Removing ZK from a parent whose
witnesses are public does not remove those obligations.

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

The current setup comprises a 1,007-byte proof and 64-byte public recipient.
Each bridge comprises a 1,137-byte proof and 192-byte ciphertext. If a final
proof replaces the setup proof and all bridge proofs, incremental data with an
explicit recipient would be:

```
64 + 192*N + size(final_proof)
```

Here `N` counts independently encrypted recovery roots, not necessarily anchors.
Root/coalition references, context, framing, consents and existing anchor leaves
are additional. The reference statement includes full public roots instead of
assuming an unimplemented on-chain index; its serialized size is therefore
larger than this incremental formula.

The final proof has not been implemented or measured. A 1-2 KB proof is a target,
not a result. Direct BP++ proofs of combined native relations and public proofs
of already completed proofs have different prover costs. Combining all native
witnesses centrally would not satisfy the required public assembler interface.

## Lift public hashing out of the parent circuit

The revised child transcript separates public preprocessing from proof-dependent
hashing, following the same boundary used by Purify's public hash-to-curve inputs.
`rho`, the ordered generators and the coefficient vector depend only on the
circuit and public statement. They do not depend on the child's `A`, `S`, `t2`
or folding messages. Compute:

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
assembler-supplied digest. A parent verifier must likewise recompute it from
the authenticated public statement and bind it to the constrained child
transcript. The large public hash can then run outside the parent circuit.
Proof-dependent commitment/round hashing remains inside it.

This is a new experimental transcript, not an alternate verifier for old
proofs. PureSign++ nonce-proof encoding advances to version 2 and rejects
version 1. The outer signature container layout is unchanged. Domain
separation and canonical public-data binding support the intended composition
argument; they do not establish the missing full BP++ security proof.

Source-derived SHA-256 compression counts, including challenge forks and the
first outer challenge attempt, are:

| Child | Padded gates | Public bytes hashed outside | Previous layout | Factored layout |
| --- | ---: | ---: | ---: | ---: |
| Recipient setup | 2,048 | 536,632 | 8,414 | 30 |
| One root encryption | 8,192 | 2,146,360 | 33,570 | 34 |

One setup plus two encryption children goes from 75,554 to 98 proof-dependent
blocks; 100 encryption children go from 3,365,414 to 3,430. Public hashing has
moved, not disappeared, and must still be accounted for in full verifier cost.
Tagged midstates are treated as constants. These are source-derived workloads,
not measured parent gates or a final proof-size estimate.

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

The inner checks still have 12,288 setup and 49,152 encryption fixed-generator
terms before any separately reviewed batch optimization. Another parent backend
is also a design choice, not a demonstrated consequence of small child proofs.

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
authority's exposure. The coalition's canonical `q`-to-recipient setup still
needs distributed proving and the correlated-key privacy argument.

## Implementation milestones

1. Share the existing reference setup and encryption verifiers without changing
   their relations, then exercise assembly using only public child packets.
2. Measure the actual verifier workload and implement a constrained SHA-256
   experiment with independently checked outputs and an honest BP++ proof.
3. Choose an affordable, reviewed parent relation/backend. Implement canonical
   child parsing, transcript replay and constrained secp verification; benchmark
   one setup plus two independent encryption children before scaling to 100.
4. Establish composition security and the remaining child-proof gates, implement
   the distributed coalition setup, and integrate accepted certificate recovery
   with the registry and punishment path before enabling enrollment.

The first two milestones are preparation for the third. No receipt should be
accepted merely because its public inputs passed the reference assembler.
Daybreak work remains deferred.

## Running the experiments

The construction fixture shares the exact existing child verifiers through
test-only helpers. Its assembler accepts the externally supplied ordered roots
and public packets; its signature accepts no secret, witness assignment or
callback to a participant. It rejects incomplete coverage, duplicate roots,
crossed child proofs, and changed recipients, coalitions, contexts or ciphertexts.
After preparation, recovery uses only the statement and extracted toy scalar;
it does not retain the child proofs. This models a future accepted receipt,
not a substitute for its missing verifier.

The two-root fixture has 3,281 bytes of out-of-band child proofs and a 662-byte
public statement, including full roots, the coalition point, context and framing.
Its recipient and ciphertext portion is 448 bytes. No final proof is included
in those statement measurements because the parent is not implemented.

The SHA-256 fixture constrains symbolic input bits and bounded 32-bit additions,
checks padding boundaries against the independent C hash, and produces an
honest BP++ proof of a hash preimage. A recursive verifier must connect those
input bits to the exact child transcript; a standalone hash proof is insufficient.

An AppleClang 16 / arm64 C++20 Release run measured the `abc` relation at 32,768
padded gates and a 1,267-byte proof, with about 13.76 seconds proving and 5.40
seconds verifying. Those timings exclude circuit/witness construction. Message
lengths 0, 3 and 55 use 32,768 padded gates; lengths 56 and 64 require two SHA-256
blocks and 65,536 gates. These are standalone hash-relation measurements, not
an extrapolated size or runtime for the complete receipt.

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
