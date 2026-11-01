# Recursive construction receipt boundary

This document fixes the selected boundary between the transparent secq parent
proof and the native BP++ accumulator. It is an implementation map, not a claim
that construction receipts are accepted yet.

The parent must authenticate independently published anchor-escrow proofs. The
assembler learns no anchor or coalition secret. Child proof payloads, norm
reduction proofs, and accumulation transitions are witnesses to the parent and
can disappear after the final receipt is published.

## Acceptance rule

A construction receipt is accepted only when both checks succeed:

1. the secq parent proof verifies for the exact construction payload, resolved
   anchor statements, and serialized root pending claim; and
2. native `accumulation::decide` discharges that exact root claim against the
   fixed anchor-escrow basis.

Neither check is optional. A pending claim does not authenticate its ancestry,
and a parent proof which does not bind the decided claim proves a different
statement.

Coalition setup is authenticated once by the registry and selected by the
payload's recovery root. The parent reconstructs each anchor statement from
that registered setup, the deterministic ordered anchor reference and resolved
root, the context, and the on-chain ciphertext. Registry authentication is
outside the proof system but is part of application acceptance.

## Constrained relation

For every anchor child, the parent performs the following operations in its
arithmetic relation:

1. Parse the fixed V3 proof payload and validate every scalar and secp256k1
   point encoding.
2. Reconstruct the exact anchor circuit and statement binding from public
   receipt data. No prover-supplied circuit digest or acceptance bit is used.
3. Replay the V3 raw-precommitment, zero-knowledge, and inner norm Fiat-Shamir
   transcripts, including canonical nonzero challenge sampling.
4. Compute the inner norm residual point and its compact generator-weight
   polynomials from the terminal scalars and folding challenges.
5. Reconstruct the exact coefficient commitment obligation and verify the
   public coefficient-opening reduction. This produces one leaf
   `PendingClaim`; it does not accept the child by itself.
6. Verify every ordered accumulation transition over those leaf claims. The
   final transition produces the root claim bound into the parent statement.

The secq commitment group has the secp256k1 coordinate field as its R1CS scalar
field. Secp256k1 point arithmetic is therefore native in the parent. BP++
scalars live modulo the secp256k1 group order and still require canonical
non-native scalar arithmetic. Proof-dependent SHA-256 challenges also remain
constrained unless the child proof suite is explicitly replaced.

The first complete group gadget constrains the secp256k1 curve equation, a
unique identity encoding, and addition for distinct points, doubling, inverses,
and both identity cases. Its circuit shape is independent of the private branch.
Point decompression, transcript hashing, non-native scalar arithmetic, and the
V3/reduction/step relations remain before an acceptance API can be exposed.

## Why the final MSM stays native

Directly checking every child's fixed-generator norm equation in the parent
would repeat linear work per anchor. The accumulator instead represents each
equation as a point and a compact polynomial over one deterministic basis.
Reduction and transition verification are logarithmic in the basis dimension.
Only the final root needs the linear fixed-basis MSM, so its cost is independent
of the number of anchors in the receipt.

For the current 8,192-gate anchor relation, the raw accumulation basis has
32,768 points and a final step has 15 folding factors. With the basis and
dimensions fixed by the receipt version, the minimal root-claim data is:

```text
point:33 || scale:32 || factors:15*32
```

That is 545 bytes before versioning and framing. It is additional to the secq
proof unless the final 32,768-term decision is moved inside the parent. Moving
that decision inside removes the public claim but makes the parent perform the
linear generator work. The initial production format should keep the explicit
claim and benchmark the native decision.

The transparent secq backend's proof length is logarithmic in its padded
multiplier count. Its implemented one-phase wire formula is:

```text
425 + 66 * ceil(log2(multiplier_count))
```

This formula does not predict the final receipt size until the full relation's
gate count is measured. The target is consequently closer to:

```text
construction payload + root pending claim + one secq parent proof
```

rather than treating the root obligation as an implicit or trusted value.

## Deterministic verification randomization

The secq backend combines independent verification equations with a random
scalar before its final MSM. That scalar is a verifier soundness challenge; it
is not secret prover randomness. Bitcoin consensus verification must not vary
with operating-system entropy.

The backend therefore seeds its verifier RNG with a domain-separated SHA-256
hash of the complete canonical circuit, statement, and proof, including length
framing. The Bulletproof library mixes that seed into its already proof-bound
Merlin transcript before sampling the equation coefficient. Every node derives
the same coefficient, while an altered circuit, statement, or proof derives a
different one. This is an intentional Fiat-Shamir transformation and relies on
the random-oracle model.

This construction currently verifies one equation bundle. A future batch
verifier must hash the complete ordered batch before deriving any coefficient.
It must not derive one coefficient and then accept later, adaptively selected
equations. Replacing the deterministic seed with `OsRng` would make consensus
acceptance depend on local state and is prohibited.

## Required negative tests

Before activation, end-to-end tests must reject at least:

- a changed setup, anchor reference, recovery root, context, or ciphertext;
- a changed V3 proof point, scalar, round message, or proof length;
- a noncanonical scalar or point and every exceptional group case;
- a valid proof moved to a different ordered manifest;
- a removed, duplicated, reordered, or substituted child;
- a changed coefficient opening or accumulation transition;
- a parent proof rebound to another root claim; and
- a valid parent proof followed by a false final native decision.

Benchmarks must report parent proving time, parent verification time, proof and
claim bytes, and final decision time separately for 1, 2, and 100 anchors.
