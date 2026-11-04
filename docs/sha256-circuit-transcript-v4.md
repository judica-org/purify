# SHA-256 circuit transcript V4

Status: candidate native proof generation, preparation, and verification are
implemented. The recursive parent must supply the matching constrained leaf
described below. This suite does not accept a construction receipt by itself.
The constrained leaf's reduced norm equation remains a pending fixed-basis
obligation until the accumulator's final decision.

V4 derives every proof-dependent challenge with the chained typed SHA-256
transcript. It does not change secret padding, mask, or nonce PRFs because a
verifier never replays those operations.

## Public precommitment

The precommitment transcript absorbs these typed items in order:

1. bytes `Purify/BPPP/CircuitNormArg/v4/precommit`;
2. bytes exact public circuit-binding digest;
3. `u64` commitment mode (`0` hidden, `1` public);
4. `u64` padded gate count;
5. `u64` circuit commitment count;
6. `u64` norm-vector length;
7. `u64` linear-vector length;
8. `u64` public-commitment count;
9. each ordered public commitment as a point; and
10. the raw witness commitment as a point.

Challenge zero clears the digest's most significant bit and requires the
resulting scalar to be nonzero. That scalar is the public precommitment digest
`d`. The construction manifest must bind the exact 32-byte canonical encoding
of `d`. The parent later constrains the hidden raw commitment and public fields
to this value.

The mode is a closed enum. Public mode requires one public point for every
circuit commitment. Hidden mode requires no public points, but its internal
circuit-commitment count must be smaller than the padded gate count. Its
linear vector stores both groups and must retain at least one zero-coefficient
hiding coordinate. The current circuit reduction also fixes
`n_vec_len = l_vec_len = 2 * gate_count` and requires a nonzero power-of-two
gate count.

## Proof transcript

A fresh transcript absorbs:

1. bytes `Purify/BPPP/CircuitNormArg/v4/proof`;
2. scalar `d`;
3. bytes raw-generator digest;
4. the same six `u64` shape fields as the precommitment transcript;
5. challenges zero through three as `rho`, multiplication scale,
   multiplication ratio, and row ratio;
6. points coefficient commitment, anchored offset, and anchored commitment;
7. challenge four as the public-commitment batching scalar `eta`;
8. the batched public commitment point;
9. bytes containing the 32-byte even-Y Schnorr nonce x-coordinate;
10. challenge five as the DLog challenge;
11. scalar DLog response;
12. point mask commitment and scalar `t2`;
13. challenge six as masking challenge `alpha`;
14. point combined norm commitment;
15. for every inner round, one typed packed point pair followed by challenge
    `7 + round` as `gamma[round]`;
16. terminal scalars `n` and `l`; and
17. challenge `7 + round_count`, selected as `prepared_binding`.

Each challenge replaces the 256-bit chain state and clears pending items. The
derived scalar is not redundantly appended. The final `prepared_binding` is
consumed by the coefficient-reduction transcript under its own scalar frame.

Challenges clear digest bit 255 and require the resulting 255-bit scalar to be
nonzero. No reduction modulo the group order, retry loop, or zero-to-one
mapping is permitted. The complete digest, including its high bit, remains the
next constrained chain state.

## Canonical encodings

Points are compressed SEC1 or the unique 33-byte zero identity. Every finite
x coordinate must lift to secp256k1. The DLog nonce is an even-Y x-only point
in public mode.

The 65-byte inner pair has this exact format:

```text
parity2 || left_x32 || right_x32
```

Parity bit one selects the left y sign and bit zero selects the right y sign.
An all-zero x encodes the identity and requires its sign bit to be zero. The
two x coordinates must otherwise lift canonically. The constrained relation
opens and checks both y coordinates before absorbing their parity and x data.

Hidden mode still derives and appends `eta` and the DLog challenge. Its batch
point, nonce, and response must be exactly identity, zero bytes, and scalar
zero. This keeps one transcript shape without treating the zero branch as an
unframed omission.

## Native boundary and constrained requirements

The native V4 producer emits the proof fields in the order above.
Preparation reconstructs the circuit-derived constants, replays every
challenge, checks the public-mode Schnorr equation, and returns the
authenticated inner norm obligation. Full native verification also
discharges that norm argument. Preparation is deliberately not
verification and is never receipt acceptance.

The matching Rust leaf must consume the same allocated transcript variables
and constrain:

- the raw-plus-offset anchored commitment;
- the public-mode batched Schnorr equation and nonzero response;
- the masking and combined-commitment equation;
- the explicit-gamma inner norm residual and compact polynomials; and
- the coefficient-opening reduction into one pending claim.

The hidden branch must constrain the zero DLog fields. Both native modes use
finite raw, mask, anchored, and combined commitments. Reconstructed
coefficient commitments and anchored offsets may use the canonical
identity. The constrained relation must support the corresponding algebraic
identity fixtures, but the native producer intentionally exposes this
finite subset.

No caller-supplied transcript result is proof acceptance. A
purpose-specific parent must bind the leaf's exact public constants,
basis, and ordered manifest. It must authenticate every accumulation
transition and expose the final claim to the mandatory native decision.

The constrained installer must retain the exact allocated ordered public
commitments, raw and proof points, proof scalars, and round-point pairs. A
composed leaf must use those variables directly for its statement and proof
equations. Reallocating the witness fields would create an unlinked copy and
would not establish that the transcript authenticated the values checked by
the equations.

The shared public and hidden fixtures are
`rust/construction-parent/tests/vectors/sha256_circuit_v4.json` and
`rust/construction-parent/tests/vectors/sha256_circuit_v4_hidden.json`. They are
generated and checked by the stdlib-only Python oracle
`tests/reference_sha256_circuit_v4.py`. The native implementation consumes the
public fixture. The matching constrained implementation must consume both
fixtures and check the hidden fixture's zero DLog branch.

Gate counts measured for the removed field-hash relation do not apply to this
wire format. Production qualification must report the exact chained SHA-256
relation, its Nova dimensions, proof size, peak memory, and end-to-end proving
time before activation. See
[the recursive construction receipt boundary](construction-receipt.md)
for the complete acceptance boundary.
