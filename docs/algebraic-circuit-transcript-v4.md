# Algebraic circuit transcript V4

Status: transcript foundation only. This suite does not prove a circuit,
verify a norm argument, or accept a construction receipt.

V4 replaces every proof-dependent SHA-256 challenge in the masked circuit
proof with the typed Poseidon transcript. It does not change secret padding,
mask, or nonce PRFs because a verifier never replays those operations.

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

The first canonical nonzero secp256k1 scalar in challenge lanes zero and one
at challenge index zero is the public precommitment digest `d`. The digest is
not appended to this transcript. The construction manifest must bind the
exact 32-byte canonical encoding of `d`. The parent later constrains the
hidden raw commitment and public fields to this value.

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
5. challenges zero through three, appending each selected scalar as `rho`,
   multiplication scale, multiplication ratio, and row ratio;
6. points coefficient commitment, anchored offset, and anchored commitment;
7. challenge four, appended as the public-commitment batching scalar `eta`;
8. the batched public commitment point;
9. bytes containing the 32-byte even-Y Schnorr nonce x-coordinate;
10. challenge five, appended as the DLog challenge;
11. scalar DLog response;
12. point mask commitment and scalar `t2`;
13. challenge six, appended as masking challenge `alpha`;
14. point combined norm commitment;
15. for every inner round, one typed packed point pair followed by challenge
    `7 + round`, whose selected scalar is appended as `gamma[round]`;
16. terminal scalars `n` and `l`; and
17. challenge `7 + round_count`, selected as `prepared_binding`.

The final `prepared_binding` is not appended. The coefficient-reduction
transcript consumes its canonical scalar value under its own type frame.

Challenges use the fixed two-lane rule: select the first lane whose canonical
integer is in `[1, group_order - 1]`, otherwise require and select the second.
No reduction modulo the group order, retry loop, or zero-to-one mapping is
permitted.

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

## Boundary

The native state machine validates framing and returns challenges only. The
Rust relation constrains the same typed replay and the public digest. Neither
checks:

- the anchored-commitment addition;
- the batched Schnorr equation;
- the masking commitment equation;
- the inner norm folding equation; or
- the coefficient reduction and final accumulator decision.

Those equations must consume the constrained values in one purpose-specific
parent relation. No caller-supplied transcript result is proof acceptance.

The constrained installer retains the exact allocated ordered public
commitments, raw and proof points, proof scalars, and round-point pairs. A
composed leaf must use those variables directly for its statement and proof
equations. Reallocating the witness fields would create an unlinked copy and
would not establish that the transcript authenticated the values checked by
the equations.

The shared public and hidden fixtures are
`rust/receipt-cycle/tests/vectors/algebraic_circuit_v4.json` and
`rust/receipt-cycle/tests/vectors/algebraic_circuit_v4_hidden.json`. They are
generated and checked by the stdlib-only Python oracle
`tests/reference_algebraic_circuit_v4.py`. The public fixture is consumed by
the native and constrained implementations; the constrained implementation
also checks the hidden fixture and its zero DLog branch.
