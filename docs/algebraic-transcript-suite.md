# Algebraic transcript suite candidate

Status: foundation only. Nothing in this document changes an accepted proof,
receipt, BPPP transcript, or accumulation transcript.

## Primitive

The candidate permutation is original Poseidon over the secp256k1 coordinate
field

```
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
```

with these parameters:

| Parameter | Value |
|---|---:|
| State width | 3 |
| Sponge rate | 2 |
| Sponge capacity | 1 |
| S-box | x^5 |
| Full rounds | 8 |
| Partial rounds | 64 |
| Target security | 128 bits |

`gcd(5, p - 1) = 1`, so `x^5` is a permutation of the field. The Poseidon
paper's updated width-three, 128-bit parameter set uses 8 full and 57 partial
rounds. This candidate keeps seven additional partial rounds. Each S-box needs
three multiplication constraints, so one permutation needs exactly

```
(8 * 3 + 64) * 3 = 264
```

multipliers. Addition of constants and the MDS layer are linear.

The internal Secq R1CS gadget now instantiates exactly those constants and MDS
entries. One permutation uses 264 multipliers. Binding all three output lanes
adds three linear constraints, for 531 explicit linear constraints under the
backend's two input constraints per multiplier. Its circuit shape is identical
for different input states. This gadget remains disconnected from receipt
acceptance until the complete typed transcript suite is frozen and migrated.

The parameter generator is equivalent to the Poseidon v1.1 Sage generator in
`daira/pasta-hadeshash` commit
`5959f2684a25b372fba347e62467efb00e7e2c3f`. Its inputs are equivalent to:

```
generate_parameters_grain.sage \
    1 0 256 3 8 64 \
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
```

Round constants come from the Appendix E self-shrinking Grain stream. The MDS
matrix is the first secure random Cauchy matrix from the continuation of that
same stream. The implementation reruns the width-three instances of the
reference generator's three subspace checks before accepting a matrix.

For independent implementations, SHA-256 over the big-endian 32-byte round
constants in round/lane order is:

```
de0209e6db9909a2bebd435499a3dd1e199626ac0d1415b55f832c8dd5bdca6d
```

SHA-256 over the row-major MDS entries in the same encoding is:

```
b214b9440fa5cb193ab6bc98fad114eaad5da447dc61629c03ab1805328945d5
```

The cross-language permutation vectors live in
`rust/receipt-cycle/tests/vectors/poseidon_secp256k1_p.txt`.

Primary references:

- Grassi et al., *POSEIDON: A New Hash Function for Zero-Knowledge Proof
  Systems*, IACR ePrint 2019/458.
- The Poseidon v1.1 parameter generator pinned above.
- Zhao and Ding, *Breaking Poseidon Challenges with Graeffe*, IACR ePrint
  2025/950. Its cost estimate for the related 255-bit, 8/56 instance is about
  2^198; this candidate does not reduce those rounds.

## Candidate transcript encoding

The eventual transcript must be a typed field sponge. Hashing an ambiguous
concatenation of field elements would reintroduce cross-type and length
collisions even if the permutation itself is sound.

The proposed state ordering is `[capacity, rate_0, rate_1]`. Initialize the
capacity to the big-endian integer encoding of the ASCII suite identifier
`Purify/PoseidonTranscript/v1` and both rate lanes to zero. To absorb a field
word, add it to the next rate lane and permute whenever both rate lanes are
full.

Every item begins with one field header:

```
header = (type << 64) | auxiliary
```

`type` is a fixed 32-bit suite constant and `auxiliary` is a 64-bit length,
counter, or canonical encoding flag. The candidate type constants are:

| Item | Type | ASCII |
|---|---:|---|
| Coordinate-field element | `0x4649454c` | `FIEL` |
| secp256k1 scalar | `0x5343414c` | `SCAL` |
| BPPP point pair | `0x50414952` | `PAIR` |
| Byte string | `0x42595445` | `BYTE` |
| `u64` | `0x55363420` | `U64 ` |
| Challenge request | `0x4348414c` | `CHAL` |

Candidate item encodings are:

- A BPPP point pair absorbs a header whose auxiliary value is the canonical
  two-bit parity byte, followed by the two coordinate-field x values. An all
  zero x value with a zero parity bit retains the existing infinity encoding.
- A secp256k1 scalar absorbs a scalar header followed by its canonical integer
  in `[0, n - 1]`, embedded directly into the coordinate field.
- A coordinate-field element absorbs a field header followed by its canonical
  value.
- Arbitrary bytes absorb a bytes header whose auxiliary value is the byte
  length, followed by 31-byte big-endian limbs. The final short limb is not
  extended with message bytes; the explicit byte length distinguishes it.
- A `u64` can be carried entirely in the auxiliary part of a `u64` header.

The canonical relation builder implements these headers and the typed duplex
operations. Its probe covers a field element, scalar, point pair, 33-byte
string, `u64`, and challenge request. Seven permutations plus nine private
allocations use 1,857 gates and produce a 1,151-byte standalone backend proof.
Native and constrained outputs agree; changed witnesses and outputs reject.
Item type, byte length, item boundary, point parity, and challenge index all
change the squeeze. This remains candidate behavior and must not become an
accepted wire format before the complete migration review.

To derive a challenge, clone the current sponge, absorb a suite-specific
challenge header with the round index in `auxiliary`, then append field padding
`1, 0*` through the next rate boundary. Permute and take both rate lanes as
ordered candidates. The append-only main transcript remains unchanged, which
matches the current BPPP clone-and-index SHA behavior.

## Reduction to a nonzero secp256k1 scalar

Let

```
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
```

For each squeezed coordinate-field value, use its canonical integer directly
only when it is in `[1, n - 1]`. Choose the first valid lane, otherwise the
second, and reject the transcript if both are invalid. A lane rejects with
probability approximately `(p - n + 1) / p`, or 2^-127.65. Both lanes reject
with probability about 2^-255.3 under the Poseidon sponge assumption.

The parent relation must constrain both range tests and the selection. A native
implementation may not replace this rule with `% n`, map zero to one, or loop
until success: those alternatives either bias the challenge or give the native
and fixed-shape circuit implementations different transcripts.

## Migration boundary

The SHA transcript is hardcoded in both the vendored BPPP norm-product code and
Purify's constant-time secret prover. The smallest complete migration is:

1. Test this permutation in native Rust, in the Secq R1CS field, and against a
   second-language implementation.
2. Add one internal append/challenge operation surface used by the vendored
   prover and verifier and by the constant-time prover. Do not fork a second
   verifier.
3. Move every proof-dependent outer, BPPP, and accumulation challenge onto one
   frozen typed suite, or continue constraining the old hash exactly.
4. Cut a new proof and receipt format only after end-to-end native/circuit
   agreement tests pass. Remove the obsolete SHA transcript at cutover instead
   of retaining proof-wrapper aliases.

The current exact SHA gadget costs 30,952 multipliers per compression block.
The existing proof-dependent path uses about 34 such blocks per anchor, or
roughly 1.05 million SHA multipliers before group and scalar checks. Even four
Poseidon permutations per BPPP round would cost only 1,056 multipliers per
round. Exact transcript costs must be measured after the framing above is
frozen rather than inferred from the permutation alone.
