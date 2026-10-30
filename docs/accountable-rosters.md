# Ordered signing-key rosters

`accountable::SigningRoster` implements the public, untweaked key-aggregation
calculation from [BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#key-aggregation),
with explicit coalition enrollment restrictions. It supplies the aggregate
key and effective member coefficients needed by the later scalar-signature
primitives. It does not implement MuSig2 signing or transfer MuSig2's security
proof to the different [accountable signature](accountable-signatures.md)
construction.

## Input and result

The caller supplies a nonempty ordered list of compressed SEC1 individual
signing keys. Every key has exactly 33 bytes, prefix `02` or `03`, and a valid
secp256k1 x-coordinate. Both individual parities are preserved. The application
must authenticate this exact order and each key's association with its member,
Purify hosts, and enrollment consent. The library does not reorder the roster.

For fixed-size key encodings `P_i`, with `tagged` as defined in the signature
document, the implemented equations are:

```text
L   = tagged("KeyAgg list", P_0 || ... || P_(N-1))
a_1 = 1                         if N >= 2
a_i = int_be(tagged("KeyAgg coefficient", L || P_i)) mod n
                                for every other i, including N = 1
Q'  = sum_i a_i * point(P_i)
g   = 1 if Q' has even Y, otherwise -1 modulo n
Q   = g * Q'
b_i = g * a_i modulo n
```

`signing_key()` returns `x(Q)`, whose canonical lift is even Y.
`members()` retains each original compressed key and effective coefficient
`b_i`, so `Q = sum_i b_i*point(P_i)`. `aggregate_was_negated()` records whether
`g=-1`; callers must not apply that sign a second time to the returned weights.
With individual secrets matching the full compressed keys, the corresponding
normalized aggregate scalar is `q = sum_i b_i*x_i`. Nonce terms are not negated
by this key-normalization rule.

The hash `L`, exposed as `key_list_hash()`, commits only to the signing-key list.
It is not the signature context's authenticated `U`: `U` must additionally
commit to the canonical roster and Purify-host associations required by the
registration protocol. Distinct member consent and host enrollment remain
application and protocol obligations even when key aggregation succeeds.

## Restrictions and exceptional cases

- Duplicate compressed keys reject. BIP327 permits duplicates, but explicitly
  allows applications to reject them. This coalition API selects that policy;
  it does not silently drop or merge a repeated member.
- A key and its negation are distinct full public keys. Both are accepted and
  hashed with their actual prefixes; their presence does not imply independent
  controllers or independently enrolled members.
- A zero derived coefficient rejects because it would remove a member's
  signing contribution. This is a stricter policy than unrestricted BIP327.
- Intermediate point sums may be infinity; accumulation continues. A final
  aggregate at infinity rejects. Valid points with opposite prefixes and equal
  x-coordinate are handled explicitly, since the existing bridge serializes
  only nonidentity points.
- There is no singleton bypass: the one-member coefficient is hashed by the
  same algorithm, and its aggregate is normalized by the same parity rule.
- No tweaks, sorting mode, configurable hash tags, or compatibility codec are
  exposed. Member count must fit BIP327's range `1..2^32-1`, and encoded-size
  arithmetic is checked. Applications impose their resource limits before
  constructing a roster; this primitive chooses no consensus coalition cap.

Invalid points, zero coefficients, final infinity, and size violations return
`RangeViolation`; duplicates return `BindingMismatch`; an empty roster returns
`EmptyInput`. The constructed roster owns its public data and exposes only const
views. This object is not a certificate that any member consented, knows a
secret, or completed the nonce protocol.

## Vectors and remaining review

The C++ suite includes the two distinct-key ordering cases from the official
[BIP327 key aggregation vectors](https://github.com/bitcoin/bips/blob/master/bip-0327/vectors/key_agg_vectors.json),
as well as the invalid-point cases. Duplicate-key success cases from that file
are deliberately reinterpreted as rejection under this enrollment policy.

`python3 tests/reference_accountable_rosters.py` independently computes N=1,2,3
fixtures using Python integers and affine curve arithmetic. The C++ fixtures
check exact list hashes, effective coefficients, aggregate parity, and keys.
This validates implementation agreement and the public aggregate equation;
it does not establish the complete signature construction's no-framing or
extraction claims. Tests do not engineer hash preimages for zero coefficients
or cancellation of adversarially selected weighted keys.

The reviewed nonce relation, partial verification/signing, aggregation,
same-slot extraction, role separation, malicious enrollment argument, and
durable authorization/release boundaries remain separate work. Key coefficients
alone do not establish those properties.
