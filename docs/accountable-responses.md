# Public partial-response equations

The response helpers extend the experimental [scalar transcript](accountable-signatures.md)
and [ordered signing roster](accountable-rosters.md) with public algebra checks.
They do not generate secret partials or validate a Purify proof, enrollment,
member consent, a certificate, or a penalty. A point chosen by the sender does
not become an authorized deterministic nonce merely because its partial
equation holds.

## Exact equations and ordering

For roster member `i`, let `P_i` be its full compressed public key and `b_i` its
effective coefficient, which already includes aggregate-key normalization.
The caller supplies the usual `Q/U/T/body` context. Its aggregate `Q` must equal
the roster's even-Y key. Derive the existing nonzero challenge `e` once.

`PartialResponse` contains the canonical scalar `sigma_i` and the full compressed
raw nonce `R_i`. The verifier checks:

```text
R_i = sigma_i*G - (e*b_i)*P_i
```

The member index selects the coefficient and public key from the immutable
roster. Individual key parity, aggregate-key parity in `b_i`, and the raw nonce
sign are distinct: no additional sign adjustment is applied to either `b_i` or
`R_i`. Invalid nonce encodings and identity points reject. A zero scalar response
is allowed when its equation holds against a nonidentity raw nonce.

`aggregate_responses` requires exactly one response in each member's roster
position, validates every equation under the same context/challenge, and returns:

```text
sigma = sum_i sigma_i modulo n
R     = sigma*G - e*Q = sum_i R_i
```

The returned `ScalarSignature` serializes to exactly 32 bytes. Partial-session
nonces are not appended to that final scalar. A final nonce at infinity rejects;
intermediate cancellation is harmless when the final sum is nonidentity. The
function rejects an empty roster, including an empty moved-from value, before
aggregation. It allocates no temporary per-member buffers and hashes the
challenge only once.

## Caller obligations

Before treating a response as authorized, the surrounding protocol must
authenticate the roster, `U`, slot, body, and the nonce commitments/proofs at the
specified session stage. After aggregation, the final verifier still needs a
reviewed proof of the deterministic Purify relation against exactly the point
reconstructed from the scalar. A successful partial-equation check is not a
replacement for either requirement.

There is no proof-backend callback or secret signing operation in this API.
The existing experimental BP++ wrapper is not silently selected as a verifier.
The complete signature/proof composition, malicious-member security, private
prover, and durable authorization/release boundary remain open work.

## Validation scope

The focused suite uses centralized public toy keys and nonces for N=1,2,3.
It checks raw odd nonce parity, an aggregate key requiring negation, partial
verification and scalar aggregation, zero responses, member order and count,
altered contexts and equations, and final versus intermediate nonce cancellation.
It also aggregates two same-slot toy statements and recovers the exact
parity-adjusted aggregate scalar through the public extraction helper. The
fixtures exercise algebra, not complete cryptographic certificates or
adversarial proof generation.
