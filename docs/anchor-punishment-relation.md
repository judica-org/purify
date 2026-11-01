# Anchor punishment-key relation

An anchor escrow proves one relation over the same canonical companion-curve
secret `(d1, d2)`:

1. `D = (x(d1 G1), x(d2 G2))` is the advertised anchor recovery root.
2. The ciphertext decrypts to `(d1, d2)` under the coalition recovery root.
3. `k_raw = PurifyEval((d1, d2), punishment_domain)`.
4. `k = k_raw` or `-k_raw`, selected so `k G` has even Y.
5. The sole circuit output is `k`, publicly committed as canonical
   `02 || x(k G)` by the V4 public-commitment proof.

The pinned evaluation input is the exact ASCII byte string
`Purify/Accountable/AnchorPunishmentKey/v1`. The ordinary Purify evaluation
bases are therefore
`H2C("Eval/1/" || punishment_domain)` and
`H2C("Eval/2/" || punishment_domain)`. This 41-byte input cannot equal an
accountable PureSign nonce input. Its nonce context is first reduced to a
32-byte digest under `Purify/Accountable/Nonce/v2`, then the actual Purify
input is `PureSign/Nonce/Topic/ || digest`. There is no SHA-256 gadget in the
circuit.

Record version 3 fixes the modern tagged hash-to-curve mode. A build configured
with `PURIFY_USE_LEGACY_FIELD_HASHES` returns `UnsupportedSymbol` before
deriving, proving, preparing, verifying, or recovering this suite. Record
parsing, basis construction, and envelope framing remain syntax-only transport
operations; none accepts a proof. Generic legacy-mode Purify APIs remain
available, but they cannot create an alternate anchor-v3 protocol under the
same record and statement versions. A production parent loader must likewise
reject legacy mode before loading the modern anchor-v3 public parameters.

The relation reuses the escrow's existing `d1` and `d2` bit witnesses and
generator multiplications. A second multiplication of the same bits by each
fixed message base costs 335 gates rather than 423 because its 88 bit-only
lookup products are already present. The exact shape is:

| Component | Gates |
| --- | ---: |
| Existing escrow relation | 6,262 |
| Two fixed-base evaluation multiplications | 670 |
| Purify output combiner | 4 |
| Boolean sign and conditional negation | 2 |
| Total unpadded | 6,938 |
| Padded suite | 8,192 |

Consequently the existing 14-round, 974-byte norm proof and 16,384-element
accumulation basis remain unchanged. Public commitment mode adds its 32-byte
DLog nonce and 32-byte response. The independent record is therefore 1,329
bytes: one version byte, 192 bytes of ciphertext, and 1,136 proof bytes.

The construction payload remains `69 + 224*N` bytes. Its resolved statement,
which is authenticated by the parent receipt, binds the canonical punishment
key in addition to the anchor reference, recovery root, and context. The
punishment key is deliberately not duplicated in the payload.

## Security boundary

The fixed-domain construction relies on a related-output extension of
Purify's multi-query PRF/key-recovery assumption: an adversary sees the
secp256k1 point of the fixed-domain output alongside nonce-domain queries, and
later learns the scalar only when coalition exposure intentionally enables
punishment. This related-output extension is an explicit protocol assumption,
not a reduction established by this implementation.
Using a cheaper linear projection such as `d1 + h*d2` would instead add a
correlated multi-group discrete-log/related-key assumption and make future
linear outputs accumulate equations in the recovery secret. The linear
projection is not part of this suite.

Native construction rejects a zero evaluation before proving. It validates
the supplied `GeneratedKey`, canonicalizes the evaluation scalar with the
secp256k1 BIP340 helper, and checks the exact x-only key supplied by the
application. Recovery repeats all three checks after decryption and returns a
move-only purpose-specific key. Raw, normalized, assignment, and decrypted
secret copies are wiped at their ownership boundaries.

Zero has no counter-based retry encoding. An application encountering the
negligible zero case must generate a different anchor recovery key before the
anchor is published, so native and circuit evaluation cannot select different
rekey branches.

## Recurrence migration boundary

The construction payload framing does not change, but the Rust production
anchor recurrence currently selects a hidden V4 leaf. It must be migrated in
a separate change to a public leaf and constrain the public DLog equation
under the exact resolved statement. The construction statement digest and
initial manifest already bind that resolution. Activating a parent built for
the hidden anchor suite against this record version would be a protocol error.
The `69 + 224*N` payload boundary is unchanged; no punishment key is added to
the payload entry.
