# Slash adaptor receipts

Slash adaptor receipts authorize one exact BIP340 spend when a coalition key is
exposed. They are an optional exact-spend slashing primitive when Char can
determine the slash transaction from consensus data. They do not recover the
anchor private key and do not provide a general decryption service.

## Statement

The statement contains:

- the anchor x-only key `P = xG`, using its even BIP340 lift;
- the exact even compressed coalition point `Q = qG`;
- the 32-byte BIP341 signature digest `m`; and
- a receipt `(A, s_hat)`.

The coalition point is not merely x-only. Requiring the exact even point makes
the exposed scalar unambiguous: only `q` with `qG = Q` is accepted; `-q` is not.

For a nonzero nonce `k`, let:

```text
K = kG
A = K + Q
nu = +1 when A has even Y, otherwise -1
R = nu*A
e = tagged_hash("BIP0340/challenge", x(R) || x(P) || m) mod n
s_hat = nu*k + e*x mod n
```

The verifier parses every point and scalar canonically, requires `A - Q` to be
finite, and checks:

```text
s_hat*G = R - nu*Q + e*P
```

The `A - Q` check is a security condition, not only input hygiene. If `A = Q`,
then `K` is infinity and a valid-looking `s_hat = e*x` directly exposes the
anchor key.

Once the accountable signing protocol exposes the exact coalition scalar, any
observer completes the ordinary BIP340 signature:

```text
s = s_hat + nu*q mod n
signature = x(R) || s
```

Extraction from the exact final signature is:

```text
q_candidate = nu*(s - s_hat) mod n
```

Extraction succeeds only after verifying the final BIP340 signature for the
same `P`, `m`, and `x(R)`, and checking `q_candidate*G = Q` exactly.

## Wire format

The receipt is exactly 65 bytes:

```text
33 bytes  A, canonical compressed SEC1 including parity
32 bytes  s_hat, canonical scalar
```

No DLEQ proof, companion-curve key, encrypted anchor scalar, or trusted setup is
needed. The parity byte is deliberately retained because it selects the sign of
the scalar used for adaptation and extraction.

The 65 bytes are the cryptographic payload, not a complete registration record.
The surrounding Char encoding must bind the receipt to its anchor identifier,
coalition core digest, exact `Q`, and transaction-template version. Those values
may be implicit in an authenticated indexed record, but they must not be inferred
from an optional local lookup.

## Transaction and data-availability contract

The cryptographic API accepts the final 32-byte signature digest. It does not
carry or interpret a Bitcoin transaction. Char must bind that digest to the
exact slash transaction before accepting a receipt.

For Bitcoin-only L2 reconstruction, every field needed to recompute the digest
must be deterministic from on-chain anchor data and protocol constants, or the
unsigned transaction skeleton must itself be consensus-available. Publishing
only a template hash is insufficient when a synchronizing node cannot recover
the preimage transaction.

Two fee policies are reasonable:

1. Use `SIGHASH_DEFAULT` or `SIGHASH_ALL` for a fixed parent and pay additional
   fees through a separately signed CPFP child or package.
2. Use `SIGHASH_ALL | SIGHASH_ANYONECANPAY` (`0x81`) with all slash outputs and
   the full anchor value fixed. Fee sponsors may append independently signed
   inputs without changing the anchor input's digest.

`SIGHASH_NONE` does not preserve slash value. `SIGHASH_SINGLE | ANYONECANPAY`
needs additional output-index and full-value invariants and is not the default
profile.

The consensus statement must fix at least the anchor outpoint, amount and
scriptPubKey, transaction version, locktime, input sequence, sighash type,
Taproot extension fields, annex absence or contents, and every committed output.

## Lifecycle

A receipt belongs to one anchor UTXO, coalition point, and slash transaction.
Rebonding or coalition rotation creates a new receipt. An old receipt remains
usable if its old coalition scalar is later exposed, so an anchor must not leave
the old liability set until the corresponding UTXO is spent or the protocol's
settlement delay has elapsed.

The adaptor signature does not prevent the anchor holder from spending the UTXO
first. The bond script and state-transition rules must keep the ordinary return
path unavailable until the liability and challenge window has elapsed. If the
holder can make an immediately valid competing spend, the adaptor provides only
a transaction race, not guaranteed slashability.

Receipt acceptance and publication must occur before the anchor becomes active.
Local relay, notification, and fee policy must not decide whether the durable
receipt exists.

## Security boundary

The receipt guarantees authorization of the bound slash spend after exact `q`
exposure. It does not:

- recover the anchor key;
- hide the transaction template;
- make an unavailable template reconstructible;
- decide when a coalition has equivocated; or
- replace the durable one-session signing database needed to guarantee that
  conflicting coalition signatures expose `q`.

Receipt creation uses a BIP340-style hedged nonce. A tagged derivation combines
the canonical anchor secret with fresh operating-system auxiliary randomness
and commits to `P`, the full `Q`, `m`, and a retry counter. RNG repetition or
rollback therefore cannot reuse `k` across distinct statements. Creation
rejects zero, rejects `K + Q` at infinity, and self-verifies the public equation
before returning. Direct nonce reuse across different messages or coalition
points under one anchor can expose the anchor secret and is forbidden.

The version-one nonce transcript is:

```text
aux_hash = tagged_hash("Char/SlashAdaptor/aux/v1", auxiliary_randomness)
t = bytes(x) XOR aux_hash
k = int(tagged_hash(
        "Char/SlashAdaptor/nonce/v1",
        t || x(P) || compressed(Q) || m || counter_u32_be)) mod n
```

The counter starts at zero and advances only when `k` is zero or `K + Q` is
infinity. Both tags and the exact transcript are consensus-versioned inputs;
changing them changes every receipt.
