# Typed SHA-256 transcript

This document specifies the reusable typed transcript state machine. Native
evaluation, replay, and the independent vector implement this exact byte
relation. Protocols using the transcript must separately bind every statement
and enforce their own acceptance conditions.

## State machine

The transcript has a 32-byte chaining state and a pending typed byte string.
It starts as:

```text
state   = SHA256("Purify/SHA256Transcript/v1")
pending = empty
```

Appending an item extends only `pending`. A challenge at index `i` computes:

```text
digest  = SHA256(state || pending || "CHAL" || BE64(i))
state   = digest
pending = empty
scalar  = ClearBit255(digest)
```

`digest` is the full 256-bit chaining state. `scalar` is its 255-bit image and
is not appended back into the transcript: the state already determines it.
Reabsorbing the scalar would add 44 redundant bytes and can force an extra
compression block at every challenge boundary.

The scalar is rejected if it is zero. There is no retry, reduction modulo the
secp256k1 group order, or zero-to-one mapping. Clearing the most significant
bit puts every nonzero output below `2^255`, which is strictly below the group
order. Thus the circuit needs only one bit truncation and one nonzero check.

## Typed framing

Every frame starts with a four-byte ASCII type followed by one unsigned
64-bit big-endian auxiliary value. The type fixes the payload length except
for `BYTE`, whose auxiliary value carries it explicitly.

| Item | Header auxiliary | Payload |
|---|---:|---|
| `FIEL` | zero | canonical field value, 32-byte big endian |
| `SCAL` | zero | canonical secp scalar, 32-byte big endian |
| `POIN` | SEC1 prefix `0`, `2`, or `3` | x coordinate, 32-byte big endian |
| `PAIR` | two-bit parity value | two x coordinates, 64 bytes total |
| `BYTE` | byte length | exact bytes |
| `U64 ` | integer value | none |
| `CHAL` | challenge index | none |
| `OBAS` | opening role | none |

A point identity is uniquely `(prefix, x) = (0, 0)`. A packed point pair uses
one parity bit per coordinate; an identity coordinate requires its bit to be
zero. V4 and accumulation validate finite SEC1 points before passing their
canonical x bytes to the transcript.

The distinct type, explicit byte length, and fixed payload sizes make item
boundaries injective. In particular, one `BYTE("ab")` frame differs from two
frames `BYTE("a"), BYTE("b")`, and a scalar differs from a field value with
the same 32-byte encoding.

## Opening-base fork

Opening-base scalar derivation does not advance the main chain. For basis
digest `d` and role `r`, it computes:

```text
opening_digest = SHA256(
    state || pending ||
    "BYTE" || BE64(32) || d ||
    "OBAS" || BE64(r))
opening_scalar = ClearBit255(opening_digest)
```

The same nonzero rule applies. Binding the 32-byte basis digest as a typed
item and using `OBAS` separates this fork from ordinary challenges and from
other opening roles. Repeating the operation is deterministic and leaves the
next ordinary challenge unchanged.

## Chaining and constrained replay

Each challenge hashes only the previous 32-byte state plus items appended
since the preceding challenge. This avoids rehashing the complete transcript
history. The constrained relation must retain all 256 digest bits as the next
state even though protocol arithmetic uses only the 255-bit scalar image.
Dropping the high digest bit would merge two distinct future transcript
states.

All lengths and round indices are public. Secret or proof-dependent payload
bytes are constrained to the canonical encodings consumed by the native
implementation. SHA-256 padding, big-endian word order, and the suite-state
initialization are part of the relation.

## Cross-language vectors

`rust/construction-parent/tests/vectors/sha256_transcript_v1.txt` pins ordinary and
opening full digests together with their scalar images. The seed-255 vector
deliberately records an `effe...` digest and its distinct `6ffe...` scalar.
Native C++ tests and `tests/reference_sha256_transcript.py` consume the same
records.
