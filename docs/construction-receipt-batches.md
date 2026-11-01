# Construction receipt batch statements

This document fixes the first construction-receipt partition suite. It defines
which ordered anchor entries a bounded parent circuit is responsible for. It
does not define proof bytes, recursive aggregation, network state, or an
acceptance API.

The complete construction statement is already committed by
`ConstructionReceiptStatementDigest`. That digest binds the canonical payload,
the resolved setup-record digest, and every resolved anchor input in order. A
batch therefore binds that complete digest and an exact contiguous range. No
second Merkle commitment or mutable batch manifest is needed at this layer.

## Version-one descriptor

Version one fixes a maximum of 16 anchor entries per batch. Its canonical
statement is exactly 54 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | statement-suite version, `1` |
| 1 | 32 | full `ConstructionReceiptStatementDigest` |
| 33 | 4 | total anchor-entry count, big endian |
| 37 | 4 | zero-based batch index, big endian |
| 41 | 4 | total batch count, big endian |
| 45 | 4 | inclusive entry start, big endian |
| 49 | 4 | exclusive entry end, big endian |
| 53 | 1 | canonical setup-inclusion boolean |

The batch statement digest is BIP340-style tagged SHA-256 over those exact
bytes with domain
`Purify/Accountable/ConstructionReceiptBatchStatement/v1`. The leading byte
and hash domain together bind the statement suite and version. Changing a
field, including a redundant derived field, changes the statement.

For a nonzero total `N`, let `B = ceil(N / 16)`. Batch `i` is defined only for
`0 <= i < B` and has:

```text
batch_count = B
entry_start = 16 * i
entry_end = min(entry_start + 16, N)
includes_setup = (i == 0)
```

Consequently every entry appears exactly once, ranges are contiguous and in
order, and the shared setup relation appears exactly once in the first batch.
There is no valid descriptor or partition for `N = 0`.

The codec carries the derived count, range, and setup flag deliberately. A
decoder regenerates them from `N` and `i` and rejects any mismatch. A complete
partition validator regenerates all `B` descriptors for the expected full
statement and requires exact ordered equality. This rejects omitted,
duplicated, overlapping, reordered, foreign-statement, and out-of-range
batches without workflow state.

## Circuit boundary

`ConstructionReceiptBatchDescriptor::serialize()` supplies canonical public
statement bytes, and `statement_digest()` supplies their domain-separated
digest. A future parent relation must bind one of those forms and constrain
the exact selected entry range. The descriptor alone does not prove that work
or authenticate any child proof.

Later recursive or accumulated layers may combine batch proofs, but they must
preserve the full construction digest and ordered descriptor identity. This
partition layer intentionally does not choose their proof encoding or final
decision rule.
