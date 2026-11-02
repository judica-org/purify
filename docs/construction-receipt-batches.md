# Historical construction receipt batch statements

This document records the pre-Nova version-one partition suite for bounded flat
parents. It is not the selected construction-receipt path. The selected
homogeneous Nova recurrence processes one anchor per step from an immutable
registry seed. Version-one descriptors must not be reinterpreted as Nova
consensus objects.

The legacy `ConstructionReceiptStatementDigest` binds the legacy payload, the
resolved setup-record digest, and every resolved anchor input in order. A new
receipt version must additionally bind every public V4 precommitment and the
recurrence's initial-manifest inputs.

## Historical version-one descriptor

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

No selected Nova recurrence consumes this descriptor. Its serialization and
digest remain useful only for legacy parser tests and historical flat-parent
experiments. A new construction-receipt version must define its own initial
manifest, exact step count, and payload binding.

The value 16 is a statement-partition limit, not a measured flat-circuit
capacity. With the current production-shape V4 leaves and shared-power
step, setup plus 12 anchors totals 16,041,247 gates and fits under the
`2^24` gate cap. Setup plus 13 totals 17,239,860 gates and does not
fit. A later step without setup fits 13 anchors at 16,170,296 gates. A
14-anchor step totals 17,368,909 and does not fit. These are
arithmetic-only bounds. No near-cap shape has been qualified for peak
memory or full proving time.

This mismatch is why the flat 16-entry and proof-tree route was rejected. The
selected design does not place a proof tree inside a version-one descriptor and
does not reinterpret its ranges. It uses a new versioned receipt whose
recurrence authenticates one ordered anchor per step.

The selected recurrence binds the full construction statement, setup-record
digest, seed root, and count into its initial manifest, then binds each
zero-based index and exact leaf constants at every step. Native
verification-equation batching still retains all child proofs and is not a
post-hoc compressor. The version-one batch layer is not part of receipt
acceptance.
