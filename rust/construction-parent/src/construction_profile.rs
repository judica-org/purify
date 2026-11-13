//! Frozen dimensions and digests for the construction-parent profile.

#[cfg(test)]
pub(crate) const CONSTRUCTION_LEAF_GATE_COUNT: usize = 8_192;
#[cfg(test)]
pub(crate) const CONSTRUCTION_LEAF_NORM_LENGTH: usize = 16_384;
#[cfg(test)]
pub(crate) const CONSTRUCTION_LEAF_ROUNDS: usize = 14;

pub(crate) const CONSTRUCTION_ROOT_ROUNDS: usize = 15;
pub(crate) const CONSTRUCTION_ROOT_STATE_ARITY: usize = 3 + CONSTRUCTION_ROOT_ROUNDS;
pub(crate) const CONSTRUCTION_STATE_ARITY: usize = CONSTRUCTION_ROOT_STATE_ARITY + 2;
pub(crate) const CONSTRUCTION_ROOT_BYTES: usize = 33 + 32 + 32 * CONSTRUCTION_ROOT_ROUNDS;
pub(crate) const CONSTRUCTION_RECURRENCE_STATE_ARITY: usize = CONSTRUCTION_STATE_ARITY;

/// SHA256 of the exact 32,768 raw V4 generator encodings selected by the
/// production anchor-escrow circuit.
pub(crate) const CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST: [u8; 32] = [
    0x10, 0x1c, 0xdb, 0x8d, 0x99, 0x28, 0x00, 0xb0, 0x3c, 0x39, 0x24, 0x6e, 0xb9, 0x20, 0xc8, 0x37,
    0xa8, 0x04, 0x0c, 0x5a, 0x36, 0xa0, 0x97, 0x0f, 0x0e, 0xbf, 0x85, 0x51, 0x11, 0x21, 0xca, 0x8a,
];

/// Native `NormAccumBasisV2` digest for the production anchor-escrow basis
/// domain and its fixed 16,384-by-16,384 dimensions.
pub(crate) const CONSTRUCTION_PARENT_BASIS_DIGEST: [u8; 32] = [
    0x3f, 0x0f, 0xc1, 0x07, 0x77, 0x88, 0xb6, 0x88, 0xc2, 0xf0, 0x5d, 0x6f, 0x17, 0xaf, 0x1c, 0x53,
    0x36, 0x52, 0xbe, 0x4f, 0x94, 0xd7, 0xcb, 0x4f, 0x9a, 0x70, 0x27, 0x0c, 0xd2, 0x04, 0xe1, 0x19,
];
