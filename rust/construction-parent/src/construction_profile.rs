//! Frozen dimensions and digests for the construction-parent profile.

#[cfg(any(test, feature = "prover"))]
pub(crate) const CONSTRUCTION_LEAF_GATE_COUNT: usize = 8_192;
#[cfg(any(test, feature = "prover"))]
pub(crate) const CONSTRUCTION_LEAF_NORM_LENGTH: usize = 16_384;
#[cfg(any(test, feature = "prover"))]
pub(crate) const CONSTRUCTION_LEAF_ROUNDS: usize = 14;

#[cfg(any(test, feature = "prover"))]
pub(crate) const CONSTRUCTION_PARENT_RELATION_AUXILIARY: usize = 7_609_014;
#[cfg(any(test, feature = "prover"))]
pub(crate) const CONSTRUCTION_PARENT_RELATION_CONSTRAINTS: usize = 7_653_553;

pub(crate) const CONSTRUCTION_ROOT_ROUNDS: usize = 15;
pub(crate) const CONSTRUCTION_ROOT_STATE_ARITY: usize = 3 + CONSTRUCTION_ROOT_ROUNDS;
pub(crate) const CONSTRUCTION_STATE_ARITY: usize = CONSTRUCTION_ROOT_STATE_ARITY + 2;
pub(crate) const CONSTRUCTION_ROOT_BYTES: usize = 33 + 32 + 32 * CONSTRUCTION_ROOT_ROUNDS;
pub(crate) const CONSTRUCTION_RECURRENCE_STATE_ARITY: usize = CONSTRUCTION_STATE_ARITY;

/// SHA256 of the exact 32,768 raw V4 generator encodings shared by both
/// production construction-leaf relations.
pub(crate) const CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST: [u8; 32] = [
    0x10, 0x1c, 0xdb, 0x8d, 0x99, 0x28, 0x00, 0xb0, 0x3c, 0x39, 0x24, 0x6e, 0xb9, 0x20, 0xc8, 0x37,
    0xa8, 0x04, 0x0c, 0x5a, 0x36, 0xa0, 0x97, 0x0f, 0x0e, 0xbf, 0x85, 0x51, 0x11, 0x21, 0xca, 0x8a,
];

/// Native `NormAccumBasisV2` digest for the homogeneous construction-leaf
/// domain and its fixed 16,384-by-16,384 dimensions.
pub(crate) const CONSTRUCTION_PARENT_BASIS_DIGEST: [u8; 32] = [
    0x3e, 0x22, 0x80, 0x71, 0x8c, 0xf5, 0x97, 0x0d, 0xaf, 0x53, 0xb8, 0xec, 0x3f, 0xf1, 0x1d, 0x59,
    0x2a, 0x71, 0x48, 0x35, 0x14, 0xba, 0x91, 0xa6, 0xf1, 0xb3, 0x72, 0x08, 0xad, 0x9e, 0xb5, 0x94,
];
