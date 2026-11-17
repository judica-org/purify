//! Frozen dimensions of the construction-parent step relation.
//!
//! The statement-level profile is re-exported so relation code has one place
//! to look for every pinned dimension.

pub use statement::profile::*;

pub const LEAF_GATE_COUNT: usize = 8_192;
pub const LEAF_NORM_LENGTH: usize = 16_384;
pub const LEAF_ROUNDS: usize = 14;

pub const RELATION_AUXILIARY: usize = 7_609_014;
pub const RELATION_CONSTRAINTS: usize = 7_653_553;
