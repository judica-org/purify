//! The construction-parent step relation.
//!
//! Each module constrains one protocol stage directly on Nova's frontend.
//! `recurrence` composes them into the step circuit, and `identity` streams
//! that circuit into the relation ID the proof suite pins.

pub mod candidate;
pub mod identity;
pub mod norm_leaf;
pub mod norm_reduction;
pub mod opening_base;
pub mod recurrence;
pub mod transcript;
