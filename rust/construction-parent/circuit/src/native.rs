//! Backend-independent witness types and native replays.
//!
//! These values define protocol shape and witnesses only. Constraint code
//! consumes them without owning or reinterpreting the wire format.

pub mod candidate;
pub mod circuit_norm;
pub mod circuit_transcript;
pub mod opening_generators;
pub mod recurrence;
pub mod secp;
