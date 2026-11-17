//! The construction-parent step relation and its native witness model.
//!
//! `native` holds the backend-independent witness types and the native
//! replays they are checked against. `gadgets` holds reusable constraint
//! building blocks over secp256k1 and SHA-256. `relation` composes them into
//! the one step circuit whose streamed identity the proof suite pins.
//!
//! This crate never ships inside the verifier library.

#![forbid(unsafe_code)]

pub mod gadgets;
pub mod native;
pub mod profile;
pub mod relation;
