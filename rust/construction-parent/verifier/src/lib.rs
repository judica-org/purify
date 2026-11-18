//! Verifier backend for Purify construction-parent proofs.
//!
//! The dynamic library exports only the purpose-specific construction-parent
//! verifier through its private C ABI in `ffi`. C++ reconstructs and decides
//! the authenticated pending root before receipt acceptance.
//!
//! The Rust API exists for the in-repository prover, which encodes proofs
//! with the same codec, checks its output with the same verifier, and frames
//! its own artifact with the same authenticated reader. This crate contains
//! no setup, proving, or circuit code, and no artifact writer.

#![deny(unsafe_code)]

// Authenticated framing shared by verifier and prover deployment artifacts.
pub mod artifact;
// Fixed-shape proof codec. This is not a receipt parser.
pub mod codec;
// Authenticates a pending construction root. Native decide remains mandatory
// before receipt acceptance.
pub mod construction;
// This private ABI returns only a proof-authenticated pending root. The C++
// acceptance boundary must parse and decide that root before exposing success.
#[allow(unsafe_code)]
mod ffi;
// Verification-only Nova state for one locally pinned suite.
pub mod nova;
// Private, immutable input snapshots for artifact loading.
pub mod snapshot;
// The one locally pinned proof-suite profile.
pub mod suite;
