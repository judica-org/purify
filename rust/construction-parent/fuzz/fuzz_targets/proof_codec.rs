//! Untrusted proof bytes through the fixed proof codec.
//!
//! Every proof byte a peer supplies passes through this decoder before Nova
//! verification. It must reject or canonically accept any input without
//! panicking or allocating beyond the qualified shape.

#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use verifier::codec::ProofShape;
use verifier::nova::CompressedProof;
use verifier::suite::QUALIFIED;

const ACCEPTED: &[u8] =
    include_bytes!("../../../../tests/vectors/construction_parent_sha256_accepted.proof");

static SHAPE: LazyLock<ProofShape> = LazyLock::new(|| {
    QUALIFIED
        .proof_shape()
        .expect("the qualified suite is self-consistent")
});

fuzz_target!(|data: &[u8]| {
    // The codec rejects every other length up front, so lay the input over a
    // real proof to keep each execution inside the decoder proper.
    let mut proof = ACCEPTED.to_vec();
    let overlay = data.len().min(proof.len());
    proof[..overlay].copy_from_slice(&data[..overlay]);
    let _ = SHAPE
        .as_fixed_serde_shape()
        .decode_canonical::<CompressedProof>(&proof);
});
