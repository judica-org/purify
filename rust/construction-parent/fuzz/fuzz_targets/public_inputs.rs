//! Untrusted statement bytes through public-input parsing.
//!
//! The digests, counts and leaf descriptors of a construction statement come
//! from a receipt. Parsing them must reject or accept without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use statement::inputs::{PublicInputs, RawPublicInputs};
use statement::profile::{BASIS_DIGEST, RAW_GENERATOR_DIGEST};

const HEAD_BYTES: usize = 32 + 32 + 64 + 1 + 1;

fuzz_target!(|data: &[u8]| {
    let Some((head, leaf_descriptors)) = data.split_at_checked(HEAD_BYTES) else {
        return;
    };
    // The two profile digests are compared against compiled constants first;
    // supplying them keeps the fuzzer in the parsing that follows. One byte
    // per count keeps descriptor lengths reachable.
    let _ = PublicInputs::parse(RawPublicInputs {
        construction_statement_digest: head[..32].try_into().expect("32 bytes"),
        resolved_setup_record_digest: head[32..64].try_into().expect("32 bytes"),
        recovery_root: head[64..128].try_into().expect("64 bytes"),
        native_basis_digest: BASIS_DIGEST,
        native_raw_generator_digest: RAW_GENERATOR_DIGEST,
        setup_leaf_count: u32::from(head[128]),
        anchor_leaf_count: u32::from(head[129]),
        leaf_descriptors,
    });
});
