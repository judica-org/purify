//! Private C ABI for the selected construction-parent verifier.
//!
//! This boundary can return only a proof-authenticated pending root. It is
//! deliberately not installed as a public C API: the C++ construction
//! verifier must parse the returned root against the fixed native basis and
//! complete `decide()` before exposing receipt acceptance.
//!
//! The entry points only turn caller memory into Rust values, and Rust
//! results into a status. Every statement and proof check lives in safe code
//! behind them.

use core::mem::{offset_of, size_of};
use core::ptr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use crate::construction::{ConstructionParentVerifier, ConstructionParentVerifierError};
use crate::nova::{VerifyError, QUALIFIED_VERIFIER_ARTIFACT};
use crate::snapshot::PrivateArtifactSnapshot;
use statement::inputs::{PublicInputs, RawPublicInputs};
use statement::profile::ROOT_BYTES;

/// Values mirrored by the private construction-parent bridge header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PurifyConstructionParentStatus {
    Ok = 0,
    Malformed = 1,
    ProofRejected = 2,
    ArtifactOpenFailed = 3,
    ArtifactRejected = 4,
    ArtifactSnapshotFailed = 5,
    /// A panic was contained at this boundary.
    InternalError = 6,
}

type Status = PurifyConstructionParentStatus;

/// Opaque owner of the locally configured construction verifier.
pub(crate) type PurifyConstructionParentVerifier = ConstructionParentVerifier;

/// Fixed-layout public statement mirrored by the private bridge header.
///
/// The fields are byte arrays followed by two `u32` counts, so the layout has
/// no padding and every bit pattern is a valid value.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PurifyConstructionParentStatement {
    construction_statement_digest: [u8; 32],
    resolved_setup_record_digest: [u8; 32],
    recovery_root: [u8; 64],
    native_basis_digest: [u8; 32],
    native_raw_generator_digest: [u8; 32],
    setup_leaf_count: u32,
    anchor_leaf_count: u32,
}

const STATEMENT_BYTES: usize = 200;
const _: () = {
    assert!(size_of::<PurifyConstructionParentStatement>() == STATEMENT_BYTES);
    assert!(offset_of!(PurifyConstructionParentStatement, setup_leaf_count) == 192);
    assert!(offset_of!(PurifyConstructionParentStatement, anchor_leaf_count) == 196);
};

/// Runs one entry point's body, reporting a panic as `InternalError`.
///
/// Unwinding out of an `extern "C"` function aborts the host process. Each
/// entry point clears its output before calling this, so a contained panic
/// leaves the caller with a failure status and no partial result. The body
/// only reads the verifier, whose key is immutable after loading.
fn contain_panics(body: impl FnOnce() -> Result<(), Status>) -> Status {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => Status::Ok,
        Ok(Err(status)) => status,
        Err(_) => Status::InternalError,
    }
}

unsafe fn borrow_input<'a>(data: *const u8, length: usize) -> Result<&'a [u8], Status> {
    if length == 0 {
        return Ok(&[]);
    }
    if data.is_null() {
        return Err(Status::Malformed);
    }
    // SAFETY: the private ABI requires every nonempty input to identify a
    // readable allocation of exactly `length` bytes for the complete call.
    Ok(unsafe { slice::from_raw_parts(data, length) })
}

fn artifact_snapshot_status(error: &std::io::Error) -> Status {
    match error.kind() {
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::InvalidData => {
            Status::ArtifactRejected
        }
        _ => Status::ArtifactSnapshotFailed,
    }
}

/// Snapshots, opens, and authenticates the configured verifier artifact.
///
/// The path selects only a storage location; artifact identity is compiled
/// into the verifier.
fn load_verifier(artifact_path: &[u8]) -> Result<ConstructionParentVerifier, Status> {
    if artifact_path.is_empty() || artifact_path.contains(&0) {
        return Err(Status::Malformed);
    }
    let artifact_path = std::str::from_utf8(artifact_path).map_err(|_| Status::Malformed)?;
    let mut source = std::fs::File::open(artifact_path).map_err(|_| Status::ArtifactOpenFailed)?;
    let mut artifact = PrivateArtifactSnapshot::copy_from(
        &mut source,
        QUALIFIED_VERIFIER_ARTIFACT.encoded_length(),
    )
    .map_err(|error| artifact_snapshot_status(&error))?;
    drop(source);
    ConstructionParentVerifier::load(artifact.reader()).map_err(|_| Status::ArtifactRejected)
}

/// Parses one statement, checks it against the compiled profile, and
/// authenticates the proof's pending root for it.
fn authenticate_root(
    verifier: &ConstructionParentVerifier,
    statement: &PurifyConstructionParentStatement,
    leaf_descriptors: &[u8],
    proof: &[u8],
) -> Result<[u8; ROOT_BYTES], Status> {
    let inputs = parse_statement(statement, leaf_descriptors)?;
    let authenticated = verifier
        .authenticate(&inputs, proof)
        .map_err(verifier_status)?;
    Ok(*authenticated.canonical_root_bytes())
}

fn parse_statement(
    statement: &PurifyConstructionParentStatement,
    leaf_descriptors: &[u8],
) -> Result<PublicInputs, Status> {
    PublicInputs::parse(RawPublicInputs {
        construction_statement_digest: statement.construction_statement_digest,
        resolved_setup_record_digest: statement.resolved_setup_record_digest,
        recovery_root: statement.recovery_root,
        native_basis_digest: statement.native_basis_digest,
        native_raw_generator_digest: statement.native_raw_generator_digest,
        setup_leaf_count: statement.setup_leaf_count,
        anchor_leaf_count: statement.anchor_leaf_count,
        leaf_descriptors,
    })
    .map_err(|_| Status::Malformed)
}

fn verifier_status(error: ConstructionParentVerifierError) -> Status {
    match error {
        ConstructionParentVerifierError::Nova(VerifyError::ProofLength { .. }) => Status::Malformed,
        ConstructionParentVerifierError::State(_)
        | ConstructionParentVerifierError::Nova(_)
        | ConstructionParentVerifierError::FinalManifest
        | ConstructionParentVerifierError::FinalIndex => Status::ProofRejected,
    }
}

/// Loads the verifier stored at an explicit UTF-8 path.
///
/// `verifier_output` is set to null before any validation or I/O and owns one
/// verifier only on success.
#[no_mangle]
pub(crate) unsafe extern "C" fn purify_construction_parent_verifier_load(
    artifact_path: *const u8,
    artifact_path_length: usize,
    verifier_output: *mut *mut PurifyConstructionParentVerifier,
) -> Status {
    if verifier_output.is_null() {
        return Status::Malformed;
    }
    // SAFETY: the ABI requires one writable verifier pointer.
    unsafe { verifier_output.write(ptr::null_mut()) };
    contain_panics(|| {
        // SAFETY: the ABI requires `artifact_path_length` readable bytes.
        let artifact_path = unsafe { borrow_input(artifact_path, artifact_path_length) }?;
        let verifier = Box::into_raw(Box::new(load_verifier(artifact_path)?));
        // SAFETY: the output was validated above, and the Box is transferred
        // exactly once to the caller.
        unsafe { verifier_output.write(verifier) };
        Ok(())
    })
}

/// Authenticates the pending root of one exact construction parent.
///
/// `pending_root_output` must not alias an input and is cleared before any
/// input is read. Success is still not receipt acceptance: the private C++
/// caller must immediately parse this root against the construction-leaf
/// basis and call the native final decision.
#[no_mangle]
pub(crate) unsafe extern "C" fn purify_construction_parent_authenticate_root(
    verifier: *const PurifyConstructionParentVerifier,
    statement: *const PurifyConstructionParentStatement,
    leaf_descriptors: *const u8,
    leaf_descriptors_length: usize,
    proof: *const u8,
    proof_length: usize,
    pending_root_output: *mut [u8; ROOT_BYTES],
) -> Status {
    if pending_root_output.is_null() {
        return Status::Malformed;
    }
    // SAFETY: the ABI requires one writable root-sized allocation.
    unsafe { pending_root_output.write_bytes(0, 1) };
    contain_panics(|| {
        if statement.is_null() {
            return Err(Status::Malformed);
        }
        // SAFETY: a non-null verifier was returned by the loader and is not
        // destroyed during the call.
        let verifier = unsafe { verifier.as_ref() }.ok_or(Status::Malformed)?;
        // SAFETY: the ABI requires one readable statement. Copying it out
        // needs no alignment and ends the dependence on caller memory.
        let statement = unsafe { statement.read_unaligned() };
        // SAFETY: the ABI requires each buffer to be readable for its length.
        let leaf_descriptors = unsafe { borrow_input(leaf_descriptors, leaf_descriptors_length) }?;
        // SAFETY: as above.
        let proof = unsafe { borrow_input(proof, proof_length) }?;
        let root = authenticate_root(verifier, &statement, leaf_descriptors, proof)?;
        // SAFETY: the output was validated above and does not alias `root`.
        unsafe { pending_root_output.write(root) };
        Ok(())
    })
}

/// Releases a verifier returned by the loader.
#[no_mangle]
pub(crate) unsafe extern "C" fn purify_construction_parent_verifier_destroy(
    verifier: *mut PurifyConstructionParentVerifier,
) {
    if verifier.is_null() {
        return;
    }
    // SAFETY: the loader transfers exactly one Box allocation to its caller,
    // which must invoke this destructor at most once.
    let verifier = unsafe { Box::from_raw(verifier) };
    // Dropping the verifier joins its worker thread.
    let _ = catch_unwind(AssertUnwindSafe(|| drop(verifier)));
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::suite::QUALIFIED_PROOF_LENGTH;
    use statement::inputs::LEAF_DESCRIPTOR_BYTES;
    use statement::profile::{BASIS_DIGEST, RAW_GENERATOR_DIGEST};

    const BRIDGE_HEADER: &str = include_str!("../../../../src/bridge/construction_parent_bridge.h");

    /// Reads `PURIFY_CONSTRUCTION_PARENT_<name> = <value>,` from the header.
    fn header_constant(name: &str) -> usize {
        let needle = format!("PURIFY_CONSTRUCTION_PARENT_{name} = ");
        let mut matches = BRIDGE_HEADER.match_indices(&needle);
        let (start, _) = matches
            .next()
            .unwrap_or_else(|| panic!("bridge header defines {name}"));
        assert!(
            matches.next().is_none(),
            "bridge header defines {name} once"
        );
        let digits: String = BRIDGE_HEADER[start + needle.len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits
            .parse()
            .unwrap_or_else(|_| panic!("bridge header gives {name} a decimal value"))
    }

    fn profile_statement() -> PurifyConstructionParentStatement {
        PurifyConstructionParentStatement {
            construction_statement_digest: [0x11; 32],
            resolved_setup_record_digest: [0x22; 32],
            recovery_root: [0x33; 64],
            native_basis_digest: BASIS_DIGEST,
            native_raw_generator_digest: RAW_GENERATOR_DIGEST,
            setup_leaf_count: 1,
            anchor_leaf_count: 1,
        }
    }

    #[test]
    fn bridge_header_mirrors_every_abi_constant() {
        assert_eq!(header_constant("ROOT_SIZE"), ROOT_BYTES);
        assert_eq!(header_constant("DESCRIPTOR_SIZE"), LEAF_DESCRIPTOR_BYTES);
        assert_eq!(header_constant("PROOF_SIZE"), QUALIFIED_PROOF_LENGTH);
        assert_eq!(header_constant("STATEMENT_SIZE"), STATEMENT_BYTES);
        for (name, status) in [
            ("OK", Status::Ok),
            ("MALFORMED", Status::Malformed),
            ("PROOF_REJECTED", Status::ProofRejected),
            ("ARTIFACT_OPEN_FAILED", Status::ArtifactOpenFailed),
            ("ARTIFACT_REJECTED", Status::ArtifactRejected),
            ("ARTIFACT_SNAPSHOT_FAILED", Status::ArtifactSnapshotFailed),
            ("INTERNAL_ERROR", Status::InternalError),
        ] {
            assert_eq!(header_constant(name), status as usize, "{name}");
        }
        for symbol in [
            "purify_construction_parent_verifier_load(",
            "purify_construction_parent_authenticate_root(",
            "purify_construction_parent_verifier_destroy(",
        ] {
            assert!(BRIDGE_HEADER.contains(symbol), "{symbol}");
        }
    }

    #[test]
    fn a_contained_panic_is_an_internal_error() {
        assert_eq!(contain_panics(|| Ok(())), Status::Ok);
        assert_eq!(
            contain_panics(|| Err(Status::ProofRejected)),
            Status::ProofRejected
        );
        assert_eq!(
            contain_panics(|| panic!("contained by the ABI boundary")),
            Status::InternalError
        );
    }

    #[test]
    fn loader_rejects_malformed_paths_and_clears_output() {
        let sentinel = ptr::dangling_mut::<PurifyConstructionParentVerifier>();
        let mut verifier = sentinel;
        // SAFETY: the output is live and the empty path is intentionally null.
        let empty =
            unsafe { purify_construction_parent_verifier_load(ptr::null(), 0, &mut verifier) };
        assert_eq!(empty, Status::Malformed);
        assert!(verifier.is_null());

        for path in [&[0xff][..], b"embedded\0nul"] {
            verifier = sentinel;
            // SAFETY: the path and output identify live allocations.
            let status = unsafe {
                purify_construction_parent_verifier_load(path.as_ptr(), path.len(), &mut verifier)
            };
            assert_eq!(status, Status::Malformed);
            assert!(verifier.is_null());
        }
    }

    #[test]
    fn loader_reports_a_missing_artifact() {
        let path = std::env::temp_dir().join(format!(
            "purify-missing-construction-parent-{}",
            std::process::id()
        ));
        let path = path.to_string_lossy();
        let mut verifier = ptr::dangling_mut::<PurifyConstructionParentVerifier>();
        // SAFETY: the path and output identify live allocations.
        let status = unsafe {
            purify_construction_parent_verifier_load(
                path.as_bytes().as_ptr(),
                path.len(),
                &mut verifier,
            )
        };
        assert_eq!(status, Status::ArtifactOpenFailed);
        assert!(verifier.is_null());
    }

    #[test]
    fn snapshot_failures_distinguish_identity_from_local_storage() {
        for kind in [
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::InvalidData,
        ] {
            let error = std::io::Error::from(kind);
            assert_eq!(artifact_snapshot_status(&error), Status::ArtifactRejected);
        }

        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::StorageFull,
            std::io::ErrorKind::Other,
        ] {
            let error = std::io::Error::from(kind);
            assert_eq!(
                artifact_snapshot_status(&error),
                Status::ArtifactSnapshotFailed
            );
        }
    }

    #[test]
    fn loader_rejects_an_unauthenticated_artifact() {
        let path = std::env::temp_dir().join(format!(
            "purify-rejected-construction-parent-{}",
            std::process::id()
        ));
        let mut artifact = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create malformed verifier artifact");
        artifact
            .write_all(&[0u8; 64])
            .expect("write malformed verifier artifact");
        drop(artifact);

        let path_bytes = path.to_string_lossy();
        let mut verifier = ptr::dangling_mut::<PurifyConstructionParentVerifier>();
        // SAFETY: the path and output identify live allocations.
        let status = unsafe {
            purify_construction_parent_verifier_load(
                path_bytes.as_bytes().as_ptr(),
                path_bytes.len(),
                &mut verifier,
            )
        };
        assert_eq!(status, Status::ArtifactRejected);
        assert!(verifier.is_null());
        std::fs::remove_file(path).expect("remove malformed verifier artifact");
    }

    #[test]
    fn missing_verifier_or_statement_clears_the_output() {
        let statement = profile_statement();
        for statement in [ptr::null(), &raw const statement] {
            let mut output = [0xa5; ROOT_BYTES];
            // SAFETY: the output is live, the statement is null or live, and
            // the null verifier is rejected before any other input is read.
            let status = unsafe {
                purify_construction_parent_authenticate_root(
                    ptr::null(),
                    statement,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    &mut output,
                )
            };
            assert_eq!(status, Status::Malformed);
            assert_eq!(output, [0; ROOT_BYTES]);
        }
    }

    #[test]
    fn missing_output_is_malformed() {
        let statement = profile_statement();
        // SAFETY: the null output is rejected before any input is read.
        let status = unsafe {
            purify_construction_parent_authenticate_root(
                ptr::null(),
                &statement,
                ptr::null(),
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, Status::Malformed);
    }

    /// Two canonical leaves: a nonzero precommitment and identity points.
    fn canonical_descriptors() -> [u8; 2 * LEAF_DESCRIPTOR_BYTES] {
        let mut descriptors = [0u8; 2 * LEAF_DESCRIPTOR_BYTES];
        let (leaves, _) = descriptors.as_chunks_mut::<LEAF_DESCRIPTOR_BYTES>();
        for leaf in leaves {
            leaf[63] = 3;
        }
        descriptors
    }

    #[test]
    fn every_statement_field_reaches_the_statement_parser() {
        let descriptors = canonical_descriptors();
        let malformed = |statement: &PurifyConstructionParentStatement, descriptors: &[u8]| {
            parse_statement(statement, descriptors).err() == Some(Status::Malformed)
        };

        let statement = profile_statement();
        let inputs = parse_statement(&statement, &descriptors).expect("canonical statement");
        assert_eq!(inputs.step_count(), 2);

        // Each change below is the only difference from that accepted statement.
        let mut wrong_basis = statement;
        wrong_basis.native_basis_digest[0] ^= 1;
        assert!(malformed(&wrong_basis, &descriptors));

        let mut wrong_generators = statement;
        wrong_generators.native_raw_generator_digest[0] ^= 1;
        assert!(malformed(&wrong_generators, &descriptors));

        let mut unresolved_setup = statement;
        unresolved_setup.resolved_setup_record_digest = [0; 32];
        assert!(malformed(&unresolved_setup, &descriptors));

        let mut empty_recovery_root = statement;
        empty_recovery_root.recovery_root = [0; 64];
        assert!(malformed(&empty_recovery_root, &descriptors));

        for (setup, anchor) in [(0, 2), (2, 0), (u32::MAX, 1), (1, 2)] {
            let mut wrong_counts = statement;
            wrong_counts.setup_leaf_count = setup;
            wrong_counts.anchor_leaf_count = anchor;
            assert!(malformed(&wrong_counts, &descriptors));
        }

        assert!(malformed(&statement, &descriptors[1..]));
        assert!(malformed(&statement, &[]));

        let mut zero_precommitment = descriptors;
        zero_precommitment[63] = 0;
        assert!(malformed(&statement, &zero_precommitment));

        // The statement digest and the phase split are bound by the manifest
        // rather than rejected, so they must change the derived inputs.
        let mut other_digest = statement;
        other_digest.construction_statement_digest[0] ^= 1;
        let other = parse_statement(&other_digest, &descriptors).expect("canonical statement");
        assert_ne!(other.initial_state(), inputs.initial_state());
    }
}
