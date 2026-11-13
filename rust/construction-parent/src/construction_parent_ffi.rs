//! Private C ABI for the selected construction-parent verifier.
//!
//! This boundary can return only a proof-authenticated pending root. It is
//! deliberately not installed as a public C API: the C++ construction
//! verifier must parse the returned root against the fixed native basis and
//! complete `decide()` before exposing receipt acceptance.

use core::ptr;
use std::slice;

use crate::construction_parent_input::{
    ConstructionParentInputs, CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES,
};
use crate::construction_parent_verifier::{
    load_qualified_construction_parent_verifier, require_qualified_construction_parent_profile,
    verify_construction_parent, ConstructionParentVerifierError,
};
use crate::construction_profile::{CONSTRUCTION_RECURRENCE_STATE_ARITY, CONSTRUCTION_ROOT_BYTES};
use crate::nova_session::{
    SelectedDirectNovaVerifier, PROVISIONAL_CONSTRUCTION_PARENT_PROOF_LENGTH,
};

/// Stable values mirrored by the private construction-parent bridge header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PurifyConstructionParentStatus {
    Ok = 0,
    Malformed = 1,
    ProofRejected = 2,
    BufferTooSmall = 3,
    ArtifactOpenFailed = 4,
    ArtifactRejected = 5,
    InternalError = 6,
}

/// Opaque owner of the locally configured construction verifier.
#[repr(C)]
pub(crate) struct PurifyConstructionParentVerifier {
    verifier: SelectedDirectNovaVerifier<CONSTRUCTION_RECURRENCE_STATE_ARITY>,
}

struct RootOutput {
    data: *mut u8,
}

impl RootOutput {
    unsafe fn initialize(
        data: *mut u8,
        capacity: usize,
    ) -> Result<Self, PurifyConstructionParentStatus> {
        if data.is_null() {
            return Err(PurifyConstructionParentStatus::Malformed);
        }
        if capacity < CONSTRUCTION_ROOT_BYTES {
            // SAFETY: the ABI requires `data` to identify `capacity` writable
            // bytes. Clearing only that declared allocation cannot overflow it.
            unsafe { ptr::write_bytes(data, 0, capacity) };
            return Err(PurifyConstructionParentStatus::BufferTooSmall);
        }
        // SAFETY: the ABI requires a writable allocation of at least the
        // canonical root size. Output must not alias an input allocation.
        unsafe { ptr::write_bytes(data, 0, CONSTRUCTION_ROOT_BYTES) };
        Ok(Self { data })
    }

    unsafe fn write(self, root: &[u8; CONSTRUCTION_ROOT_BYTES]) {
        // SAFETY: initialization established the fixed writable capacity and
        // the source is a distinct Rust-owned canonical root.
        unsafe { ptr::copy_nonoverlapping(root.as_ptr(), self.data, root.len()) };
    }
}

unsafe fn borrow_input<'a>(
    data: *const u8,
    length: usize,
) -> Result<&'a [u8], PurifyConstructionParentStatus> {
    if length == 0 {
        return Ok(&[]);
    }
    if data.is_null() {
        return Err(PurifyConstructionParentStatus::Malformed);
    }
    // SAFETY: the private ABI requires every nonempty input to identify a
    // readable allocation of exactly `length` bytes for the complete call.
    Ok(unsafe { slice::from_raw_parts(data, length) })
}

unsafe fn read_array<const N: usize>(
    data: *const u8,
) -> Result<[u8; N], PurifyConstructionParentStatus> {
    if data.is_null() {
        return Err(PurifyConstructionParentStatus::Malformed);
    }
    let mut output = [0u8; N];
    // SAFETY: the private ABI requires `data` to identify N readable bytes.
    // The stack output is a distinct allocation of exactly N bytes.
    unsafe { ptr::copy_nonoverlapping(data, output.as_mut_ptr(), N) };
    Ok(output)
}

fn verifier_status(error: ConstructionParentVerifierError) -> PurifyConstructionParentStatus {
    match error {
        ConstructionParentVerifierError::Suite => PurifyConstructionParentStatus::InternalError,
        ConstructionParentVerifierError::State(_)
        | ConstructionParentVerifierError::Nova(_)
        | ConstructionParentVerifierError::FinalManifest
        | ConstructionParentVerifierError::FinalIndex => {
            PurifyConstructionParentStatus::ProofRejected
        }
    }
}

/// Opens and authenticates the configured verifier artifact.
///
/// `artifact_path` is an explicit UTF-8 path. The output is set to null before
/// any validation or I/O. The path selects only a storage location; artifact
/// identity is compiled into the Rust verifier. The mixed profile currently
/// fails closed until its complete artifact set is requalified.
#[no_mangle]
pub(crate) unsafe extern "C" fn purify_construction_parent_verifier_load(
    artifact_path: *const u8,
    artifact_path_length: usize,
    verifier_output: *mut *mut PurifyConstructionParentVerifier,
) -> PurifyConstructionParentStatus {
    if verifier_output.is_null() {
        return PurifyConstructionParentStatus::Malformed;
    }
    // SAFETY: the ABI requires one writable verifier pointer.
    unsafe { verifier_output.write(ptr::null_mut()) };
    let artifact_path = match unsafe { borrow_input(artifact_path, artifact_path_length) } {
        Ok([]) => return PurifyConstructionParentStatus::Malformed,
        Ok(value) => value,
        Err(error) => return error,
    };
    if artifact_path.contains(&0) {
        return PurifyConstructionParentStatus::Malformed;
    }
    let artifact_path = match std::str::from_utf8(artifact_path) {
        Ok(value) => value,
        Err(_) => return PurifyConstructionParentStatus::Malformed,
    };
    if require_qualified_construction_parent_profile().is_err() {
        return PurifyConstructionParentStatus::ArtifactRejected;
    }
    let mut artifact = match std::fs::File::open(artifact_path) {
        Ok(value) => value,
        Err(_) => return PurifyConstructionParentStatus::ArtifactOpenFailed,
    };
    let verifier = match load_qualified_construction_parent_verifier(&mut artifact) {
        Ok(value) => value,
        Err(_) => return PurifyConstructionParentStatus::ArtifactRejected,
    };
    let verifier = Box::into_raw(Box::new(PurifyConstructionParentVerifier { verifier }));
    // SAFETY: output validation established one writable pointer, and the Box
    // is transferred exactly once to the caller.
    unsafe { verifier_output.write(verifier) };
    PurifyConstructionParentStatus::Ok
}

#[allow(clippy::too_many_arguments)]
unsafe fn verify_inner(
    verifier: &PurifyConstructionParentVerifier,
    construction_statement_digest: *const u8,
    resolved_setup_record_digest: *const u8,
    recovery_root: *const u8,
    native_basis_digest: *const u8,
    native_raw_generator_digest: *const u8,
    setup_leaf_count: u32,
    anchor_leaf_count: u32,
    leaf_descriptors: *const u8,
    leaf_descriptors_length: usize,
    proof: *const u8,
    proof_length: usize,
    output: RootOutput,
) -> PurifyConstructionParentStatus {
    if setup_leaf_count == 0 || anchor_leaf_count == 0 {
        return PurifyConstructionParentStatus::Malformed;
    }
    let leaf_count = match setup_leaf_count.checked_add(anchor_leaf_count) {
        Some(value) => value,
        None => return PurifyConstructionParentStatus::Malformed,
    };
    let leaf_count_usize = match usize::try_from(leaf_count) {
        Ok(value) => value,
        Err(_) => return PurifyConstructionParentStatus::Malformed,
    };
    let expected_descriptors =
        match leaf_count_usize.checked_mul(CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES) {
            Some(value) => value,
            None => return PurifyConstructionParentStatus::Malformed,
        };
    if leaf_descriptors_length != expected_descriptors
        || proof_length != PROVISIONAL_CONSTRUCTION_PARENT_PROOF_LENGTH
    {
        return PurifyConstructionParentStatus::Malformed;
    }

    let construction_statement_digest =
        match unsafe { read_array::<32>(construction_statement_digest) } {
            Ok(value) => value,
            Err(error) => return error,
        };
    let resolved_setup_record_digest =
        match unsafe { read_array::<32>(resolved_setup_record_digest) } {
            Ok(value) => value,
            Err(error) => return error,
        };
    let recovery_root = match unsafe { read_array::<64>(recovery_root) } {
        Ok(value) => value,
        Err(error) => return error,
    };
    let native_basis_digest = match unsafe { read_array::<32>(native_basis_digest) } {
        Ok(value) => value,
        Err(error) => return error,
    };
    let native_raw_generator_digest = match unsafe { read_array::<32>(native_raw_generator_digest) }
    {
        Ok(value) => value,
        Err(error) => return error,
    };
    let leaf_descriptors = match unsafe { borrow_input(leaf_descriptors, leaf_descriptors_length) }
    {
        Ok(value) => value,
        Err(error) => return error,
    };
    let proof = match unsafe { borrow_input(proof, proof_length) } {
        Ok(value) => value,
        Err(error) => return error,
    };

    let inputs = match ConstructionParentInputs::parse(
        construction_statement_digest,
        resolved_setup_record_digest,
        recovery_root,
        native_basis_digest,
        native_raw_generator_digest,
        setup_leaf_count,
        anchor_leaf_count,
        leaf_descriptors,
    ) {
        Ok(value) => value,
        Err(_) => return PurifyConstructionParentStatus::Malformed,
    };
    let authenticated = match verify_construction_parent(&verifier.verifier, &inputs, proof) {
        Ok(value) => value,
        Err(error) => return verifier_status(error),
    };
    unsafe { output.write(authenticated.canonical_root_bytes()) };
    PurifyConstructionParentStatus::Ok
}

/// Verifies one exact construction parent and returns its pending root.
///
/// The output is cleared before any input or proof check. It must not alias
/// any input. Success is still not receipt acceptance: the private C++ caller
/// must immediately parse this root against the construction-leaf basis and call the
/// native final decision.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe extern "C" fn purify_construction_parent_verify(
    verifier: *const PurifyConstructionParentVerifier,
    construction_statement_digest: *const u8,
    resolved_setup_record_digest: *const u8,
    recovery_root: *const u8,
    native_basis_digest: *const u8,
    native_raw_generator_digest: *const u8,
    setup_leaf_count: u32,
    anchor_leaf_count: u32,
    leaf_descriptors: *const u8,
    leaf_descriptors_length: usize,
    proof: *const u8,
    proof_length: usize,
    pending_root_output: *mut u8,
    pending_root_capacity: usize,
) -> PurifyConstructionParentStatus {
    let output = match unsafe { RootOutput::initialize(pending_root_output, pending_root_capacity) }
    {
        Ok(value) => value,
        Err(error) => return error,
    };
    let verifier = match unsafe { verifier.as_ref() } {
        Some(value) => value,
        None => return PurifyConstructionParentStatus::Malformed,
    };
    unsafe {
        verify_inner(
            verifier,
            construction_statement_digest,
            resolved_setup_record_digest,
            recovery_root,
            native_basis_digest,
            native_raw_generator_digest,
            setup_leaf_count,
            anchor_leaf_count,
            leaf_descriptors,
            leaf_descriptors_length,
            proof,
            proof_length,
            output,
        )
    }
}

/// Releases a verifier returned by the configured-artifact loader.
#[no_mangle]
pub(crate) unsafe extern "C" fn purify_construction_parent_verifier_destroy(
    verifier: *mut PurifyConstructionParentVerifier,
) {
    if verifier.is_null() {
        return;
    }
    // SAFETY: the loader transfers exactly one Box allocation to its caller,
    // which must invoke this destructor at most once.
    drop(unsafe { Box::from_raw(verifier) });
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn loader_rejects_malformed_paths_and_clears_output() {
        let sentinel = ptr::dangling_mut::<PurifyConstructionParentVerifier>();
        let mut verifier = sentinel;
        // SAFETY: the output is live and the empty path is intentionally null.
        let empty =
            unsafe { purify_construction_parent_verifier_load(ptr::null(), 0, &mut verifier) };
        assert_eq!(empty, PurifyConstructionParentStatus::Malformed);
        assert!(verifier.is_null());

        let invalid_utf8 = [0xff];
        verifier = sentinel;
        // SAFETY: the path and output identify live allocations.
        let invalid = unsafe {
            purify_construction_parent_verifier_load(
                invalid_utf8.as_ptr(),
                invalid_utf8.len(),
                &mut verifier,
            )
        };
        assert_eq!(invalid, PurifyConstructionParentStatus::Malformed);
        assert!(verifier.is_null());
    }

    #[test]
    fn pending_loader_rejects_before_opening_a_missing_artifact() {
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
        assert_eq!(status, PurifyConstructionParentStatus::ArtifactRejected);
        assert!(verifier.is_null());
    }

    #[test]
    fn pending_loader_rejects_existing_storage_without_an_owner() {
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
        assert_eq!(status, PurifyConstructionParentStatus::ArtifactRejected);
        assert!(verifier.is_null());
        std::fs::remove_file(path).expect("remove malformed verifier artifact");
    }

    #[test]
    fn null_verifier_clears_complete_output() {
        let mut output = [0xa5; CONSTRUCTION_ROOT_BYTES];
        // SAFETY: every pointer is either intentionally null or identifies a
        // live output allocation of the declared size.
        let status = unsafe {
            purify_construction_parent_verify(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_eq!(status, PurifyConstructionParentStatus::Malformed);
        assert_eq!(output, [0; CONSTRUCTION_ROOT_BYTES]);
    }

    #[test]
    fn short_output_clears_only_declared_capacity() {
        let mut output = [0xa5; CONSTRUCTION_ROOT_BYTES];
        let declared = CONSTRUCTION_ROOT_BYTES - 1;
        // SAFETY: the output allocation is larger than the deliberately short
        // declared capacity and no input pointer is dereferenced.
        let status = unsafe {
            purify_construction_parent_verify(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                0,
                ptr::null(),
                0,
                ptr::null(),
                0,
                output.as_mut_ptr(),
                declared,
            )
        };
        assert_eq!(status, PurifyConstructionParentStatus::BufferTooSmall);
        assert_eq!(&output[..declared], vec![0; declared]);
        assert_eq!(output[declared], 0xa5);
    }
}
