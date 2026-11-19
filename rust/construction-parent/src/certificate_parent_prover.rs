//! Checked production proving for recursive certificate parents.
//!
//! Decoding accepts only canonical CertJWit3. Binding then executes every
//! production constraint against independently supplied public inputs. The
//! proving and verification artifacts remain locally pinned and are added by
//! the purpose-specific one-shot boundary below this checked layer.

use std::{fs::File, io, path::Path};

use thiserror::Error;

use crate::artifact_snapshot::PrivateArtifactSnapshot;
use crate::certificate_joined_witness::CertificateLinearJoinedWitness;
use crate::certificate_parent_input::CertificateParentInputs;
use crate::certificate_parent_prover_binding::BoundCertificateParentWitness;
pub use crate::certificate_parent_prover_binding::CertificateParentWitnessBindingError;
use crate::certificate_parent_verifier::load_qualified_certificate_parent_verifier;
#[cfg(test)]
use crate::certificate_parent_verifier::verify_certificate_parent;
use crate::certificate_profile::{CERTIFICATE_RECURRENCE_STATE_ARITY, CERTIFICATE_ROOT_BYTES};
use crate::nova_certificate_recurrence::CertificateParentStep;
use crate::nova_session::prover_artifact::QUALIFIED_CERTIFICATE_PARENT_PROVER_ARTIFACT;
use crate::nova_session::verifier_artifact::QUALIFIED_CERTIFICATE_PARENT_VERIFIER_ARTIFACT;
use crate::nova_session::{
    DirectNovaSessionError, SelectedDirectNovaVerifier, SelectedNovaProver,
    QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE, QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH,
};
use crate::{RelationError, Scalar};

const CERTIFICATE_PARENT_PUBLIC_FRAME_MAGIC: &[u8; 16] = b"Purify/CertPub1\0";

/// Exact byte length of the qualified certificate-parent recursive proof.
pub const CERTIFICATE_PARENT_PROOF_SIZE: usize = QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH;

/// Failure while decoding the external certificate-parent public frame.
#[derive(Debug, Error)]
#[error("invalid certificate parent public frame: {detail}")]
pub struct CertificateParentPublicFrameDecodeError {
    detail: String,
}

/// Independently resolved public inputs for one certificate-parent proof.
///
/// This fixed frame must be derived from the complete ordered admitted
/// certificate records. It is deliberately separate from CertJWit3 so the
/// private witness cannot select its own certificate context, counts, or
/// final manifest.
pub struct CertificateParentPublicFrame {
    inputs: CertificateParentInputs,
}

impl CertificateParentPublicFrame {
    pub const SERIALIZED_SIZE: usize = 96;

    /// Decode the exact fixed-width, big-endian public frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, CertificateParentPublicFrameDecodeError> {
        if bytes.len() != Self::SERIALIZED_SIZE {
            return Err(CertificateParentPublicFrameDecodeError {
                detail: format!(
                    "expected {} bytes, received {}",
                    Self::SERIALIZED_SIZE,
                    bytes.len(),
                ),
            });
        }
        if &bytes[..CERTIFICATE_PARENT_PUBLIC_FRAME_MAGIC.len()]
            != CERTIFICATE_PARENT_PUBLIC_FRAME_MAGIC
        {
            return Err(CertificateParentPublicFrameDecodeError {
                detail: "wrong magic or version".to_owned(),
            });
        }

        let context = bytes[16..48]
            .try_into()
            .expect("fixed certificate public context width");
        let total_responses = u64::from_be_bytes(
            bytes[48..56]
                .try_into()
                .expect("fixed certificate response count width"),
        );
        let total_steps = u64::from_be_bytes(
            bytes[56..64]
                .try_into()
                .expect("fixed certificate step count width"),
        );
        let final_manifest = bytes[64..96]
            .try_into()
            .expect("fixed certificate final manifest width");
        let inputs = CertificateParentInputs::new(
            context,
            total_responses,
            u128::from(total_steps),
            final_manifest,
        )
        .map_err(|error| CertificateParentPublicFrameDecodeError {
            detail: error.to_string(),
        })?;
        Ok(Self { inputs })
    }
}

/// Failure while decoding canonical linear certificate prover input.
#[derive(Debug, Error)]
#[error("invalid certificate parent CertJWit3 witness: {detail}")]
pub struct CertificateParentWitnessDecodeError {
    detail: String,
}

/// Canonically decoded CertJWit3 data before relation execution.
pub struct CertificateParentWitness {
    witness: CertificateLinearJoinedWitness,
    step_count: usize,
}

impl CertificateParentWitness {
    /// Decode one exact linear certificate witness without trusting it.
    pub fn decode(bytes: &[u8]) -> Result<Self, CertificateParentWitnessDecodeError> {
        let witness = CertificateLinearJoinedWitness::parse(bytes).map_err(|error| {
            CertificateParentWitnessDecodeError {
                detail: error.to_string(),
            }
        })?;
        let step_count = witness
            .responses()
            .iter()
            .try_fold(0usize, |total, response| {
                total.checked_add(response.member_proofs().len())
            })
            .ok_or_else(|| CertificateParentWitnessDecodeError {
                detail: "certificate parent step count overflow".to_owned(),
            })?;
        Ok(Self {
            witness,
            step_count,
        })
    }

    /// Return the number of ordered member recurrences in this witness.
    pub const fn step_count(&self) -> usize {
        self.step_count
    }

    /// Execute every production constraint under an external public frame.
    pub fn bind(
        self,
        frame: CertificateParentPublicFrame,
    ) -> Result<CheckedCertificateParentWitness, CertificateParentWitnessBindingError> {
        Ok(CheckedCertificateParentWitness {
            inner: self.witness.bind(frame.inputs)?,
        })
    }
}

/// Exact certificate prover input after complete production validation.
pub struct CheckedCertificateParentWitness {
    inner: BoundCertificateParentWitness,
}

impl CheckedCertificateParentWitness {
    pub fn step_count(&self) -> usize {
        self.inner.steps().len()
    }

    /// Prove this exact state chain with the locally selected prover.
    pub(crate) fn prove_with(
        self,
        prover: SelectedCertificateParentProver,
    ) -> Result<UnverifiedCertificateParentProof, CertificateParentProvingError> {
        if prover.expected() != &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE {
            return Err(CertificateParentProvingError::Suite);
        }

        let (initial_state, final_state, steps, pending_root, public_inputs) =
            self.inner.into_prover_parts();
        let step_count = steps.len();
        let mut session = prover.start(initial_state, step_count)?;
        for step in steps {
            session = session.add_step(step)?;
        }
        let proof = session.finish()?;
        require_frozen_proof_length(&proof)?;
        drop(prover);

        Ok(UnverifiedCertificateParentProof {
            initial_state,
            final_state,
            step_count,
            pending_root,
            public_inputs,
            proof,
        })
    }
}

type SelectedCertificateParentProver =
    SelectedNovaProver<CERTIFICATE_RECURRENCE_STATE_ARITY, CertificateParentStep>;

/// Failure while proving or independently rechecking one checked witness.
#[derive(Debug, Error)]
pub(crate) enum CertificateParentProvingError {
    #[error("certificate parent selected an unexpected Nova suite")]
    Suite,
    #[error(transparent)]
    Nova(#[from] DirectNovaSessionError),
    #[error("certificate parent proof length mismatch: expected {expected}, actual {actual}")]
    ProofLength { expected: usize, actual: usize },
    #[error("certificate parent verified final state mismatch")]
    FinalState,
    #[error("certificate parent verified final frame is invalid: {0}")]
    FinalFrame(#[source] RelationError),
    #[error("certificate parent verified pending root mismatch")]
    PendingRoot,
}

/// Compressed proof state pending independent VK2 verification.
pub(crate) struct UnverifiedCertificateParentProof {
    initial_state: [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
    final_state: [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
    step_count: usize,
    pending_root: [u8; CERTIFICATE_ROOT_BYTES],
    public_inputs: CertificateParentInputs,
    proof: Vec<u8>,
}

impl UnverifiedCertificateParentProof {
    /// Recheck the exact state and public frame with a separate verifier.
    pub(crate) fn verify_with(
        self,
        verifier: SelectedDirectNovaVerifier<CERTIFICATE_RECURRENCE_STATE_ARITY>,
    ) -> Result<VerifiedCertificateParentProof, CertificateParentProvingError> {
        if verifier.expected() != &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE {
            return Err(CertificateParentProvingError::Suite);
        }
        let authenticated =
            verifier.verify_final(&self.initial_state, self.step_count, &self.proof)?;
        require_exact_final_state(&self.final_state, &authenticated)?;
        let pending = self
            .public_inputs
            .validate_authenticated_final_state(authenticated)
            .map_err(CertificateParentProvingError::FinalFrame)?;
        require_exact_pending_root(&self.pending_root, pending.canonical_root_bytes())?;
        drop(verifier);
        Ok(VerifiedCertificateParentProof { proof: self.proof })
    }
}

/// Exact proof bytes after independent recursive re-verification.
pub(crate) struct VerifiedCertificateParentProof {
    proof: Vec<u8>,
}

impl VerifiedCertificateParentProof {
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.proof
    }
}

/// Failure in the purpose-specific qualified certificate-parent prover.
#[derive(Debug, Error)]
pub enum QualifiedCertificateParentProvingError {
    #[error("cannot open the qualified certificate-parent prover artifact: {source}")]
    OpenProverArtifact {
        #[source]
        source: io::Error,
    },
    #[error("cannot snapshot the qualified certificate-parent prover artifact: {source}")]
    SnapshotProverArtifact {
        #[source]
        source: io::Error,
    },
    #[error("the qualified certificate-parent prover artifact was rejected: {detail}")]
    LoadProverArtifact { detail: String },
    #[error("qualified certificate-parent proving failed: {detail}")]
    Prove { detail: String },
    #[error("cannot open the qualified certificate-parent verifier artifact: {source}")]
    OpenVerifierArtifact {
        #[source]
        source: io::Error,
    },
    #[error("cannot snapshot the qualified certificate-parent verifier artifact: {source}")]
    SnapshotVerifierArtifact {
        #[source]
        source: io::Error,
    },
    #[error("the qualified certificate-parent verifier artifact was rejected: {detail}")]
    LoadVerifierArtifact { detail: String },
    #[error("qualified certificate-parent proof re-verification failed: {detail}")]
    Reverify { detail: String },
}

/// Produce and independently reverify one qualified certificate proof.
///
/// The checked witness has already executed every production constraint
/// against its independently supplied [`CertificateParentPublicFrame`]. PK1 is
/// copied into an unlinked exact-length snapshot and authenticated against
/// the compiled identity before proving. Its complete decoded state is
/// consumed and dropped before VK2 is opened and receives the same snapshot
/// treatment. Re-verification checks the exact final state, public frame, and
/// pending root. The returned bytes remain pending native BP++ `decide()`.
pub fn prove_qualified_certificate_parent(
    witness: CheckedCertificateParentWitness,
    prover_artifact_path: &Path,
    verifier_artifact_path: &Path,
) -> Result<Vec<u8>, QualifiedCertificateParentProvingError> {
    let mut prover_source = File::open(prover_artifact_path)
        .map_err(|source| QualifiedCertificateParentProvingError::OpenProverArtifact { source })?;
    let mut prover_artifact = PrivateArtifactSnapshot::copy_from(
        &mut prover_source,
        QUALIFIED_CERTIFICATE_PARENT_PROVER_ARTIFACT.encoded_length(),
    )
    .map_err(|source| QualifiedCertificateParentProvingError::SnapshotProverArtifact { source })?;
    drop(prover_source);
    let prover = SelectedCertificateParentProver::from_artifact_reader(
        prover_artifact.reader(),
        &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE,
        &QUALIFIED_CERTIFICATE_PARENT_PROVER_ARTIFACT,
    )
    .map_err(
        |error| QualifiedCertificateParentProvingError::LoadProverArtifact {
            detail: error.to_string(),
        },
    )?;
    drop(prover_artifact);

    let unverified = witness.prove_with(prover).map_err(|error| {
        QualifiedCertificateParentProvingError::Prove {
            detail: error.to_string(),
        }
    })?;

    // Proving consumed and dropped PK1 before this separately selected VK2
    // path can allocate or authenticate verifier state.
    let mut verifier_source = File::open(verifier_artifact_path).map_err(|source| {
        QualifiedCertificateParentProvingError::OpenVerifierArtifact { source }
    })?;
    let mut verifier_artifact = PrivateArtifactSnapshot::copy_from(
        &mut verifier_source,
        QUALIFIED_CERTIFICATE_PARENT_VERIFIER_ARTIFACT.encoded_length(),
    )
    .map_err(
        |source| QualifiedCertificateParentProvingError::SnapshotVerifierArtifact { source },
    )?;
    drop(verifier_source);
    let verifier = load_qualified_certificate_parent_verifier(verifier_artifact.reader()).map_err(
        |error| QualifiedCertificateParentProvingError::LoadVerifierArtifact {
            detail: error.to_string(),
        },
    )?;
    drop(verifier_artifact);

    unverified
        .verify_with(verifier)
        .map(VerifiedCertificateParentProof::into_bytes)
        .map_err(|error| QualifiedCertificateParentProvingError::Reverify {
            detail: error.to_string(),
        })
}

fn require_frozen_proof_length(proof: &[u8]) -> Result<(), CertificateParentProvingError> {
    if proof.len() != QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH {
        return Err(CertificateParentProvingError::ProofLength {
            expected: QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH,
            actual: proof.len(),
        });
    }
    Ok(())
}

fn require_exact_final_state(
    expected: &[Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
    authenticated: &[Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
) -> Result<(), CertificateParentProvingError> {
    if authenticated != expected {
        return Err(CertificateParentProvingError::FinalState);
    }
    Ok(())
}

fn require_exact_pending_root(
    expected: &[u8; CERTIFICATE_ROOT_BYTES],
    authenticated: &[u8; CERTIFICATE_ROOT_BYTES],
) -> Result<(), CertificateParentProvingError> {
    if authenticated != expected {
        return Err(CertificateParentProvingError::PendingRoot);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{io::Write, path::PathBuf};

    use sha2::{Digest, Sha256};

    use super::*;

    const WITNESS: &[u8] = include_bytes!("../tests/vectors/certificate_joined_witness_v3.bin");
    const CONTEXT: [u8; 32] = [
        0x7b, 0xcb, 0x06, 0xb8, 0x53, 0x8c, 0xcc, 0x9c, 0x79, 0xfd, 0x2f, 0x59, 0x5b, 0xbb, 0xee,
        0x9f, 0x08, 0xc0, 0xd8, 0x29, 0xa9, 0x7c, 0xcd, 0x92, 0xfc, 0x31, 0x75, 0xeb, 0x37, 0x90,
        0x39, 0xf5,
    ];
    const FINAL_MANIFEST: [u8; 32] = [
        0x45, 0xe8, 0x14, 0x7f, 0x29, 0x3a, 0x6e, 0xdc, 0xf5, 0x0c, 0x17, 0x8d, 0x94, 0xa4, 0x73,
        0x1b, 0x5e, 0x18, 0x78, 0x4c, 0x7b, 0x40, 0x4b, 0xa9, 0xc3, 0x57, 0xb9, 0xdb, 0x22, 0x4c,
        0x1f, 0x9c,
    ];

    fn public_frame_bytes(
        context: [u8; 32],
        total_responses: u64,
        total_steps: u64,
        final_manifest: [u8; 32],
    ) -> [u8; CertificateParentPublicFrame::SERIALIZED_SIZE] {
        let mut encoded = [0u8; CertificateParentPublicFrame::SERIALIZED_SIZE];
        encoded[..16].copy_from_slice(CERTIFICATE_PARENT_PUBLIC_FRAME_MAGIC);
        encoded[16..48].copy_from_slice(&context);
        encoded[48..56].copy_from_slice(&total_responses.to_be_bytes());
        encoded[56..64].copy_from_slice(&total_steps.to_be_bytes());
        encoded[64..96].copy_from_slice(&final_manifest);
        encoded
    }

    fn pinned_public_frame() -> CertificateParentPublicFrame {
        let encoded = public_frame_bytes(CONTEXT, 2, 4, FINAL_MANIFEST);
        assert_eq!(
            hex(&Sha256::digest(encoded)),
            "9057d923d70e4b600eb9e7f085a32f4a1eb245e6188dde6a0b8147a0ad816196",
        );
        CertificateParentPublicFrame::decode(&encoded).expect("pinned certificate public frame")
    }

    fn required_new_output(environment: &str) -> PathBuf {
        let path = PathBuf::from(
            std::env::var_os(environment)
                .unwrap_or_else(|| panic!("set {environment} before qualification")),
        );
        assert!(!path.as_os_str().is_empty(), "{environment} is empty");
        assert!(!path.exists(), "{environment} already exists");
        path
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn decoder_rejects_truncated_certjwit3() {
        let error = CertificateParentWitness::decode(&[])
            .err()
            .expect("empty witness rejects");
        assert!(error
            .to_string()
            .contains("invalid certificate parent CertJWit3 witness"));
    }

    #[test]
    fn decoder_accepts_the_pinned_certjwit3_without_binding() {
        let witness = CertificateParentWitness::decode(WITNESS).expect("decode CertJWit3");
        assert_eq!(witness.step_count(), 4);
    }

    #[test]
    fn public_frame_decodes_fixed_big_endian_counts() {
        let frame = pinned_public_frame();
        assert_eq!(frame.inputs.step_count(), 4);
        let expected = CertificateParentInputs::new(CONTEXT, 2, 4, FINAL_MANIFEST)
            .expect("expected certificate public inputs");
        assert_eq!(frame.inputs.initial_state(), expected.initial_state());
    }

    #[test]
    fn public_frame_rejects_noncanonical_width_and_magic() {
        let encoded = public_frame_bytes(CONTEXT, 2, 4, FINAL_MANIFEST);
        assert!(CertificateParentPublicFrame::decode(&encoded[..encoded.len() - 1]).is_err());

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(CertificateParentPublicFrame::decode(&trailing).is_err());

        let mut wrong_magic = encoded;
        wrong_magic[0] ^= 1;
        assert!(CertificateParentPublicFrame::decode(&wrong_magic).is_err());
    }

    #[test]
    fn public_frame_rejects_invalid_response_and_step_counts() {
        assert!(CertificateParentPublicFrame::decode(&public_frame_bytes(
            CONTEXT,
            0,
            0,
            FINAL_MANIFEST
        ))
        .is_err());
        assert!(CertificateParentPublicFrame::decode(&public_frame_bytes(
            CONTEXT,
            2,
            1,
            FINAL_MANIFEST
        ))
        .is_err());
        assert!(CertificateParentPublicFrame::decode(&public_frame_bytes(
            CONTEXT,
            2,
            257,
            FINAL_MANIFEST
        ))
        .is_err());
    }

    #[test]
    fn public_frame_rejects_noncanonical_manifest() {
        let mut high_manifest = FINAL_MANIFEST;
        high_manifest[0] |= 0x80;
        assert!(CertificateParentPublicFrame::decode(&public_frame_bytes(
            CONTEXT,
            2,
            4,
            high_manifest
        ))
        .is_err());
    }

    #[test]
    fn one_shot_boundary_requires_the_frozen_proof_length() {
        let short = vec![0; QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH - 1];
        assert!(matches!(
            require_frozen_proof_length(&short),
            Err(CertificateParentProvingError::ProofLength {
                expected: QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH,
                actual
            }) if actual == short.len()
        ));
        let exact = vec![0; QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH];
        require_frozen_proof_length(&exact).expect("frozen certificate proof length");
    }

    #[test]
    fn one_shot_boundary_requires_exact_final_state_and_root() {
        let expected = [Scalar::from(7u64); CERTIFICATE_RECURRENCE_STATE_ARITY];
        require_exact_final_state(&expected, &expected).expect("exact final state");
        let mut changed = expected;
        changed[CERTIFICATE_RECURRENCE_STATE_ARITY - 1] = Scalar::from(8u64);
        assert!(matches!(
            require_exact_final_state(&expected, &changed),
            Err(CertificateParentProvingError::FinalState)
        ));

        let expected_root = [0x11; CERTIFICATE_ROOT_BYTES];
        require_exact_pending_root(&expected_root, &expected_root).expect("exact pending root");
        let changed_root = [0x12; CERTIFICATE_ROOT_BYTES];
        assert!(matches!(
            require_exact_pending_root(&changed_root, &expected_root),
            Err(CertificateParentProvingError::PendingRoot)
        ));
    }

    #[test]
    #[ignore = "binds, proves, and reverifies four production certificate steps"]
    fn qualified_artifacts_produce_the_pinned_certificate_proof() {
        let started = std::time::Instant::now();
        let proof_output = required_new_output("PURIFY_CERTIFICATE_PARENT_PROOF_OUT");
        let prover_artifact = PathBuf::from(
            std::env::var_os("PURIFY_CERTIFICATE_PARENT_PROVER_ARTIFACT")
                .expect("set PURIFY_CERTIFICATE_PARENT_PROVER_ARTIFACT"),
        );
        let verifier_artifact = PathBuf::from(
            std::env::var_os("PURIFY_CERTIFICATE_PARENT_VERIFIER_ARTIFACT")
                .expect("set PURIFY_CERTIFICATE_PARENT_VERIFIER_ARTIFACT"),
        );
        let mut proof_output_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&proof_output)
            .expect("claim new certificate proof output");
        let binding_started = std::time::Instant::now();
        let checked = CertificateParentWitness::decode(WITNESS)
            .expect("decode pinned CertJWit3")
            .bind(pinned_public_frame())
            .expect("bind pinned CertJWit3");
        assert_eq!(checked.step_count(), 4);
        eprintln!(
            "certificate_parent_prover: binding_seconds={:.3}",
            binding_started.elapsed().as_secs_f64(),
        );

        let proving_started = std::time::Instant::now();
        let proof =
            prove_qualified_certificate_parent(checked, &prover_artifact, &verifier_artifact)
                .expect("prove and reverify pinned certificate parent");
        assert_eq!(proof.len(), QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH);

        proof_output_file
            .write_all(&proof)
            .expect("write complete certificate proof");
        proof_output_file
            .sync_all()
            .expect("sync certificate proof output");
        drop(proof_output_file);
        let persisted = std::fs::read(&proof_output).expect("reload certificate proof output");
        assert_eq!(persisted, proof);
        let proof_sha256: [u8; 32] = Sha256::digest(&persisted).into();

        let mut verifier_source =
            File::open(&verifier_artifact).expect("open certificate verifier artifact read-only");
        let mut verifier_snapshot = PrivateArtifactSnapshot::copy_from(
            &mut verifier_source,
            QUALIFIED_CERTIFICATE_PARENT_VERIFIER_ARTIFACT.encoded_length(),
        )
        .expect("snapshot certificate verifier artifact");
        drop(verifier_source);
        let verifier = load_qualified_certificate_parent_verifier(verifier_snapshot.reader())
            .expect("reload qualified certificate verifier");
        drop(verifier_snapshot);
        let persisted_inputs = CertificateParentInputs::new(CONTEXT, 2, 4, FINAL_MANIFEST)
            .expect("persisted certificate public inputs");
        let pending = verify_certificate_parent(&verifier, &persisted_inputs, &persisted)
            .expect("reloaded proof verifies");
        assert_ne!(pending.canonical_root_bytes(), &[0; CERTIFICATE_ROOT_BYTES]);
        drop(verifier);
        eprintln!(
            "certificate_parent_prover: prove_reverify_seconds={:.3}\n\
             proof_output={}\nproof_bytes={}\nproof_sha256={}\n\
             total_seconds={:.3}",
            proving_started.elapsed().as_secs_f64(),
            proof_output.display(),
            proof.len(),
            hex(&proof_sha256),
            started.elapsed().as_secs_f64(),
        );
    }
}
