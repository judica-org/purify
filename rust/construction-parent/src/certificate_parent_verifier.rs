//! Exact recursive verifier for one certificate-parent receipt.
//!
//! Successful Nova verification authenticates only the pending accumulation
//! root. The native caller must parse that root against the fixed certificate
//! basis and complete `decide()` before treating the certificate as accepted.

use std::io::{Read, Seek};

use thiserror::Error;

use crate::certificate_parent_input::{CertificateParentInputs, CertificateParentPendingRoot};
use crate::certificate_profile::CERTIFICATE_RECURRENCE_STATE_ARITY;
use crate::nova_session::verifier_artifact::{
    DirectNovaVerifierArtifactError, QUALIFIED_CERTIFICATE_PARENT_VERIFIER_ARTIFACT,
};
use crate::nova_session::{
    DirectNovaSessionError, SelectedDirectNovaVerifier, QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE,
    QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH,
};
use crate::RelationError;

/// Loads the sole certificate verifier from one seekable artifact snapshot.
///
/// Authentication of the complete encoding precedes all Serde work. Neither
/// an artifact nor a proof can select its suite, relation, or proof shape.
pub(crate) fn load_qualified_certificate_parent_verifier<R>(
    artifact: &mut R,
) -> Result<
    SelectedDirectNovaVerifier<CERTIFICATE_RECURRENCE_STATE_ARITY>,
    DirectNovaVerifierArtifactError,
>
where
    R: Read + Seek,
{
    SelectedDirectNovaVerifier::from_artifact_reader(
        artifact,
        &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE,
        &QUALIFIED_CERTIFICATE_PARENT_VERIFIER_ARTIFACT,
    )
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum CertificateParentVerifierError {
    #[error(transparent)]
    State(#[from] RelationError),
    #[error(transparent)]
    Nova(#[from] DirectNovaSessionError),
    #[error("certificate parent selected an unexpected Nova suite")]
    Suite,
    #[error("certificate parent proof length is {actual}, expected {expected}")]
    ProofLength { expected: usize, actual: usize },
}

/// Verifies one profile-checked recursive parent and returns its pending root.
///
/// `inputs` must come from independently admitted public certificate records.
/// In particular, the proof does not supply its context, counts, step count,
/// or final manifest. This function deliberately cannot produce an accepted
/// certificate: native BP++ `decide()` remains mandatory for the returned
/// root.
pub(crate) fn verify_certificate_parent(
    verifier: &SelectedDirectNovaVerifier<CERTIFICATE_RECURRENCE_STATE_ARITY>,
    inputs: &CertificateParentInputs,
    proof: &[u8],
) -> Result<CertificateParentPendingRoot, CertificateParentVerifierError> {
    if verifier.expected() != &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE {
        return Err(CertificateParentVerifierError::Suite);
    }
    validate_proof_length(proof)?;

    let authenticated_final =
        verifier.verify_final(inputs.initial_state(), inputs.step_count(), proof)?;
    Ok(inputs.validate_authenticated_final_state(authenticated_final)?)
}

fn validate_proof_length(proof: &[u8]) -> Result<(), CertificateParentVerifierError> {
    if proof.len() != QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH {
        return Err(CertificateParentVerifierError::ProofLength {
            expected: QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH,
            actual: proof.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn enforces_the_frozen_certificate_proof_length() {
        let short = vec![0; QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH - 1];
        assert_eq!(
            validate_proof_length(&short),
            Err(CertificateParentVerifierError::ProofLength {
                expected: QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH,
                actual: short.len(),
            })
        );
        let exact = vec![0; QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH];
        assert_eq!(validate_proof_length(&exact), Ok(()));
        let long = vec![0; QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH + 1];
        assert_eq!(
            validate_proof_length(&long),
            Err(CertificateParentVerifierError::ProofLength {
                expected: QUALIFIED_CERTIFICATE_PARENT_PROOF_LENGTH,
                actual: long.len(),
            })
        );
    }

    #[test]
    fn loader_rejects_a_nonartifact_before_serde() {
        let mut artifact = Cursor::new(vec![0xa5; 16]);
        assert!(matches!(
            load_qualified_certificate_parent_verifier(&mut artifact),
            Err(DirectNovaVerifierArtifactError::Length)
        ));
        assert_eq!(artifact.position(), 16);
    }

    #[test]
    #[ignore = "authenticates and decodes the production certificate VK2"]
    fn qualified_loader_accepts_the_frozen_artifact() {
        let path = std::env::var_os("PURIFY_CERTIFICATE_PARENT_VERIFIER_ARTIFACT")
            .expect("set PURIFY_CERTIFICATE_PARENT_VERIFIER_ARTIFACT");
        let mut artifact =
            std::fs::File::open(path).expect("open certificate verifier artifact read-only");
        let verifier = load_qualified_certificate_parent_verifier(&mut artifact)
            .expect("load qualified certificate verifier");
        assert_eq!(
            verifier.expected(),
            &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE
        );
    }
}
