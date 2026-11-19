//! Proof-suite identity and engine types shared by proving and verification.

use nova_snark::provider::{Secp256k1Sha256Engine, Secq256k1Sha256Engine};
use nova_snark::{
    frontend::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError},
    traits::circuit::StepCircuit,
};

use crate::Scalar;

/// Canonical encoding of an ordered direct [`StepCircuit`] relation.
///
/// This version is part of both the streamed relation ID and the complete
/// Nova suite ID.
pub(crate) const DIRECT_STEP_RELATION_ENCODING_VERSION: u8 = 1;

pub(crate) type DirectNovaPrimaryEngine = Secq256k1Sha256Engine;
pub(crate) type DirectNovaSecondaryEngine = Secp256k1Sha256Engine;
pub(crate) type DirectNovaScalar = Scalar;

/// Uninhabited circuit marker for verification-only Nova types.
///
/// Nova verifier keys and compressed proofs retain their circuit generic only
/// through `PhantomData`. Verification uses the authenticated arity stored in
/// the key and never synthesizes the circuit. Keeping this marker uninhabited
/// makes accidental setup or proving against it impossible.
#[derive(Clone, Copy, Debug)]
pub(crate) enum VerifierOnlyNovaStep<const ARITY: usize> {}

impl<const ARITY: usize> StepCircuit<DirectNovaScalar> for VerifierOnlyNovaStep<ARITY> {
    fn arity(&self) -> usize {
        match *self {}
    }

    fn synthesize<CS: ConstraintSystem<DirectNovaScalar>>(
        &self,
        _cs: &mut CS,
        _z: &[AllocatedNum<DirectNovaScalar>],
    ) -> Result<Vec<AllocatedNum<DirectNovaScalar>>, SynthesisError> {
        match *self {}
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectRelationId([u8; 32]);

impl DirectRelationId {
    /// This identifies only the ordered direct step relation. The qualified
    /// suite ID additionally binds Nova, both engines, public parameters,
    /// compression, and the canonical proof codec.
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reconstructs an ID only from a locally frozen suite profile.
    pub(crate) const fn from_frozen_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
