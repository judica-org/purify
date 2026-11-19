//! Homogeneous one-member certificate recurrence.
//!
//! Every step verifies one nonce leaf, binds one fixed-size response frame,
//! advances one ordered record manifest, and folds exactly two candidate
//! claims. Response boundaries change values, never the circuit shape.

use std::array;

use ff::Field;
use nova_snark::{
    frontend::{
        gadgets::{boolean::Boolean, num::AllocatedNum},
        ConstraintSystem, LinearCombination, SynthesisError,
    },
    gadgets::utils::select_zero_or_num2,
    traits::circuit::StepCircuit,
};

use crate::candidate::CandidateStepProofWitness;
use crate::certificate_joined_witness::{CertificateJoinedWitness, CertificateLinearJoinedWitness};
use crate::certificate_member_leaf::{
    constrain_certificate_member_leaf, CertificateMemberLeafWitness, DirectCertificateMemberLeaf,
};
use crate::certificate_profile::{
    CERTIFICATE_PARENT_BASIS_DIGEST, CERTIFICATE_RECURRENCE_STATE_ARITY, CERTIFICATE_ROOT_ROUNDS,
    CERTIFICATE_ROOT_STATE_ARITY, CONTEXT_HIGH_INDEX, CONTEXT_LOW_INDEX, MEMBER_COUNT_INDEX,
    MEMBER_ORDINAL_INDEX, NONCE_PREFIX_INDEX, NONCE_X_INDEX, RECORD_MANIFEST_INDEX,
    RESPONSE_BINDING_INDEX, RESPONSE_ORDINAL_INDEX, TOTAL_RESPONSES_INDEX,
};
use crate::certificate_recurrence::CertificateRecurrenceStateWitness;
use crate::certificate_recursive_manifest::MANIFEST_STEP_TAG;
use crate::certificate_response_relation::{
    CertificateResponseRelationWitness, CERTIFICATE_RECURSIVE_STEP_TAG,
};
use crate::nova_candidate::{
    install_constrained_bound_candidate_step, DirectCandidateRoot, DirectPendingClaim,
};
use crate::nova_candidate_state::{bind_candidate_root_state, candidate_root_output_fields};
use crate::nova_protocol_transcript::scalar_bytes;
use crate::nova_secp::{
    add_points, allocate_constant_point, allocate_encoded_point, encode_computed_point,
    scale_point, DirectEncodedSecpPoint,
};
use crate::nova_secp_scalar::{
    allocate_canonical_scalar, constant_scalar, invert_scalar, subtract_scalars,
    CanonicalSecpScalar,
};
use crate::nova_session::NovaSessionStep;
use crate::nova_sha256_transcript::{constrain_tagged_sha256, NovaByte};
use crate::nova_types::DirectRelationId;
use crate::secp_native::{standard_generator, SecpScalarWitness};
use crate::{RelationError, Scalar};

const FIELD_BITS: usize = 256;

pub(crate) const QUALIFIED_CERTIFICATE_PARENT_RELATION_ID: DirectRelationId =
    DirectRelationId::from_frozen_bytes([
        0xf5, 0xa3, 0x14, 0x75, 0x8f, 0x53, 0x15, 0xd9, 0x19, 0x89, 0x49, 0x3b, 0x31, 0xa7, 0x97,
        0x7a, 0xde, 0x72, 0x0f, 0x29, 0x67, 0xb4, 0x6e, 0x75, 0x6b, 0xce, 0x63, 0x8e, 0x18, 0x76,
        0x08, 0x1b,
    ]);

#[derive(Clone)]
pub(crate) struct CertificateParentStep {
    state: CertificateRecurrenceStateWitness,
    leaf: CertificateMemberLeafWitness,
    response: CertificateResponseRelationWitness,
    proof: CandidateStepProofWitness,
    input_state: [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
}

impl CertificateParentStep {
    pub(crate) fn new(
        state: CertificateRecurrenceStateWitness,
        joined: &CertificateJoinedWitness,
        response_ordinal: u64,
        member_ordinal: u32,
        proof: CandidateStepProofWitness,
    ) -> Result<Self, RelationError> {
        let leaf =
            CertificateMemberLeafWitness::from_joined(joined, response_ordinal, member_ordinal)?;
        let response = CertificateResponseRelationWitness::from_joined(
            joined,
            response_ordinal,
            member_ordinal,
            leaf.expected_record_digest(),
        )?;
        Self::from_parts(
            state,
            joined.frame(),
            response_ordinal,
            member_ordinal,
            leaf,
            response,
            proof,
        )
    }

    pub(crate) fn from_linear(
        state: CertificateRecurrenceStateWitness,
        joined: &CertificateLinearJoinedWitness,
        response_ordinal: u64,
        member_ordinal: u32,
    ) -> Result<Self, RelationError> {
        let response_index = usize::try_from(response_ordinal)
            .map_err(|_| RelationError::Malformed("certificate response ordinal"))?;
        let member_index = usize::try_from(member_ordinal)
            .map_err(|_| RelationError::Malformed("certificate member ordinal"))?;
        let proof = joined
            .responses()
            .get(response_index)
            .ok_or(RelationError::Malformed("certificate response ordinal"))?
            .member_proofs()
            .get(member_index)
            .ok_or(RelationError::Malformed(
                "certificate linear member ordinal",
            ))?
            .bound_step()
            .clone();
        let leaf =
            CertificateMemberLeafWitness::from_linear(joined, response_ordinal, member_ordinal)?;
        let response = CertificateResponseRelationWitness::from_linear(
            joined,
            response_ordinal,
            member_ordinal,
            leaf.expected_record_digest(),
        )?;
        Self::from_parts(
            state,
            joined.frame(),
            response_ordinal,
            member_ordinal,
            leaf,
            response,
            proof,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        state: CertificateRecurrenceStateWitness,
        frame: crate::certificate_profile::CertificateWitnessFrame,
        response_ordinal: u64,
        member_ordinal: u32,
        leaf: CertificateMemberLeafWitness,
        response: CertificateResponseRelationWitness,
        proof: CandidateStepProofWitness,
    ) -> Result<Self, RelationError> {
        if proof.left.len() != CERTIFICATE_ROOT_ROUNDS
            || proof.right.len() != CERTIFICATE_ROOT_ROUNDS
        {
            return Err(RelationError::Malformed(
                "certificate recurrence candidate proof",
            ));
        }
        if state.certificate_context_digest != frame.certificate_context_digest()
            || state.total_responses != frame.total_responses()
            || state.response_ordinal != response_ordinal
            || state.response_ordinal >= state.total_responses
        {
            return Err(RelationError::Malformed(
                "certificate recurrence immutable frame",
            ));
        }
        if state.member_count == 0 {
            if member_ordinal != 0 {
                return Err(RelationError::Malformed(
                    "certificate recurrence first member",
                ));
            }
        } else if state.member_count != response.member_count()
            || state.member_ordinal != member_ordinal
            || state.response_binding != response.masked_response_binding()
        {
            return Err(RelationError::Malformed(
                "certificate recurrence active response",
            ));
        }
        let input_state = state.state_fields()?;
        Ok(Self {
            state,
            leaf,
            response,
            proof,
            input_state,
        })
    }

    pub(crate) const fn input_state(&self) -> &[Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY] {
        &self.input_state
    }

    pub(crate) const fn expected_step_digest(&self) -> [u8; 32] {
        self.response.expected_step_digest()
    }

    fn synthesize_relation<CS: ConstraintSystem<Scalar>>(
        &self,
        mut cs: CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        if z.len() != CERTIFICATE_RECURRENCE_STATE_ARITY {
            return Err(synthesis_error("certificate recurrence state arity"));
        }
        let prior = bind_prior_state(cs.namespace(|| "prior state"), z, &self.state)?;
        let response = allocate_response_frame(cs.namespace(|| "response frame"), &self.response)?;
        constrain_response_position(cs.namespace(|| "response position"), &prior, &response)?;
        let leaf = constrain_certificate_member_leaf(
            cs.namespace(|| "certificate member leaf"),
            &self.leaf,
        )?;
        let step_digest =
            constrain_step_digest(cs.namespace(|| "recursive step digest"), &leaf, &response)?;
        let manifest = constrain_manifest_step(
            cs.namespace(|| "record manifest"),
            &prior,
            &response,
            &step_digest,
        )?;
        let claims = [prior.root_claim.clone(), leaf.claim];
        let root = install_constrained_bound_candidate_step(
            cs.namespace(|| "bound candidate step"),
            CERTIFICATE_PARENT_BASIS_DIGEST,
            CERTIFICATE_ROOT_ROUNDS,
            &step_digest,
            &claims,
            &self.proof,
        )?;
        let nonce = constrain_nonce_transition(
            cs.namespace(|| "nonce transition"),
            &prior,
            &response,
            &leaf.nonce_point,
        )?;
        expose_output_state(
            cs.namespace(|| "output state"),
            &prior,
            &response,
            &root,
            &manifest,
            &nonce,
        )
    }
}

impl StepCircuit<Scalar> for CertificateParentStep {
    fn arity(&self) -> usize {
        CERTIFICATE_RECURRENCE_STATE_ARITY
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        self.synthesize_relation(cs, z)
    }
}

impl NovaSessionStep<CERTIFICATE_RECURRENCE_STATE_ARITY> for CertificateParentStep {
    fn relation_id(&self) -> DirectRelationId {
        QUALIFIED_CERTIFICATE_PARENT_RELATION_ID
    }

    fn input_state(&self) -> &[Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY] {
        CertificateParentStep::input_state(self)
    }
}

#[derive(Clone)]
struct DirectCertificatePriorState {
    root_claim: DirectPendingClaim,
    context_high: AllocatedNum<Scalar>,
    context_low: AllocatedNum<Scalar>,
    total_responses: AllocatedNum<Scalar>,
    partial_nonce: DirectEncodedSecpPoint,
    record_manifest: [NovaByte; 32],
    response_ordinal: AllocatedNum<Scalar>,
    member_ordinal: AllocatedNum<Scalar>,
    member_count: AllocatedNum<Scalar>,
    response_binding: [NovaByte; 32],
}

struct DirectCertificateResponse {
    response_ordinal: AllocatedNum<Scalar>,
    response_ordinal_bytes: [NovaByte; 8],
    member_ordinal: AllocatedNum<Scalar>,
    member_ordinal_bytes: [NovaByte; 4],
    member_count: AllocatedNum<Scalar>,
    member_count_bytes: [NovaByte; 4],
    response_binding: [NovaByte; 32],
    masked_response_binding_field: AllocatedNum<Scalar>,
    signing_key: DirectEncodedSecpPoint,
    response: CanonicalSecpScalar,
    challenge: CanonicalSecpScalar,
    is_last: AllocatedNum<Scalar>,
}

struct DirectNonceTransition {
    prefix: AllocatedNum<Scalar>,
    x: AllocatedNum<Scalar>,
}

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

fn enforce_equal<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &AllocatedNum<Scalar>,
    expected: LinearCombination<Scalar>,
) {
    cs.enforce(
        || "field equality",
        |linear| linear + value.get_variable(),
        |linear| linear + CS::one(),
        |_| expected,
    );
}

fn enforce_zero_if<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    condition: &AllocatedNum<Scalar>,
    value: LinearCombination<Scalar>,
) {
    cs.enforce(
        || "conditional zero",
        |linear| linear + condition.get_variable(),
        |_| value,
        |linear| linear,
    );
}

fn enforce_equal_if<CS: ConstraintSystem<Scalar>>(
    cs: CS,
    condition: &AllocatedNum<Scalar>,
    left: &AllocatedNum<Scalar>,
    right: &AllocatedNum<Scalar>,
) {
    enforce_zero_if(
        cs,
        condition,
        LinearCombination::zero() + left.get_variable() - right.get_variable(),
    );
}

fn allocate_bytes<CS: ConstraintSystem<Scalar>, const N: usize>(
    mut cs: CS,
    bytes: [u8; N],
) -> Result<[NovaByte; N], SynthesisError> {
    bytes
        .into_iter()
        .enumerate()
        .map(|(index, byte)| NovaByte::allocate(cs.namespace(|| format!("byte {index}")), byte))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| synthesis_error("certificate byte width"))
}

fn bytes_linear_combination<CS: ConstraintSystem<Scalar>>(
    bytes: &[NovaByte],
) -> LinearCombination<Scalar> {
    let mut coefficient = Scalar::ONE;
    let mut value = LinearCombination::zero();
    for byte in bytes.iter().rev() {
        for bit in byte.bits_le() {
            value = value + &bit.lc(CS::one(), coefficient);
            coefficient = coefficient.double();
        }
    }
    value
}

fn allocate_num_with_bytes<CS: ConstraintSystem<Scalar>, const N: usize>(
    mut cs: CS,
    value: u64,
) -> Result<(AllocatedNum<Scalar>, [NovaByte; N]), SynthesisError> {
    if N > 8 || (N < 8 && value >= (1u64 << (8 * N))) {
        return Err(synthesis_error("certificate integer width"));
    }
    let encoded = value.to_be_bytes();
    let bytes: [u8; N] = encoded[8 - N..]
        .try_into()
        .map_err(|_| synthesis_error("certificate integer width"))?;
    let bytes = allocate_bytes(cs.namespace(|| "integer bytes"), bytes)?;
    let number = AllocatedNum::alloc(cs.namespace(|| "integer value"), || Ok(Scalar::from(value)))?;
    enforce_equal(
        cs.namespace(|| "integer encoding"),
        &number,
        bytes_linear_combination::<CS::Root>(&bytes),
    );
    Ok((number, bytes))
}

fn bind_num<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    state: &AllocatedNum<Scalar>,
    value: u64,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let number = AllocatedNum::alloc(cs.namespace(|| "typed integer"), || Ok(Scalar::from(value)))?;
    enforce_equal(
        cs.namespace(|| "state integer"),
        state,
        LinearCombination::zero() + number.get_variable(),
    );
    Ok(number)
}

fn field_bytes_be<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &AllocatedNum<Scalar>,
) -> Result<[NovaByte; 32], SynthesisError> {
    let bits = value.to_bits_le_strict(cs.namespace(|| "canonical field bits"))?;
    if bits.len() != FIELD_BITS {
        return Err(synthesis_error("certificate state field width"));
    }
    Ok(array::from_fn(|byte| {
        let offset = (31 - byte) * 8;
        NovaByte::from_constrained_bits_le(array::from_fn(|bit| bits[offset + bit].clone()))
    }))
}

fn enforce_low_255<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    bytes: &[NovaByte; 32],
) -> Result<(), SynthesisError> {
    Boolean::enforce_equal(
        cs.namespace(|| "high digest bit is zero"),
        &bytes[0].bits_le()[7],
        &Boolean::constant(false),
    )
}

fn masked_digest(bytes: &[NovaByte; 32]) -> [NovaByte; 32] {
    let mut masked = bytes.clone();
    let mut first = masked[0].bits_le().clone();
    first[7] = Boolean::constant(false);
    masked[0] = NovaByte::from_constrained_bits_le(first);
    masked
}

fn field_from_low_digest<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    bytes: &[NovaByte; 32],
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    enforce_low_255(cs.namespace(|| "low digest"), bytes)?;
    let number = AllocatedNum::alloc(cs.namespace(|| "digest field"), || {
        bytes
            .iter()
            .try_fold(Scalar::ZERO, |value, byte| {
                byte.bits_le()
                    .iter()
                    .enumerate()
                    .try_fold(0u8, |value, (bit, input)| {
                        input
                            .get_value()
                            .map(|input| value | (u8::from(input) << bit))
                    })
                    .map(|byte| value * Scalar::from(256) + Scalar::from(u64::from(byte)))
            })
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    enforce_equal(
        cs.namespace(|| "digest field encoding"),
        &number,
        bytes_linear_combination::<CS::Root>(bytes),
    );
    Ok(number)
}

fn is_zero<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let zero = AllocatedNum::alloc(cs.namespace(|| "is zero"), || {
        value
            .get_value()
            .map(|value| {
                if value == Scalar::ZERO {
                    Scalar::ONE
                } else {
                    Scalar::ZERO
                }
            })
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    let inverse = AllocatedNum::alloc(cs.namespace(|| "zero inverse"), || {
        value
            .get_value()
            .map(|value| Option::<Scalar>::from(value.invert()).unwrap_or(Scalar::ZERO))
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "zero indicator boolean",
        |linear| linear + zero.get_variable(),
        |linear| linear + zero.get_variable() - CS::one(),
        |linear| linear,
    );
    cs.enforce(
        || "zero inverse",
        |linear| linear + value.get_variable(),
        |linear| linear + inverse.get_variable(),
        |linear| linear + CS::one() - zero.get_variable(),
    );
    cs.enforce(
        || "zero product",
        |linear| linear + value.get_variable(),
        |linear| linear + zero.get_variable(),
        |linear| linear,
    );
    Ok(zero)
}

fn bind_prior_state<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    state: &[AllocatedNum<Scalar>],
    witness: &CertificateRecurrenceStateWitness,
) -> Result<DirectCertificatePriorState, SynthesisError> {
    if state.len() != CERTIFICATE_RECURRENCE_STATE_ARITY {
        return Err(synthesis_error("certificate recurrence state shape"));
    }
    let root_claim = bind_candidate_root_state::<_, CERTIFICATE_ROOT_ROUNDS>(
        &mut cs,
        &state[..CERTIFICATE_ROOT_STATE_ARITY],
        &witness.root,
    )?;
    let total_responses = bind_num(
        cs.namespace(|| "total responses"),
        &state[TOTAL_RESPONSES_INDEX],
        witness.total_responses,
    )?;
    let partial_nonce =
        allocate_encoded_point(cs.namespace(|| "partial nonce"), witness.partial_nonce)?;
    enforce_equal(
        cs.namespace(|| "partial nonce prefix"),
        &state[NONCE_PREFIX_INDEX],
        LinearCombination::zero() + partial_nonce.prefix().get_variable(),
    );
    enforce_equal(
        cs.namespace(|| "partial nonce x"),
        &state[NONCE_X_INDEX],
        LinearCombination::zero() + partial_nonce.point().x().get_variable(),
    );
    let record_manifest = field_bytes_be(
        cs.namespace(|| "record manifest"),
        &state[RECORD_MANIFEST_INDEX],
    )?;
    enforce_low_255(cs.namespace(|| "record manifest range"), &record_manifest)?;
    let response_ordinal = bind_num(
        cs.namespace(|| "response ordinal"),
        &state[RESPONSE_ORDINAL_INDEX],
        witness.response_ordinal,
    )?;
    let member_ordinal = bind_num(
        cs.namespace(|| "member ordinal"),
        &state[MEMBER_ORDINAL_INDEX],
        u64::from(witness.member_ordinal),
    )?;
    let member_count = bind_num(
        cs.namespace(|| "member count"),
        &state[MEMBER_COUNT_INDEX],
        u64::from(witness.member_count),
    )?;
    let response_binding = field_bytes_be(
        cs.namespace(|| "response binding"),
        &state[RESPONSE_BINDING_INDEX],
    )?;
    enforce_low_255(cs.namespace(|| "response binding range"), &response_binding)?;
    Ok(DirectCertificatePriorState {
        root_claim,
        context_high: state[CONTEXT_HIGH_INDEX].clone(),
        context_low: state[CONTEXT_LOW_INDEX].clone(),
        total_responses,
        partial_nonce,
        record_manifest,
        response_ordinal,
        member_ordinal,
        member_count,
        response_binding,
    })
}

fn allocate_response_frame<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    witness: &CertificateResponseRelationWitness,
) -> Result<DirectCertificateResponse, SynthesisError> {
    let (response_ordinal, response_ordinal_bytes) = allocate_num_with_bytes::<_, 8>(
        cs.namespace(|| "response ordinal"),
        witness.response_ordinal(),
    )?;
    let (member_ordinal, member_ordinal_bytes) = allocate_num_with_bytes::<_, 4>(
        cs.namespace(|| "member ordinal"),
        u64::from(witness.member_ordinal()),
    )?;
    let (member_count, member_count_bytes) = allocate_num_with_bytes::<_, 4>(
        cs.namespace(|| "member count"),
        u64::from(witness.member_count()),
    )?;
    let response_binding = allocate_bytes(
        cs.namespace(|| "response binding"),
        witness.response_binding(),
    )?;
    let masked_response_binding = masked_digest(&response_binding);
    let masked_response_binding_field = field_from_low_digest(
        cs.namespace(|| "masked response binding"),
        &masked_response_binding,
    )?;
    let signing_key =
        allocate_encoded_point(cs.namespace(|| "signing key"), witness.signing_key())?;
    enforce_equal(
        cs.namespace(|| "even signing key"),
        signing_key.prefix(),
        LinearCombination::zero() + (Scalar::from(2), CS::one()),
    );
    enforce_equal(
        cs.namespace(|| "finite signing key"),
        signing_key.point().identity_num(),
        LinearCombination::zero(),
    );
    let response =
        allocate_canonical_scalar(cs.namespace(|| "response scalar"), witness.response())?;
    let challenge =
        allocate_canonical_scalar(cs.namespace(|| "challenge scalar"), witness.challenge())?;
    invert_scalar(cs.namespace(|| "nonzero challenge"), &challenge)?;

    let remaining = AllocatedNum::alloc(cs.namespace(|| "remaining members"), || {
        Ok(Scalar::from(u64::from(
            witness.member_count() - witness.member_ordinal() - 1,
        )))
    })?;
    cs.enforce(
        || "remaining member count",
        |linear| linear + member_count.get_variable() - member_ordinal.get_variable() - CS::one(),
        |linear| linear + CS::one(),
        |linear| linear + remaining.get_variable(),
    );
    let is_last = is_zero(cs.namespace(|| "last member"), &remaining)?;
    Ok(DirectCertificateResponse {
        response_ordinal,
        response_ordinal_bytes,
        member_ordinal,
        member_ordinal_bytes,
        member_count,
        member_count_bytes,
        response_binding,
        masked_response_binding_field,
        signing_key,
        response,
        challenge,
        is_last,
    })
}

fn constrain_response_position<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    prior: &DirectCertificatePriorState,
    response: &DirectCertificateResponse,
) -> Result<(), SynthesisError> {
    enforce_equal(
        cs.namespace(|| "response ordinal"),
        &prior.response_ordinal,
        LinearCombination::zero() + response.response_ordinal.get_variable(),
    );
    let is_start = is_zero(cs.namespace(|| "response start"), &prior.member_count)?;
    let not_start = AllocatedNum::alloc(cs.namespace(|| "active response"), || {
        is_start
            .get_value()
            .map(|value| Scalar::ONE - value)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "response phase complement",
        |linear| linear + is_start.get_variable() + not_start.get_variable(),
        |linear| linear + CS::one(),
        |linear| linear + CS::one(),
    );
    enforce_zero_if(
        cs.namespace(|| "first member ordinal"),
        &is_start,
        LinearCombination::zero() + response.member_ordinal.get_variable(),
    );
    enforce_equal_if(
        cs.namespace(|| "active member ordinal"),
        &not_start,
        &prior.member_ordinal,
        &response.member_ordinal,
    );
    enforce_equal_if(
        cs.namespace(|| "active member count"),
        &not_start,
        &prior.member_count,
        &response.member_count,
    );
    let prior_binding = field_from_low_digest(
        cs.namespace(|| "prior response binding"),
        &prior.response_binding,
    )?;
    enforce_equal_if(
        cs.namespace(|| "active response binding"),
        &not_start,
        &prior_binding,
        &response.masked_response_binding_field,
    );
    enforce_zero_if(
        cs.namespace(|| "neutral nonce prefix"),
        &is_start,
        LinearCombination::zero() + prior.partial_nonce.prefix().get_variable(),
    );
    enforce_zero_if(
        cs.namespace(|| "neutral nonce x"),
        &is_start,
        LinearCombination::zero() + prior.partial_nonce.point().x().get_variable(),
    );
    Ok(())
}

fn constrain_step_digest<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    leaf: &DirectCertificateMemberLeaf,
    response: &DirectCertificateResponse,
) -> Result<[NovaByte; 32], SynthesisError> {
    let mut encoded = Vec::with_capacity(32 + 32 + 4 + 32 + 32 + 32);
    encoded.extend_from_slice(&leaf.record_digest);
    encoded.extend_from_slice(&response.response_binding);
    encoded.extend_from_slice(&response.member_count_bytes);
    encoded.extend_from_slice(response.signing_key.x_bytes());
    encoded.extend(scalar_bytes(&response.response)?);
    encoded.extend(scalar_bytes(&response.challenge)?);
    constrain_tagged_sha256(
        cs.namespace(|| "certificate recursive step"),
        CERTIFICATE_RECURSIVE_STEP_TAG,
        &encoded,
    )
}

fn constrain_manifest_step<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    prior: &DirectCertificatePriorState,
    response: &DirectCertificateResponse,
    step_digest: &[NovaByte; 32],
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let mut encoded = Vec::with_capacity(32 + 8 + 4 + 32);
    encoded.extend_from_slice(&prior.record_manifest);
    encoded.extend_from_slice(&response.response_ordinal_bytes);
    encoded.extend_from_slice(&response.member_ordinal_bytes);
    encoded.extend_from_slice(step_digest);
    let digest = constrain_tagged_sha256(
        cs.namespace(|| "certificate recursive manifest"),
        MANIFEST_STEP_TAG,
        &encoded,
    )?;
    field_from_low_digest(cs.namespace(|| "manifest scalar"), &masked_digest(&digest))
}

fn constrain_nonce_transition<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    prior: &DirectCertificatePriorState,
    response: &DirectCertificateResponse,
    member_nonce: &DirectEncodedSecpPoint,
) -> Result<DirectNonceTransition, SynthesisError> {
    let aggregate = add_points(
        cs.namespace(|| "aggregate nonce"),
        prior.partial_nonce.point(),
        member_nonce.point(),
    )?;
    let zero = constant_scalar::<CS::Root>(SecpScalarWitness::from_u64(0))?;
    let negative_challenge = subtract_scalars(
        cs.namespace(|| "negative challenge"),
        &zero,
        &response.challenge,
    )?;
    let generator =
        allocate_constant_point(cs.namespace(|| "signature generator"), standard_generator())?;
    let response_bits = response
        .response
        .allocated_bits_le(cs.namespace(|| "response bits"))?;
    let response_term = scale_point(
        cs.namespace(|| "response generator term"),
        &generator,
        &response_bits,
    )?;
    let challenge_bits = negative_challenge.allocated_bits_le(cs.namespace(|| "challenge bits"))?;
    let key_term = scale_point(
        cs.namespace(|| "challenge key term"),
        response.signing_key.point(),
        &challenge_bits,
    )?;
    let reconstructed = add_points(
        cs.namespace(|| "reconstructed nonce"),
        &response_term,
        &key_term,
    )?;
    enforce_equal_if(
        cs.namespace(|| "final nonce x"),
        &response.is_last,
        aggregate.x(),
        reconstructed.x(),
    );
    enforce_equal_if(
        cs.namespace(|| "final nonce y"),
        &response.is_last,
        aggregate.y(),
        reconstructed.y(),
    );
    enforce_equal_if(
        cs.namespace(|| "final nonce identity"),
        &response.is_last,
        aggregate.identity_num(),
        reconstructed.identity_num(),
    );
    enforce_zero_if(
        cs.namespace(|| "finite final nonce"),
        &response.is_last,
        LinearCombination::zero() + reconstructed.identity_num().get_variable(),
    );
    let aggregate = encode_computed_point(cs.namespace(|| "aggregate nonce encoding"), aggregate)?;
    let prefix = select_zero_or_num2(
        cs.namespace(|| "next nonce prefix"),
        aggregate.prefix(),
        &response.is_last,
    )?;
    let x = select_zero_or_num2(
        cs.namespace(|| "next nonce x"),
        aggregate.point().x(),
        &response.is_last,
    )?;
    Ok(DirectNonceTransition { prefix, x })
}

fn increment_if<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &AllocatedNum<Scalar>,
    condition: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let output = AllocatedNum::alloc(cs.namespace(|| "conditional increment"), || {
        value
            .get_value()
            .zip(condition.get_value())
            .map(|(value, condition)| value + condition)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "conditional increment",
        |linear| linear + value.get_variable() + condition.get_variable(),
        |linear| linear + CS::one(),
        |linear| linear + output.get_variable(),
    );
    Ok(output)
}

fn increment<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    value: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let output = AllocatedNum::alloc(cs.namespace(|| "increment"), || {
        value
            .get_value()
            .map(|value| value + Scalar::ONE)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "increment",
        |linear| linear + value.get_variable() + CS::one(),
        |linear| linear + CS::one(),
        |linear| linear + output.get_variable(),
    );
    Ok(output)
}

fn expose_output_state<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    prior: &DirectCertificatePriorState,
    response: &DirectCertificateResponse,
    root: &DirectCandidateRoot,
    manifest: &AllocatedNum<Scalar>,
    nonce: &DirectNonceTransition,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    let mut output = Vec::with_capacity(CERTIFICATE_RECURRENCE_STATE_ARITY);
    output.extend(candidate_root_output_fields::<_, CERTIFICATE_ROOT_ROUNDS>(
        &mut cs, root,
    )?);
    output.push(prior.context_high.clone());
    output.push(prior.context_low.clone());
    output.push(prior.total_responses.clone());
    output.push(nonce.prefix.clone());
    output.push(nonce.x.clone());
    output.push(manifest.clone());
    output.push(increment_if(
        cs.namespace(|| "response ordinal"),
        &prior.response_ordinal,
        &response.is_last,
    )?);
    let next_member = increment(
        cs.namespace(|| "next member ordinal"),
        &response.member_ordinal,
    )?;
    output.push(select_zero_or_num2(
        cs.namespace(|| "member ordinal"),
        &next_member,
        &response.is_last,
    )?);
    output.push(select_zero_or_num2(
        cs.namespace(|| "member count"),
        &response.member_count,
        &response.is_last,
    )?);
    output.push(select_zero_or_num2(
        cs.namespace(|| "response binding"),
        &response.masked_response_binding_field,
        &response.is_last,
    )?);
    debug_assert_eq!(output.len(), CERTIFICATE_RECURRENCE_STATE_ARITY);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::{panic, thread};

    use super::*;
    use crate::certificate_profile::{
        CERTIFICATE_RECURRENCE_RELATION_AUXILIARY, CERTIFICATE_RECURRENCE_RELATION_CONSTRAINTS,
    };
    use crate::certificate_recursive_manifest::recursive_manifest_step;
    use crate::nova_relation_identity::direct_step_relation_shape;
    use crate::secp_native::SecpEncodedPointWitness;

    const JOINED_WITNESS: &[u8] =
        include_bytes!("../tests/vectors/certificate_joined_witness_v2.bin");

    fn joined_witness() -> CertificateJoinedWitness {
        CertificateJoinedWitness::parse(JOINED_WITNESS).expect("accepted joined witness")
    }

    fn candidate_proof() -> CandidateStepProofWitness {
        CandidateStepProofWitness {
            left: vec![SecpEncodedPointWitness::identity(); CERTIFICATE_ROOT_ROUNDS],
            right: vec![SecpEncodedPointWitness::identity(); CERTIFICATE_ROOT_ROUNDS],
            terminal_scalar: SecpScalarWitness::from_u64(1),
            folded_generator: SecpEncodedPointWitness::identity(),
        }
    }

    #[test]
    fn recurrence_state_layout_matches_output_order() {
        assert_eq!(CERTIFICATE_ROOT_STATE_ARITY, 16);
        assert_eq!(CONTEXT_HIGH_INDEX, 16);
        assert_eq!(CONTEXT_LOW_INDEX, 17);
        assert_eq!(TOTAL_RESPONSES_INDEX, 18);
        assert_eq!(NONCE_PREFIX_INDEX, 19);
        assert_eq!(NONCE_X_INDEX, 20);
        assert_eq!(RECORD_MANIFEST_INDEX, 21);
        assert_eq!(RESPONSE_ORDINAL_INDEX, 22);
        assert_eq!(MEMBER_ORDINAL_INDEX, 23);
        assert_eq!(MEMBER_COUNT_INDEX, 24);
        assert_eq!(RESPONSE_BINDING_INDEX, 25);
        assert_eq!(CERTIFICATE_RECURRENCE_STATE_ARITY, 26);
    }

    #[test]
    fn recurrence_constructor_enforces_member_order() {
        let joined = joined_witness();
        let frame = joined.frame();
        let state = CertificateRecurrenceStateWitness::genesis(
            frame.certificate_context_digest(),
            frame.total_responses(),
        )
        .expect("certificate genesis");
        let expected = state.state_fields().expect("genesis fields");
        let step = CertificateParentStep::new(state.clone(), &joined, 0, 0, candidate_proof())
            .expect("first certificate step");
        assert_eq!(step.input_state(), &expected);
        assert!(CertificateParentStep::new(state, &joined, 0, 1, candidate_proof()).is_err());
    }

    fn first_active_state(joined: &CertificateJoinedWitness) -> CertificateRecurrenceStateWitness {
        let frame = joined.frame();
        let mut state = CertificateRecurrenceStateWitness::genesis(
            frame.certificate_context_digest(),
            frame.total_responses(),
        )
        .expect("certificate genesis");
        let leaf =
            CertificateMemberLeafWitness::from_joined(joined, 0, 0).expect("first member leaf");
        let response = CertificateResponseRelationWitness::from_joined(
            joined,
            0,
            0,
            leaf.expected_record_digest(),
        )
        .expect("first response frame");
        state.record_manifest =
            recursive_manifest_step(state.record_manifest, 0, 0, response.expected_step_digest())
                .expect("first recursive manifest step");
        state.partial_nonce = joined.responses()[0].members()[0].nonce_point();
        state.member_ordinal = 1;
        state.member_count = response.member_count();
        state.response_binding = response.masked_response_binding();
        state
    }

    #[test]
    #[ignore = "streams the full production certificate relation"]
    fn production_relation_shape_is_homogeneous_across_response_boundary() {
        let worker = thread::Builder::new()
            .name("certificate-relation-shape".to_owned())
            .stack_size(64 * 1024 * 1024)
            .spawn(run_production_relation_shape)
            .expect("certificate relation worker");
        if let Err(payload) = worker.join() {
            panic::resume_unwind(payload);
        }
    }

    fn run_production_relation_shape() {
        let joined = joined_witness();
        let frame = joined.frame();
        let first = CertificateParentStep::new(
            CertificateRecurrenceStateWitness::genesis(
                frame.certificate_context_digest(),
                frame.total_responses(),
            )
            .expect("certificate genesis"),
            &joined,
            0,
            0,
            candidate_proof(),
        )
        .expect("first certificate step");
        let last = CertificateParentStep::new(
            first_active_state(&joined),
            &joined,
            0,
            1,
            candidate_proof(),
        )
        .expect("last certificate step");
        let first_shape =
            direct_step_relation_shape::<CERTIFICATE_RECURRENCE_STATE_ARITY, _>(&first)
                .expect("first certificate relation");
        let last_shape = direct_step_relation_shape::<CERTIFICATE_RECURRENCE_STATE_ARITY, _>(&last)
            .expect("last certificate relation");
        assert_eq!(first_shape, last_shape);
        assert_eq!(first_shape.inputs(), CERTIFICATE_RECURRENCE_STATE_ARITY + 1);
        assert_eq!(
            first_shape.relation_id(),
            QUALIFIED_CERTIFICATE_PARENT_RELATION_ID,
        );
        assert_eq!(
            first_shape.auxiliary(),
            CERTIFICATE_RECURRENCE_RELATION_AUXILIARY,
        );
        assert_eq!(
            first_shape.constraints(),
            CERTIFICATE_RECURRENCE_RELATION_CONSTRAINTS,
        );
    }
}
