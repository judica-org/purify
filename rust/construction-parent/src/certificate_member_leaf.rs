//! Host-bound certificate member leaves for recursive accumulation.
//!
//! One leaf verifies the exact V4 transcript and coefficient reduction under
//! parent constants recomputed by the compact verifier. It also hashes the
//! canonical raw proof and reconstructs the native leaf binding. The returned
//! record digest binds the complete host and topic to the only seam into the
//! ordered certificate recurrence.
//!
//! Paired-curve host validation and variable-length accountable-topic hashing
//! remain compact-verifier work. Recursive soundness therefore requires the
//! final recurrence to enforce equality with the verifier-derived ordered
//! record manifest. Native candidate decision without that equality is not a
//! certificate verifier.

use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use sha2::{Digest as _, Sha256};

use crate::certificate_joined_witness::{
    CertificateJoinedMemberWitness, CertificateJoinedResponseWitness, CertificateJoinedWitness,
    CertificateLinearJoinedWitness,
};
use crate::certificate_nonce_proof::{certificate_leaf_shape, CertificateNonceProofWitnessV4};
use crate::certificate_profile::{
    CERTIFICATE_NONCE_PROOF_BYTES, CERTIFICATE_PARENT_BASIS_DIGEST,
    CERTIFICATE_PARENT_RAW_GENERATOR_DIGEST,
};
use crate::circuit_norm::{
    CandidateNormReductionProofWitness, ManifestBoundConstructionLeafStatementV4,
};
use crate::nova_candidate::DirectPendingClaim;
use crate::nova_circuit_norm_leaf::{
    constrain_manifest_bound_construction_leaf, DirectManifestBoundConstructionLeaf,
};
use crate::nova_circuit_transcript::DirectCircuitTranscriptResultV4;
use crate::nova_protocol_transcript::scalar_bytes;
use crate::nova_secp::{allocate_encoded_point, DirectEncodedSecpPoint};
use crate::nova_secp_scalar::{allocate_canonical_scalar, CanonicalSecpScalar};
use crate::nova_sha256_transcript::{constrain_tagged_sha256, NovaByte};
use crate::secp_native::{SecpEncodedPointWitness, SecpScalarWitness};
use crate::{RelationError, Scalar};

const ACCOUNTABLE_NONCE_TAG: &[u8] = b"Purify/Accountable/Nonce/v2";
const CERTIFICATE_NONCE_PROOF_TAG: &[u8] = b"Purify/Accountable/CertificateNonceProof/v1";
const CERTIFICATE_NONCE_LEAF_TAG: &[u8] = b"Purify/Accountable/CertificateNonceLeaf/v1";
pub(crate) const CERTIFICATE_RECURSIVE_MEMBER_TAG: &[u8] =
    b"Purify/Accountable/CertificateRecursiveMember/v1";

/// Exact inputs for one member of one certificate response.
#[derive(Clone)]
pub(crate) struct CertificateMemberLeafWitness {
    response_ordinal: u64,
    member_ordinal: u32,
    authorization_digest: [u8; 32],
    host: [u8; 96],
    host_signing_key: SecpEncodedPointWitness,
    topic: [u8; 32],
    circuit_precommitment: SecpScalarWitness,
    circuit_binding_digest: [u8; 32],
    // Prover-side recurrence planning only. A compact verifier must derive
    // the final record manifest independently from admitted public data.
    expected_record_digest: [u8; 32],
    transcript: crate::circuit_transcript::CircuitProofTranscriptWitnessV4,
    reduction: CandidateNormReductionProofWitness,
}

impl CertificateMemberLeafWitness {
    pub(crate) fn from_joined(
        joined: &CertificateJoinedWitness,
        response_ordinal: u64,
        member_ordinal: u32,
    ) -> Result<Self, RelationError> {
        let response_index = usize::try_from(response_ordinal)
            .map_err(|_| RelationError::Malformed("certificate response ordinal"))?;
        let member_index = usize::try_from(member_ordinal)
            .map_err(|_| RelationError::Malformed("certificate member ordinal"))?;
        let response = joined
            .responses()
            .get(response_index)
            .ok_or(RelationError::Malformed("certificate response ordinal"))?;
        if response.boundary().ordinal() != response_ordinal {
            return Err(RelationError::Malformed("certificate response boundary"));
        }
        let member = response
            .members()
            .get(member_index)
            .ok_or(RelationError::Malformed("certificate member ordinal"))?;
        let native_response = joined
            .native_receipt()
            .responses()
            .get(response_index)
            .ok_or(RelationError::Malformed(
                "certificate native response ordinal",
            ))?;
        let reduction = native_response
            .reductions()
            .get(member_index)
            .ok_or(RelationError::Malformed(
                "certificate native member ordinal",
            ))?
            .clone();
        Self::from_response_member(
            response,
            member,
            response_ordinal,
            member_ordinal,
            reduction,
        )
    }

    pub(crate) fn from_linear(
        joined: &CertificateLinearJoinedWitness,
        response_ordinal: u64,
        member_ordinal: u32,
    ) -> Result<Self, RelationError> {
        let response_index = usize::try_from(response_ordinal)
            .map_err(|_| RelationError::Malformed("certificate response ordinal"))?;
        let member_index = usize::try_from(member_ordinal)
            .map_err(|_| RelationError::Malformed("certificate member ordinal"))?;
        let linear_response = joined
            .responses()
            .get(response_index)
            .ok_or(RelationError::Malformed("certificate response ordinal"))?;
        let response = linear_response.response();
        if response.boundary().ordinal() != response_ordinal {
            return Err(RelationError::Malformed("certificate response boundary"));
        }
        let member = response
            .members()
            .get(member_index)
            .ok_or(RelationError::Malformed("certificate member ordinal"))?;
        let reduction = linear_response
            .member_proofs()
            .get(member_index)
            .ok_or(RelationError::Malformed(
                "certificate linear member ordinal",
            ))?
            .reduction()
            .clone();
        Self::from_response_member(
            response,
            member,
            response_ordinal,
            member_ordinal,
            reduction,
        )
    }

    fn from_response_member(
        response: &CertificateJoinedResponseWitness,
        member: &CertificateJoinedMemberWitness,
        response_ordinal: u64,
        member_ordinal: u32,
        reduction: CandidateNormReductionProofWitness,
    ) -> Result<Self, RelationError> {
        let host = member.host();
        let host_signing_key = parse_host_signing_key(host)?;
        let topic = accountable_nonce_topic(response)?;
        let circuit_precommitment = member.circuit_precommitment();
        let parent_constants = member.parent_constants();
        let expected_record_digest = native_member_record_digest(
            response_ordinal,
            member_ordinal,
            member.authorization_digest(),
            host,
            topic,
            parent_constants,
            member.leaf_binding(),
        );
        let nonce_proof = CertificateNonceProofWitnessV4::parse(*member.nonce_proof())?;
        let transcript = nonce_proof.transcript(parent_constants, circuit_precommitment)?;
        if member_ordinal >= response.boundary().member_count() {
            return Err(RelationError::Malformed("certificate member leaf ordinal"));
        }
        Ok(Self {
            response_ordinal,
            member_ordinal,
            authorization_digest: member.authorization_digest(),
            host,
            host_signing_key,
            topic,
            circuit_precommitment,
            circuit_binding_digest: parent_constants.circuit_binding_digest,
            expected_record_digest,
            transcript,
            reduction,
        })
    }

    /// Return the native mirror used to plan the expected recurrence state.
    ///
    /// This is not a constrained result or verifier authority. Acceptance
    /// requires an independently recomputed compact-verifier manifest.
    pub(crate) const fn expected_record_digest(&self) -> [u8; 32] {
        self.expected_record_digest
    }
}

fn tagged_sha256(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest.update(message);
    digest.finalize().into()
}

fn accountable_nonce_topic(
    response: &crate::certificate_joined_witness::CertificateJoinedResponseWitness,
) -> Result<[u8; 32], RelationError> {
    let slot_length = u64::try_from(response.slot().len())
        .map_err(|_| RelationError::Malformed("certificate accountable slot length"))?;
    let mut encoded = Vec::with_capacity(32 + 32 + 32 + 8 + response.slot().len());
    encoded.extend_from_slice(&response.signing_key());
    encoded.extend_from_slice(&response.host_commitment());
    encoded.extend_from_slice(&response.coalition_core_digest());
    encoded.extend_from_slice(&slot_length.to_be_bytes());
    encoded.extend_from_slice(response.slot());
    Ok(tagged_sha256(ACCOUNTABLE_NONCE_TAG, &encoded))
}

fn parse_host_signing_key(host: [u8; 96]) -> Result<SecpEncodedPointWitness, RelationError> {
    let mut encoded = [0; 33];
    encoded[0] = 2;
    encoded[1..].copy_from_slice(&host[64..]);
    SecpEncodedPointWitness::parse(encoded)
}

#[allow(clippy::too_many_arguments)]
fn native_member_record_digest(
    response_ordinal: u64,
    member_ordinal: u32,
    authorization_digest: [u8; 32],
    host: [u8; 96],
    topic: [u8; 32],
    parent_constants: crate::certificate_nonce_proof::CertificateLeafParentConstantsWitness,
    leaf_binding: [u8; 32],
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(8 + 4 + 32 + 96 + 32 + 32 + 33 + 33 + 32);
    encoded.extend_from_slice(&response_ordinal.to_be_bytes());
    encoded.extend_from_slice(&member_ordinal.to_be_bytes());
    encoded.extend_from_slice(&authorization_digest);
    encoded.extend_from_slice(&host);
    encoded.extend_from_slice(&topic);
    encoded.extend_from_slice(&parent_constants.circuit_binding_digest);
    encoded.extend_from_slice(&parent_constants.coefficient_commitment.encoded);
    encoded.extend_from_slice(&parent_constants.anchored_offset.encoded);
    encoded.extend_from_slice(&leaf_binding);
    tagged_sha256(CERTIFICATE_RECURSIVE_MEMBER_TAG, &encoded)
}

/// Constrained values consumed atomically by the certificate recurrence.
pub(crate) struct DirectCertificateMemberLeaf {
    pub(crate) claim: DirectPendingClaim,
    pub(crate) nonce_point: DirectEncodedSecpPoint,
    pub(crate) record_digest: [NovaByte; 32],
}

pub(crate) fn constrain_certificate_member_leaf<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    witness: &CertificateMemberLeafWitness,
) -> Result<DirectCertificateMemberLeaf, SynthesisError> {
    let statement = ManifestBoundConstructionLeafStatementV4 {
        shape: certificate_leaf_shape(),
        circuit_binding_digest: witness.circuit_binding_digest,
        raw_generator_digest: CERTIFICATE_PARENT_RAW_GENERATOR_DIGEST,
        basis_digest: CERTIFICATE_PARENT_BASIS_DIGEST,
    };
    let leaf = constrain_manifest_bound_construction_leaf(
        cs.namespace(|| "certificate V4 leaf"),
        statement,
        &witness.transcript,
        &witness.reduction,
    )?;
    constrain_expected_precommitment(
        cs.namespace(|| "certificate precommitment"),
        &leaf.precommitment,
        witness.circuit_precommitment,
    )?;

    let proof_bytes = canonical_nonce_proof_bytes(&leaf.transcript)?;
    let proof_digest = constrain_tagged_sha256(
        cs.namespace(|| "certificate proof digest"),
        CERTIFICATE_NONCE_PROOF_TAG,
        &proof_bytes,
    )?;
    let purify_host = allocate_bytes(
        cs.namespace(|| "certificate Purify host"),
        witness.host[..64]
            .try_into()
            .expect("fixed Purify host bytes"),
    )?;
    let host_signing_key = allocate_encoded_point(
        cs.namespace(|| "certificate host signing key"),
        witness.host_signing_key,
    )?;
    let mut full_host = Vec::with_capacity(96);
    full_host.extend_from_slice(&purify_host);
    full_host.extend_from_slice(host_signing_key.x_bytes());
    let topic = allocate_bytes(cs.namespace(|| "certificate nonce topic"), witness.topic)?;
    let leaf_binding = constrain_leaf_binding(
        cs.namespace(|| "certificate leaf binding"),
        &purify_host,
        &topic,
        &proof_digest,
        &leaf,
    )?;
    let authorization_digest = allocate_bytes(
        cs.namespace(|| "certificate member authorization"),
        witness.authorization_digest,
    )?;
    let response_ordinal = allocate_bytes(
        cs.namespace(|| "certificate response ordinal"),
        witness.response_ordinal.to_be_bytes(),
    )?;
    let member_ordinal = allocate_bytes(
        cs.namespace(|| "certificate member ordinal"),
        witness.member_ordinal.to_be_bytes(),
    )?;
    let record_digest = constrain_member_record(
        cs.namespace(|| "certificate member record"),
        &response_ordinal,
        &member_ordinal,
        &authorization_digest,
        &full_host,
        &topic,
        &leaf,
        &leaf_binding,
    )?;
    let nonce_point = leaf
        .transcript
        .public_commitments
        .first()
        .ok_or_else(|| synthesis_error("certificate public commitment"))?
        .clone();
    Ok(DirectCertificateMemberLeaf {
        claim: leaf.claim,
        nonce_point,
        record_digest,
    })
}

fn allocate_bytes<CS: ConstraintSystem<Scalar>, const N: usize>(
    mut cs: CS,
    value: [u8; N],
) -> Result<[NovaByte; N], SynthesisError> {
    value
        .into_iter()
        .enumerate()
        .map(|(index, byte)| NovaByte::allocate(cs.namespace(|| format!("byte {index}")), byte))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| synthesis_error("certificate byte width"))
}

fn constrain_expected_precommitment<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    actual: &CanonicalSecpScalar,
    expected: SecpScalarWitness,
) -> Result<(), SynthesisError> {
    let expected = allocate_canonical_scalar(cs.namespace(|| "expected precommitment"), expected)?;
    let difference = actual.embedded() - &expected.embedded();
    cs.enforce(
        || "expected circuit precommitment",
        |_| difference,
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(())
}

fn append_point(encoded: &mut Vec<NovaByte>, point: &DirectEncodedSecpPoint) {
    encoded.push(point.prefix_byte().clone());
    encoded.extend_from_slice(point.x_bytes());
}

fn append_scalar(
    encoded: &mut Vec<NovaByte>,
    scalar: &CanonicalSecpScalar,
) -> Result<(), SynthesisError> {
    encoded.extend(scalar_bytes(scalar)?);
    Ok(())
}

fn canonical_nonce_proof_bytes(
    transcript: &DirectCircuitTranscriptResultV4,
) -> Result<Vec<NovaByte>, SynthesisError> {
    let nonce = transcript
        .public_commitments
        .first()
        .ok_or_else(|| synthesis_error("certificate public commitment"))?;
    if transcript.public_commitments.len() != 1
        || transcript.rounds.len() != crate::certificate_profile::CERTIFICATE_LEAF_ROUNDS
    {
        return Err(synthesis_error("certificate nonce proof shape"));
    }
    let mut encoded = Vec::with_capacity(CERTIFICATE_NONCE_PROOF_BYTES);
    encoded.push(NovaByte::constant(4));
    encoded.extend_from_slice(nonce.x_bytes());
    append_point(&mut encoded, nonce);
    append_point(&mut encoded, &transcript.raw_commitment);
    append_point(&mut encoded, &transcript.mask_commitment);
    append_scalar(&mut encoded, &transcript.t2)?;
    encoded.extend_from_slice(transcript.dlog_nonce.x_bytes());
    append_scalar(&mut encoded, &transcript.dlog_response)?;
    for pair in &transcript.rounds {
        encoded.push(NovaByte::from_constrained_bits_le([
            pair.second.odd().clone(),
            pair.first.odd().clone(),
            nova_snark::frontend::gadgets::boolean::Boolean::constant(false),
            nova_snark::frontend::gadgets::boolean::Boolean::constant(false),
            nova_snark::frontend::gadgets::boolean::Boolean::constant(false),
            nova_snark::frontend::gadgets::boolean::Boolean::constant(false),
            nova_snark::frontend::gadgets::boolean::Boolean::constant(false),
            nova_snark::frontend::gadgets::boolean::Boolean::constant(false),
        ]));
        encoded.extend_from_slice(pair.first.x_bytes());
        encoded.extend_from_slice(pair.second.x_bytes());
    }
    append_scalar(&mut encoded, &transcript.terminal_n)?;
    append_scalar(&mut encoded, &transcript.terminal_l)?;
    if encoded.len() != CERTIFICATE_NONCE_PROOF_BYTES {
        return Err(synthesis_error("certificate nonce proof length"));
    }
    Ok(encoded)
}

fn constrain_leaf_binding<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    host: &[NovaByte; 64],
    topic: &[NovaByte; 32],
    proof_digest: &[NovaByte; 32],
    leaf: &DirectManifestBoundConstructionLeaf,
) -> Result<[NovaByte; 32], SynthesisError> {
    let mut encoded = Vec::with_capacity(64 + 32 + 32 + 32 + 33 + 32);
    encoded.extend_from_slice(host);
    encoded.extend_from_slice(topic);
    encoded.extend_from_slice(proof_digest);
    encoded.extend(scalar_bytes(&leaf.precommitment)?);
    append_point(
        &mut encoded,
        leaf.transcript
            .public_commitments
            .first()
            .ok_or_else(|| synthesis_error("certificate public commitment"))?,
    );
    encoded.extend(scalar_bytes(&leaf.transcript.prepared_binding)?);
    constrain_tagged_sha256(
        cs.namespace(|| "certificate leaf hash"),
        CERTIFICATE_NONCE_LEAF_TAG,
        &encoded,
    )
}

fn constrain_member_record<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    response_ordinal: &[NovaByte; 8],
    member_ordinal: &[NovaByte; 4],
    authorization_digest: &[NovaByte; 32],
    full_host: &[NovaByte],
    topic: &[NovaByte; 32],
    leaf: &DirectManifestBoundConstructionLeaf,
    leaf_binding: &[NovaByte; 32],
) -> Result<[NovaByte; 32], SynthesisError> {
    if full_host.len() != 96 {
        return Err(synthesis_error("certificate member host length"));
    }
    let mut encoded = Vec::with_capacity(8 + 4 + 32 + 96 + 32 + 32 + 33 + 33 + 32);
    encoded.extend_from_slice(response_ordinal);
    encoded.extend_from_slice(member_ordinal);
    encoded.extend_from_slice(authorization_digest);
    encoded.extend_from_slice(full_host);
    encoded.extend_from_slice(topic);
    encoded.extend_from_slice(&leaf.circuit_binding_digest);
    append_point(&mut encoded, &leaf.coefficient_commitment);
    append_point(&mut encoded, &leaf.anchored_offset);
    encoded.extend_from_slice(leaf_binding);
    constrain_tagged_sha256(
        cs.namespace(|| "certificate member hash"),
        CERTIFICATE_RECURSIVE_MEMBER_TAG,
        &encoded,
    )
}

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

#[cfg(test)]
mod tests {
    use std::{panic, thread};

    use nova_snark::{
        frontend::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError},
        traits::circuit::StepCircuit,
    };

    use super::*;
    use crate::certificate_nonce_proof::CertificateLeafParentConstantsWitness;
    use crate::certificate_parent_input::CertificateParentInputs;
    use crate::certificate_profile::{RECORD_MANIFEST_INDEX, RESPONSE_ORDINAL_INDEX};
    use crate::certificate_recursive_manifest::{recursive_manifest_seed, recursive_manifest_step};
    use crate::certificate_response_relation::native_step_digest;
    use crate::construction_parent_prover_binding::CheckingWitnessCs;
    use crate::nova_relation_identity::direct_step_relation_shape;
    use crate::secp_native::coordinate_field_value;

    const GENERATOR: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    const ACCEPTED_JOINED_WITNESS: &[u8] =
        include_bytes!("../tests/vectors/certificate_joined_witness_v2.bin");
    const ACCEPTED_JOINED_WITNESS_SHA256: [u8; 32] = [
        0x21, 0x14, 0x6d, 0x1a, 0x2c, 0x78, 0x20, 0x62, 0x88, 0xe7, 0x41, 0xef, 0xb5, 0x79, 0x95,
        0xda, 0xba, 0x87, 0x1f, 0x78, 0x7a, 0x25, 0xab, 0x85, 0x48, 0xe0, 0x11, 0x9c, 0xe5, 0x8c,
        0x48, 0xd5,
    ];

    fn decode_hex<const N: usize>(encoded: &str) -> [u8; N] {
        assert_eq!(encoded.len(), 2 * N);
        std::array::from_fn(|index| {
            u8::from_str_radix(&encoded[2 * index..2 * index + 2], 16).expect("test vector hex")
        })
    }

    #[test]
    fn native_member_record_matches_cpp_fixture() {
        let parent_constants = CertificateLeafParentConstantsWitness {
            circuit_binding_digest: decode_hex(
                "7b3bfc9496164ff840ba510baf986a814971e77a3c7fd71c650a9efe1edbd7d6",
            ),
            coefficient_commitment: SecpEncodedPointWitness::parse(decode_hex(
                "03c7abaebd9aea5d6b3284c5d06ea172253bab5c2d6f3d8d35a65c53c148d85efa",
            ))
            .expect("coefficient commitment"),
            anchored_offset: SecpEncodedPointWitness::parse(decode_hex(
                "0287b61ac5ba54700467325a16440f1f01fcab2775b55a986ad21c9c94fb629e0c",
            ))
            .expect("anchored offset"),
        };
        let digest = native_member_record_digest(
            0,
            0,
            decode_hex("79be0a07ab0749bc19cb8d2fd43b4f43fc9485d8e7bb366a6fce34b0bce1792b"),
            decode_hex(concat!(
                "512c8cb338e95981ddd219b66efb4c32ebe7bd448e8505d97e6d9b1e0b1acddb",
                "b3495a9d3a8dc4697c58182b76b9c7c8c443224d184cca14793c063c8db759ed",
                "1cc53d5f2f31ae932eb89e40a2621ae44d47a513841be6c7f17224aa83a7d6e9",
            )),
            decode_hex("9cbf85439bcbb4aac1a81824d7c1a5433b8c031af38270ef22acaf6bf544cc36"),
            parent_constants,
            decode_hex("d3eb172784ede6e7cc5ee50b40e70cc132a6d80769db5726afb9f90df32b70e0"),
        );
        assert_eq!(
            digest,
            decode_hex("2f42294f02933d5b2433b589b75248d0a8a66e4e98bed8944a93f880f81f9324",),
        );
    }

    #[test]
    fn native_member_record_framing_is_pinned() {
        let parent_constants = CertificateLeafParentConstantsWitness {
            circuit_binding_digest: [0x44; 32],
            coefficient_commitment: SecpEncodedPointWitness::parse(GENERATOR).expect("generator"),
            anchored_offset: SecpEncodedPointWitness::identity(),
        };
        let expected = native_member_record_digest(
            5,
            7,
            [0x11; 32],
            [0x22; 96],
            [0x33; 32],
            parent_constants,
            [0x55; 32],
        );
        assert_eq!(
            expected,
            [
                0x6f, 0x99, 0x41, 0x3e, 0x24, 0xbd, 0x81, 0xa4, 0x3f, 0x69, 0x13, 0x9e, 0x56, 0x8e,
                0x8a, 0x4c, 0x0d, 0x8d, 0x22, 0x0d, 0x1a, 0x49, 0x0a, 0x0b, 0x81, 0x4a, 0x85, 0xa5,
                0x25, 0x8b, 0x8f, 0x1b,
            ],
        );

        let mut changed_host = [0x22; 96];
        changed_host[95] ^= 1;
        assert_ne!(
            native_member_record_digest(
                5,
                7,
                [0x11; 32],
                changed_host,
                [0x33; 32],
                parent_constants,
                [0x55; 32],
            ),
            expected,
        );

        let mut changed_topic = [0x33; 32];
        changed_topic[31] ^= 1;
        assert_ne!(
            native_member_record_digest(
                5,
                7,
                [0x11; 32],
                [0x22; 96],
                changed_topic,
                parent_constants,
                [0x55; 32],
            ),
            expected,
        );

        let mut changed_constants = parent_constants;
        changed_constants.circuit_binding_digest[31] ^= 1;
        assert_ne!(
            native_member_record_digest(
                5,
                7,
                [0x11; 32],
                [0x22; 96],
                [0x33; 32],
                changed_constants,
                [0x55; 32],
            ),
            expected,
        );

        let mut changed_binding = [0x55; 32];
        changed_binding[31] ^= 1;
        assert_ne!(
            native_member_record_digest(
                5,
                7,
                [0x11; 32],
                [0x22; 96],
                [0x33; 32],
                parent_constants,
                changed_binding,
            ),
            expected,
        );
        assert_ne!(
            native_member_record_digest(
                6,
                7,
                [0x11; 32],
                [0x22; 96],
                [0x33; 32],
                parent_constants,
                [0x55; 32],
            ),
            expected,
        );
        assert_ne!(
            native_member_record_digest(
                5,
                8,
                [0x11; 32],
                [0x22; 96],
                [0x33; 32],
                parent_constants,
                [0x55; 32],
            ),
            expected,
        );
    }

    #[test]
    fn external_manifest_rejects_rogue_parent_constants() {
        let context = [0x66; 32];
        let authorization = [0x11; 32];
        let host = [0x22; 96];
        let topic = [0x33; 32];
        let leaf_binding = [0x55; 32];
        let response_binding = [0x77; 32];
        let signing_key = [0x78; 32];
        let response = [0x88; 32];
        let challenge = [0x99; 32];
        let constants = CertificateLeafParentConstantsWitness {
            circuit_binding_digest: [0x44; 32],
            coefficient_commitment: SecpEncodedPointWitness::parse(GENERATOR).expect("generator"),
            anchored_offset: SecpEncodedPointWitness::identity(),
        };
        let seed = recursive_manifest_seed(context, 1).expect("manifest seed");
        let accepted_record =
            native_member_record_digest(0, 0, authorization, host, topic, constants, leaf_binding);
        let accepted_step = native_step_digest(
            accepted_record,
            response_binding,
            1,
            signing_key,
            response,
            challenge,
        );
        let accepted_manifest =
            recursive_manifest_step(seed, 0, 0, accepted_step).expect("accepted manifest");
        let inputs = CertificateParentInputs::new(context, 1, 1, accepted_manifest)
            .expect("external certificate frame");
        let mut accepted_final = *inputs.initial_state();
        accepted_final[RECORD_MANIFEST_INDEX] =
            coordinate_field_value(accepted_manifest).expect("manifest field");
        accepted_final[RESPONSE_ORDINAL_INDEX] = Scalar::from(1);
        inputs
            .validate_authenticated_final_state(accepted_final)
            .expect("matching external manifest");

        let mut changed_binding = constants;
        changed_binding.circuit_binding_digest[0] ^= 1;
        let mut changed_coefficient = constants;
        changed_coefficient.coefficient_commitment =
            alternate_point(changed_coefficient.coefficient_commitment);
        let mut changed_offset = constants;
        changed_offset.anchored_offset = alternate_point(changed_offset.anchored_offset);

        // The leaf binding stays fixed here deliberately. Each otherwise
        // witness-selected parent constant must still change the public
        // record manifest checked after recursive proof verification.
        for rogue_constants in [changed_binding, changed_coefficient, changed_offset] {
            let rogue_record = native_member_record_digest(
                0,
                0,
                authorization,
                host,
                topic,
                rogue_constants,
                leaf_binding,
            );
            assert_ne!(rogue_record, accepted_record);
            let rogue_step = native_step_digest(
                rogue_record,
                response_binding,
                1,
                signing_key,
                response,
                challenge,
            );
            assert_ne!(rogue_step, accepted_step);
            let rogue_manifest =
                recursive_manifest_step(seed, 0, 0, rogue_step).expect("rogue manifest");
            assert_ne!(rogue_manifest, accepted_manifest);

            let mut rogue_final = accepted_final;
            rogue_final[RECORD_MANIFEST_INDEX] =
                coordinate_field_value(rogue_manifest).expect("rogue manifest field");
            assert!(inputs
                .validate_authenticated_final_state(rogue_final)
                .is_err());
        }
    }

    #[test]
    fn host_signing_key_requires_a_valid_even_point() {
        assert!(parse_host_signing_key([0; 96]).is_err());

        let mut host = [0; 96];
        host[64..].copy_from_slice(&GENERATOR[1..]);
        assert_eq!(
            parse_host_signing_key(host)
                .expect("valid host signing key")
                .encoded,
            GENERATOR,
        );
    }

    #[derive(Clone)]
    struct LeafShapeStep {
        witness: CertificateMemberLeafWitness,
    }

    impl StepCircuit<Scalar> for LeafShapeStep {
        fn arity(&self) -> usize {
            1
        }

        fn synthesize<CS: ConstraintSystem<Scalar>>(
            &self,
            cs: &mut CS,
            state: &[AllocatedNum<Scalar>],
        ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
            if state.len() != 1 {
                return Err(synthesis_error("certificate leaf test state"));
            }
            constrain_certificate_member_leaf(
                cs.namespace(|| "certificate member leaf"),
                &self.witness,
            )?;
            Ok(vec![state[0].clone()])
        }
    }

    struct CheckedLeaf {
        auxiliary: usize,
        constraints: usize,
        unsatisfied: Option<usize>,
        record_digest: [u8; 32],
        nonce_point: [u8; 33],
    }

    fn check_leaf(
        witness: &CertificateMemberLeafWitness,
        auxiliary_capacity: usize,
    ) -> CheckedLeaf {
        let mut cs = CheckingWitnessCs::with_auxiliary_capacity(auxiliary_capacity);
        let output =
            constrain_certificate_member_leaf(cs.namespace(|| "certificate member leaf"), witness)
                .expect("certificate member leaf synthesis");
        let mut nonce_point = [0; 33];
        nonce_point[0] = output.nonce_point.prefix_byte().value();
        nonce_point[1..]
            .copy_from_slice(&output.nonce_point.x_bytes().each_ref().map(NovaByte::value));
        CheckedLeaf {
            auxiliary: cs.auxiliary_len(),
            constraints: cs.constraint_count(),
            unsatisfied: cs.first_unsatisfied(),
            record_digest: output.record_digest.each_ref().map(NovaByte::value),
            nonce_point,
        }
    }

    fn alternate_point(point: SecpEncodedPointWitness) -> SecpEncodedPointWitness {
        if point.encoded == [0; 33] {
            return SecpEncodedPointWitness::parse(GENERATOR).expect("generator");
        }
        let mut encoded = point.encoded;
        encoded[0] = 5 - encoded[0];
        SecpEncodedPointWitness::parse(encoded).expect("opposite point")
    }

    fn alternate_host_key(current: SecpEncodedPointWitness) -> SecpEncodedPointWitness {
        const TWICE_GENERATOR: [u8; 33] = [
            0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
            0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
            0xb9, 0x5c, 0x70, 0x9e, 0xe5,
        ];
        let alternate = if current.encoded == TWICE_GENERATOR {
            GENERATOR
        } else {
            TWICE_GENERATOR
        };
        SecpEncodedPointWitness::parse(alternate).expect("alternate host key")
    }

    #[test]
    #[ignore = "full production certificate relation takes about five minutes"]
    fn real_member_leaf_binds_every_record_and_parent_input() {
        let worker = thread::Builder::new()
            .name("certificate-member-leaf".to_owned())
            .stack_size(64 * 1024 * 1024)
            .spawn(run_real_member_leaf_harness)
            .expect("certificate member leaf worker");
        if let Err(payload) = worker.join() {
            panic::resume_unwind(payload);
        }
    }

    fn run_real_member_leaf_harness() {
        assert_eq!(ACCEPTED_JOINED_WITNESS.len(), 13_782);
        let fixture_digest: [u8; 32] = Sha256::digest(ACCEPTED_JOINED_WITNESS).into();
        assert_eq!(fixture_digest, ACCEPTED_JOINED_WITNESS_SHA256);
        let joined = CertificateJoinedWitness::parse(ACCEPTED_JOINED_WITNESS)
            .expect("accepted joined certificate fixture");
        let witness = CertificateMemberLeafWitness::from_joined(&joined, 0, 0)
            .expect("certificate member witness");
        let expected_nonce = joined.responses()[0].members()[0].nonce_point().encoded;

        let shape = direct_step_relation_shape::<1, _>(&LeafShapeStep {
            witness: witness.clone(),
        })
        .expect("certificate member relation shape");
        let checked = check_leaf(&witness, shape.auxiliary());
        assert_eq!(checked.unsatisfied, None);
        assert_eq!(checked.auxiliary, shape.auxiliary());
        assert_eq!(checked.constraints, shape.constraints());
        assert_eq!(checked.record_digest, witness.expected_record_digest(),);
        assert_eq!(checked.nonce_point, expected_nonce);

        let mut record_mutation = witness.clone();
        record_mutation.response_ordinal ^= 1;
        record_mutation.member_ordinal ^= 1;
        record_mutation.authorization_digest[0] ^= 1;
        record_mutation.host[0] ^= 1;
        record_mutation.topic[0] ^= 1;
        record_mutation.host_signing_key = alternate_host_key(record_mutation.host_signing_key);
        record_mutation.host[64..].copy_from_slice(&record_mutation.host_signing_key.encoded[1..]);
        let mutated_shape = direct_step_relation_shape::<1, _>(&LeafShapeStep {
            witness: record_mutation.clone(),
        })
        .expect("mutated certificate member relation shape");
        assert_eq!(shape, mutated_shape);
        let checked_mutation = check_leaf(&record_mutation, shape.auxiliary());
        assert_eq!(checked_mutation.unsatisfied, None);
        assert_ne!(
            checked_mutation.record_digest,
            witness.expected_record_digest(),
        );
        assert_eq!(checked_mutation.auxiliary, checked.auxiliary);
        assert_eq!(checked_mutation.constraints, checked.constraints);

        let mut binding_mutation = witness.clone();
        binding_mutation.circuit_binding_digest[0] ^= 1;
        let mut coefficient_mutation = witness.clone();
        coefficient_mutation.transcript.coefficient_commitment =
            alternate_point(coefficient_mutation.transcript.coefficient_commitment);
        let mut offset_mutation = witness.clone();
        offset_mutation.transcript.anchored_offset =
            alternate_point(offset_mutation.transcript.anchored_offset);
        for mutation in [binding_mutation, coefficient_mutation, offset_mutation] {
            let checked_mutation = check_leaf(&mutation, shape.auxiliary());
            assert!(checked_mutation.unsatisfied.is_some());
            assert_eq!(checked_mutation.auxiliary, checked.auxiliary);
            assert_eq!(checked_mutation.constraints, checked.constraints,);
        }
    }
}
