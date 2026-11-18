//! Strict syntax decoder for accepted certificate-parent prover witnesses.
//!
//! The C++ exporter emits bytes only after native verification and decision.
//! Parsing those bytes here preserves their exact response/proof/receipt joins,
//! but does not inherit that acceptance or verify any cryptographic relation.

use crate::certificate_authorization::{
    authorization_manifest_seed, authorization_manifest_step, member_authorization_digest,
    nonce_proof_digest, response_authorization_digest, response_binding_digest,
    response_common_digest, response_statement_digest, RESPONSE_MEMBER_DESCRIPTOR_BYTES,
};
use crate::certificate_native_witness::CertificateNativeReceiptWitness;
use crate::certificate_profile::{
    CertificateResponseBoundary, CertificateWitnessFrame, CERTIFICATE_LEAF_ROUNDS,
    CERTIFICATE_MAX_RESPONSES, CERTIFICATE_MEMBER_BATCH_CAPACITY, CERTIFICATE_NONCE_PROOF_BYTES,
};
use crate::circuit_transcript::CircuitPointPairWitnessV4;
use crate::secp_native::{canonical_scalar_value, SecpEncodedPointWitness, SecpScalarWitness};
use crate::RelationError;

const MAGIC: &[u8; 16] = b"Purify/CertJWit1";
const PUBLIC_INPUT_VERSION: u8 = 1;
const ACCOUNTABLE_TOPIC_SCOPE: u8 = 1;
const NONCE_PROOF_VERSION: u8 = 4;

const MEMBER_STATEMENT_BYTES: usize = RESPONSE_MEMBER_DESCRIPTOR_BYTES + 32 + 32 + 32 + 33;
const MINIMUM_STATEMENT_BYTES: usize = 575;
const MINIMUM_JOINED_RESPONSE_BYTES: usize =
    8 + MINIMUM_STATEMENT_BYTES + 4 + CERTIFICATE_NONCE_PROOF_BYTES;

/// One response member joined to its exact canonical V4 nonce proof.
pub(crate) struct CertificateJoinedMemberWitness {
    roster_public_key: [u8; 33],
    coefficient: SecpScalarWitness,
    host: [u8; 96],
    leaf_binding: [u8; 32],
    proof_digest: [u8; 32],
    circuit_precommitment: SecpScalarWitness,
    nonce_point: SecpEncodedPointWitness,
    authorization_digest: [u8; 32],
    nonce_proof: [u8; CERTIFICATE_NONCE_PROOF_BYTES],
}

impl CertificateJoinedMemberWitness {
    pub(crate) const fn roster_public_key(&self) -> [u8; 33] {
        self.roster_public_key
    }

    pub(crate) const fn coefficient(&self) -> SecpScalarWitness {
        self.coefficient
    }

    pub(crate) const fn host(&self) -> [u8; 96] {
        self.host
    }

    pub(crate) const fn leaf_binding(&self) -> [u8; 32] {
        self.leaf_binding
    }

    pub(crate) const fn proof_digest(&self) -> [u8; 32] {
        self.proof_digest
    }

    pub(crate) const fn circuit_precommitment(&self) -> SecpScalarWitness {
        self.circuit_precommitment
    }

    pub(crate) const fn nonce_point(&self) -> SecpEncodedPointWitness {
        self.nonce_point
    }

    pub(crate) const fn authorization_digest(&self) -> [u8; 32] {
        self.authorization_digest
    }

    pub(crate) const fn nonce_proof(&self) -> &[u8; CERTIFICATE_NONCE_PROOF_BYTES] {
        &self.nonce_proof
    }
}

/// One canonical response statement and all of its exact raw nonce proofs.
pub(crate) struct CertificateJoinedResponseWitness {
    boundary: CertificateResponseBoundary,
    electorate_index: u32,
    electorate_weight: u64,
    signing_key: [u8; 32],
    host_commitment: [u8; 32],
    coalition_core_digest: [u8; 32],
    slot: Vec<u8>,
    canonical_body: Vec<u8>,
    response: SecpScalarWitness,
    key_list_hash: [u8; 32],
    aggregate_was_negated: bool,
    common_digest: [u8; 32],
    authorization_digest: [u8; 32],
    response_binding: [u8; 32],
    statement_digest: [u8; 32],
    members: Vec<CertificateJoinedMemberWitness>,
    aggregate_nonce: SecpEncodedPointWitness,
}

impl CertificateJoinedResponseWitness {
    pub(crate) const fn boundary(&self) -> CertificateResponseBoundary {
        self.boundary
    }

    pub(crate) fn members(&self) -> &[CertificateJoinedMemberWitness] {
        &self.members
    }

    pub(crate) const fn electorate_index(&self) -> u32 {
        self.electorate_index
    }

    pub(crate) const fn electorate_weight(&self) -> u64 {
        self.electorate_weight
    }

    pub(crate) const fn signing_key(&self) -> [u8; 32] {
        self.signing_key
    }

    pub(crate) const fn host_commitment(&self) -> [u8; 32] {
        self.host_commitment
    }

    pub(crate) const fn coalition_core_digest(&self) -> [u8; 32] {
        self.coalition_core_digest
    }

    pub(crate) fn slot(&self) -> &[u8] {
        &self.slot
    }

    pub(crate) fn canonical_body(&self) -> &[u8] {
        &self.canonical_body
    }

    pub(crate) const fn response(&self) -> SecpScalarWitness {
        self.response
    }

    pub(crate) const fn key_list_hash(&self) -> [u8; 32] {
        self.key_list_hash
    }

    pub(crate) const fn aggregate_was_negated(&self) -> bool {
        self.aggregate_was_negated
    }

    pub(crate) const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    pub(crate) const fn common_digest(&self) -> [u8; 32] {
        self.common_digest
    }

    pub(crate) const fn authorization_digest(&self) -> [u8; 32] {
        self.authorization_digest
    }

    pub(crate) const fn response_binding(&self) -> [u8; 32] {
        self.response_binding
    }

    pub(crate) const fn aggregate_nonce(&self) -> SecpEncodedPointWitness {
        self.aggregate_nonce
    }
}

/// Canonical joined prover input after all public framing cross-checks.
pub(crate) struct CertificateJoinedWitness {
    frame: CertificateWitnessFrame,
    responses: Vec<CertificateJoinedResponseWitness>,
    authorization_manifest: [u8; 32],
    native_receipt: CertificateNativeReceiptWitness,
}

impl CertificateJoinedWitness {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, RelationError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.array::<16>()? != *MAGIC {
            return Err(RelationError::Malformed("certificate joined witness magic"));
        }
        let response_count = cursor.u64()?;
        if response_count == 0 || response_count > CERTIFICATE_MAX_RESPONSES {
            return Err(RelationError::Malformed(
                "certificate joined response count",
            ));
        }
        let response_count_usize = usize::try_from(response_count)
            .map_err(|_| RelationError::Malformed("certificate joined response count"))?;
        if response_count_usize > cursor.remaining() / MINIMUM_JOINED_RESPONSE_BYTES {
            return Err(RelationError::Malformed(
                "certificate joined response bytes",
            ));
        }

        let mut responses = Vec::with_capacity(response_count_usize);
        for ordinal in 0..response_count {
            let statement_length = cursor.usize_u64("certificate joined statement length")?;
            if statement_length < MINIMUM_STATEMENT_BYTES {
                return Err(RelationError::Malformed(
                    "certificate joined statement length",
                ));
            }
            let statement_bytes = cursor.take(statement_length)?;
            let parsed = parse_response_statement(statement_bytes, response_count, ordinal)?;

            let proof_count = cursor.u32()?;
            if proof_count != parsed.boundary.member_count() {
                return Err(RelationError::Malformed("certificate joined proof count"));
            }
            let proof_count_usize = usize::try_from(proof_count)
                .map_err(|_| RelationError::Malformed("certificate joined proof count"))?;
            let proof_bytes = proof_count_usize
                .checked_mul(CERTIFICATE_NONCE_PROOF_BYTES)
                .ok_or(RelationError::Malformed("certificate joined proof bytes"))?;
            if cursor.remaining() < proof_bytes {
                return Err(RelationError::Malformed(
                    "truncated certificate joined proof bytes",
                ));
            }

            let mut members = Vec::with_capacity(proof_count_usize);
            for parsed_member in parsed.members {
                let nonce_proof = cursor.array::<CERTIFICATE_NONCE_PROOF_BYTES>()?;
                let proof_nonce = parse_nonce_proof(&nonce_proof)?;
                if proof_nonce != parsed_member.nonce_point
                    || nonce_proof_digest(&nonce_proof) != parsed_member.proof_digest
                {
                    return Err(RelationError::Malformed(
                        "certificate joined nonce proof binding",
                    ));
                }
                members.push(CertificateJoinedMemberWitness {
                    roster_public_key: parsed_member.roster_public_key,
                    coefficient: parsed_member.coefficient,
                    host: parsed_member.host,
                    leaf_binding: parsed_member.leaf_binding,
                    proof_digest: parsed_member.proof_digest,
                    circuit_precommitment: parsed_member.circuit_precommitment,
                    nonce_point: parsed_member.nonce_point,
                    authorization_digest: parsed_member.authorization_digest,
                    nonce_proof,
                });
            }
            responses.push(CertificateJoinedResponseWitness {
                boundary: parsed.boundary,
                electorate_index: parsed.electorate_index,
                electorate_weight: parsed.electorate_weight,
                signing_key: parsed.signing_key,
                host_commitment: parsed.host_commitment,
                coalition_core_digest: parsed.coalition_core_digest,
                slot: parsed.slot,
                canonical_body: parsed.canonical_body,
                response: parsed.response,
                key_list_hash: parsed.key_list_hash,
                aggregate_was_negated: parsed.aggregate_was_negated,
                common_digest: parsed.common_digest,
                authorization_digest: parsed.authorization_digest,
                response_binding: parsed.response_binding,
                statement_digest: parsed.statement_digest,
                members,
                aggregate_nonce: parsed.aggregate_nonce,
            });
        }

        let receipt_length = cursor.usize_u64("certificate joined receipt length")?;
        if receipt_length != cursor.remaining() {
            return Err(RelationError::Malformed("certificate joined receipt bytes"));
        }
        let native_receipt = CertificateNativeReceiptWitness::parse(cursor.take(receipt_length)?)?;
        cursor.finish()?;

        let frame = responses
            .first()
            .ok_or(RelationError::Malformed("empty certificate joined witness"))?
            .boundary
            .frame();
        if native_receipt.frame() != frame || native_receipt.responses().len() != responses.len() {
            return Err(RelationError::Malformed("certificate joined receipt frame"));
        }
        for (response, native) in responses.iter().zip(native_receipt.responses()) {
            if native.boundary() != response.boundary
                || native.statement_digest() != response.statement_digest
                || native.reductions().len() != response.members.len()
            {
                return Err(RelationError::Malformed(
                    "certificate joined receipt response",
                ));
            }
        }

        let mut authorization_manifest = authorization_manifest_seed(
            frame.certificate_context_digest(),
            frame.total_responses(),
        )?;
        for response in &responses {
            for (member_ordinal, member) in response.members.iter().enumerate() {
                authorization_manifest = authorization_manifest_step(
                    authorization_manifest,
                    response.boundary.ordinal(),
                    u32::try_from(member_ordinal).map_err(|_| {
                        RelationError::Malformed("certificate joined member ordinal")
                    })?,
                    member.authorization_digest,
                )?;
            }
        }

        Ok(Self {
            frame,
            responses,
            authorization_manifest,
            native_receipt,
        })
    }

    pub(crate) const fn frame(&self) -> CertificateWitnessFrame {
        self.frame
    }

    pub(crate) fn responses(&self) -> &[CertificateJoinedResponseWitness] {
        &self.responses
    }

    pub(crate) const fn authorization_manifest(&self) -> [u8; 32] {
        self.authorization_manifest
    }

    pub(crate) const fn native_receipt(&self) -> &CertificateNativeReceiptWitness {
        &self.native_receipt
    }
}

struct ParsedResponseStatement {
    boundary: CertificateResponseBoundary,
    electorate_index: u32,
    electorate_weight: u64,
    signing_key: [u8; 32],
    host_commitment: [u8; 32],
    coalition_core_digest: [u8; 32],
    slot: Vec<u8>,
    canonical_body: Vec<u8>,
    response: SecpScalarWitness,
    key_list_hash: [u8; 32],
    aggregate_was_negated: bool,
    common_digest: [u8; 32],
    authorization_digest: [u8; 32],
    response_binding: [u8; 32],
    statement_digest: [u8; 32],
    members: Vec<ParsedResponseMember>,
    aggregate_nonce: SecpEncodedPointWitness,
}

struct ParsedResponseMember {
    roster_public_key: [u8; 33],
    coefficient: SecpScalarWitness,
    host: [u8; 96],
    leaf_binding: [u8; 32],
    proof_digest: [u8; 32],
    circuit_precommitment: SecpScalarWitness,
    nonce_point: SecpEncodedPointWitness,
    authorization_digest: [u8; 32],
}

fn parse_response_statement(
    encoded: &[u8],
    expected_total: u64,
    expected_ordinal: u64,
) -> Result<ParsedResponseStatement, RelationError> {
    let mut cursor = Cursor::new(encoded);
    if cursor.u8()? != PUBLIC_INPUT_VERSION
        || cursor.u8()? != ACCOUNTABLE_TOPIC_SCOPE
        || cursor.u32()? != CERTIFICATE_MEMBER_BATCH_CAPACITY
    {
        return Err(RelationError::Malformed(
            "certificate response public frame",
        ));
    }
    let context_digest = cursor.array::<32>()?;
    let total_responses = cursor.u64()?;
    let response_ordinal = cursor.u64()?;
    let frame = CertificateWitnessFrame::new(context_digest, total_responses)?;
    if total_responses != expected_total || response_ordinal != expected_ordinal {
        return Err(RelationError::Malformed("certificate response outer frame"));
    }
    let electorate_index = cursor.u32()?;
    let electorate_weight = cursor.u64()?;
    if electorate_weight == 0 {
        return Err(RelationError::Malformed(
            "certificate response electorate weight",
        ));
    }
    let signing_key = cursor.array::<32>()?;
    parse_xonly(signing_key)?;
    let host_commitment = cursor.array::<32>()?;
    let coalition_core_digest = cursor.array::<32>()?;
    let slot_length = cursor.usize_u64("certificate response slot length")?;
    if slot_length == 0 {
        return Err(RelationError::Malformed("empty certificate response slot"));
    }
    let slot = cursor.take(slot_length)?.to_vec();
    let body_length = cursor.usize_u64("certificate response body length")?;
    let canonical_body = cursor.take(body_length)?.to_vec();
    let response = parse_scalar(cursor.array::<32>()?)?;
    let key_list_hash = cursor.array::<32>()?;
    let aggregate_was_negated = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(RelationError::Malformed(
                "certificate response aggregate parity",
            ));
        }
    };
    let member_count = cursor.u32()?;
    let boundary = frame.response(response_ordinal, member_count)?;
    let member_count_usize = usize::try_from(member_count)
        .map_err(|_| RelationError::Malformed("certificate response member count"))?;
    let expected_tail = member_count_usize
        .checked_mul(MEMBER_STATEMENT_BYTES)
        .and_then(|size| size.checked_add(33))
        .ok_or(RelationError::Malformed(
            "certificate response member bytes",
        ))?;
    if cursor.remaining() != expected_tail {
        return Err(RelationError::Malformed(
            "certificate response statement bytes",
        ));
    }

    let common_digest = response_common_digest(&encoded[..cursor.offset()]);
    let mut authorization_bytes = Vec::with_capacity(
        cursor
            .offset()
            .checked_add(member_count_usize * RESPONSE_MEMBER_DESCRIPTOR_BYTES)
            .ok_or(RelationError::Malformed(
                "certificate response authorization bytes",
            ))?,
    );
    authorization_bytes.extend_from_slice(&encoded[..cursor.offset()]);
    let mut parsed_members = Vec::with_capacity(member_count_usize);
    let mut member_descriptors = Vec::with_capacity(member_count_usize);
    for member_ordinal in 0..member_count {
        let descriptor = cursor.array::<RESPONSE_MEMBER_DESCRIPTOR_BYTES>()?;
        if u32::from_be_bytes(descriptor[..4].try_into().expect("member index")) != member_ordinal {
            return Err(RelationError::Malformed(
                "certificate response member ordinal",
            ));
        }
        let roster_public_key: [u8; 33] = descriptor[4..37].try_into().expect("roster public key");
        parse_finite_point(roster_public_key)?;
        let coefficient = parse_nonzero_scalar(
            descriptor[37..69].try_into().expect("member coefficient"),
            "zero certificate roster coefficient",
        )?;
        let host: [u8; 96] = descriptor[69..].try_into().expect("member host");
        parse_xonly(host[64..].try_into().expect("host BIP340 key"))?;
        authorization_bytes.extend_from_slice(&descriptor);
        member_descriptors.push(descriptor);

        let leaf_binding = cursor.array::<32>()?;
        let proof_digest = cursor.array::<32>()?;
        let circuit_precommitment = parse_nonzero_scalar(
            cursor.array::<32>()?,
            "zero certificate circuit precommitment",
        )?;
        let nonce_point = parse_finite_point(cursor.array::<33>()?)?;
        parsed_members.push(ParsedResponseMember {
            roster_public_key,
            coefficient,
            host,
            leaf_binding,
            proof_digest,
            circuit_precommitment,
            nonce_point,
            authorization_digest: [0; 32],
        });
    }
    let aggregate_nonce = parse_finite_point(cursor.array::<33>()?)?;
    cursor.finish()?;

    let authorization_digest = response_authorization_digest(&authorization_bytes);
    let response_binding = response_binding_digest(common_digest, authorization_digest);
    for ((member, descriptor), member_ordinal) in parsed_members
        .iter_mut()
        .zip(member_descriptors.iter())
        .zip(0..member_count)
    {
        member.authorization_digest =
            member_authorization_digest(response_binding, response_ordinal, descriptor);
        debug_assert_eq!(
            u32::from_be_bytes(descriptor[..4].try_into().expect("member index")),
            member_ordinal
        );
    }

    Ok(ParsedResponseStatement {
        boundary,
        electorate_index,
        electorate_weight,
        signing_key,
        host_commitment,
        coalition_core_digest,
        slot,
        canonical_body,
        response,
        key_list_hash,
        aggregate_was_negated,
        common_digest,
        authorization_digest,
        response_binding,
        statement_digest: response_statement_digest(encoded),
        members: parsed_members,
        aggregate_nonce,
    })
}

fn parse_nonce_proof(
    encoded: &[u8; CERTIFICATE_NONCE_PROOF_BYTES],
) -> Result<SecpEncodedPointWitness, RelationError> {
    if encoded[0] != NONCE_PROOF_VERSION {
        return Err(RelationError::Malformed("certificate nonce proof version"));
    }
    let nonce_x: [u8; 32] = encoded[1..33].try_into().expect("nonce x");
    parse_xonly(nonce_x)?;
    let commitment = parse_finite_point(encoded[33..66].try_into().expect("nonce commitment"))?;
    if commitment.encoded[1..] != nonce_x {
        return Err(RelationError::Malformed(
            "certificate nonce proof commitment",
        ));
    }
    parse_finite_point(encoded[66..99].try_into().expect("raw commitment"))?;
    parse_finite_point(encoded[99..132].try_into().expect("mask commitment"))?;
    parse_scalar(encoded[132..164].try_into().expect("t2 scalar"))?;
    parse_xonly(encoded[164..196].try_into().expect("DLog nonce"))?;
    parse_nonzero_scalar(
        encoded[196..228].try_into().expect("DLog response"),
        "zero certificate DLog response",
    )?;

    let mut offset = 228;
    for _ in 0..CERTIFICATE_LEAF_ROUNDS {
        parse_pair(encoded[offset..offset + 65].try_into().expect("norm pair"))?;
        offset += 65;
    }
    parse_scalar(encoded[offset..offset + 32].try_into().expect("terminal n"))?;
    offset += 32;
    parse_scalar(encoded[offset..offset + 32].try_into().expect("terminal l"))?;
    offset += 32;
    if offset != encoded.len() {
        return Err(RelationError::Malformed("certificate nonce proof length"));
    }
    Ok(commitment)
}

fn parse_pair(encoded: [u8; 65]) -> Result<CircuitPointPairWitnessV4, RelationError> {
    if encoded[0] > 3 {
        return Err(RelationError::Malformed("certificate V4 point pair"));
    }
    let first = parse_pair_point(&encoded, 0)?;
    let second = parse_pair_point(&encoded, 1)?;
    Ok(CircuitPointPairWitnessV4 {
        encoded,
        first_y: first.y,
        second_y: second.y,
    })
}

fn parse_pair_point(
    pair: &[u8; 65],
    index: usize,
) -> Result<SecpEncodedPointWitness, RelationError> {
    let offset = 1 + index * 32;
    let x = &pair[offset..offset + 32];
    let parity_mask = 2u8 >> index;
    if x == [0; 32] {
        if pair[0] & parity_mask != 0 {
            return Err(RelationError::Malformed("signed certificate pair identity"));
        }
        return Ok(SecpEncodedPointWitness::identity());
    }
    let mut encoded = [0; 33];
    encoded[0] = 2 + u8::from(pair[0] & parity_mask != 0);
    encoded[1..].copy_from_slice(x);
    SecpEncodedPointWitness::parse(encoded)
}

fn parse_xonly(encoded: [u8; 32]) -> Result<SecpEncodedPointWitness, RelationError> {
    let mut point = [0; 33];
    point[0] = 2;
    point[1..].copy_from_slice(&encoded);
    parse_finite_point(point)
}

fn parse_finite_point(encoded: [u8; 33]) -> Result<SecpEncodedPointWitness, RelationError> {
    let point = SecpEncodedPointWitness::parse(encoded)?;
    if point.encoded == [0; 33] {
        return Err(RelationError::Malformed("identity certificate point"));
    }
    Ok(point)
}

fn parse_scalar(encoded: [u8; 32]) -> Result<SecpScalarWitness, RelationError> {
    let scalar = SecpScalarWitness::from_bytes_be(encoded);
    canonical_scalar_value(scalar)?;
    Ok(scalar)
}

fn parse_nonzero_scalar(
    encoded: [u8; 32],
    label: &'static str,
) -> Result<SecpScalarWitness, RelationError> {
    let scalar = parse_scalar(encoded)?;
    if scalar.bytes == [0; 32] {
        return Err(RelationError::Malformed(label));
    }
    Ok(scalar)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    const fn offset(&self) -> usize {
        self.offset
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RelationError> {
        self.take(N)?
            .try_into()
            .map_err(|_| RelationError::Malformed("certificate joined fixed bytes"))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RelationError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RelationError::Malformed(
                "certificate joined witness overflow",
            ))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(RelationError::Malformed(
                "truncated certificate joined witness",
            ))?;
        self.offset = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, RelationError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, RelationError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, RelationError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn usize_u64(&mut self, label: &'static str) -> Result<usize, RelationError> {
        usize::try_from(self.u64()?).map_err(|_| RelationError::Malformed(label))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn finish(self) -> Result<(), RelationError> {
        if self.offset != self.bytes.len() {
            return Err(RelationError::Malformed(
                "trailing certificate joined witness bytes",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate_profile::{
        CERTIFICATE_PARENT_BASIS_DIGEST, CERTIFICATE_REDUCTION_PROOF_BYTES,
        CERTIFICATE_STEP_PROOF_BYTES,
    };

    const GENERATOR_X: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];
    const CONTEXT: [u8; 32] = [0x11; 32];

    fn generator() -> [u8; 33] {
        let mut encoded = [0; 33];
        encoded[0] = 2;
        encoded[1..].copy_from_slice(&GENERATOR_X);
        encoded
    }

    fn scalar(value: u8) -> [u8; 32] {
        let mut encoded = [0; 32];
        encoded[31] = value;
        encoded
    }

    fn push_u32(encoded: &mut Vec<u8>, value: u32) {
        encoded.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u64(encoded: &mut Vec<u8>, value: u64) {
        encoded.extend_from_slice(&value.to_be_bytes());
    }

    fn nonce_proof() -> [u8; CERTIFICATE_NONCE_PROOF_BYTES] {
        let mut encoded = [0; CERTIFICATE_NONCE_PROOF_BYTES];
        encoded[0] = NONCE_PROOF_VERSION;
        encoded[1..33].copy_from_slice(&GENERATOR_X);
        encoded[33..66].copy_from_slice(&generator());
        encoded[66..99].copy_from_slice(&generator());
        encoded[99..132].copy_from_slice(&generator());
        encoded[164..196].copy_from_slice(&GENERATOR_X);
        encoded[196..228].copy_from_slice(&scalar(1));
        encoded
    }

    fn response_statement(proof: &[u8; CERTIFICATE_NONCE_PROOF_BYTES]) -> (Vec<u8>, usize) {
        let mut encoded = Vec::new();
        encoded.push(PUBLIC_INPUT_VERSION);
        encoded.push(ACCOUNTABLE_TOPIC_SCOPE);
        push_u32(&mut encoded, CERTIFICATE_MEMBER_BATCH_CAPACITY);
        encoded.extend_from_slice(&CONTEXT);
        push_u64(&mut encoded, 1);
        push_u64(&mut encoded, 0);
        push_u32(&mut encoded, 7);
        push_u64(&mut encoded, 50);
        encoded.extend_from_slice(&GENERATOR_X);
        encoded.extend_from_slice(&[0x22; 32]);
        encoded.extend_from_slice(&[0x33; 32]);
        push_u64(&mut encoded, 1);
        encoded.push(0x44);
        push_u64(&mut encoded, 2);
        encoded.extend_from_slice(&[0x55, 0x56]);
        encoded.extend_from_slice(&scalar(1));
        encoded.extend_from_slice(&[0x66; 32]);
        encoded.push(0);
        push_u32(&mut encoded, 1);
        let descriptor_offset = encoded.len();
        push_u32(&mut encoded, 0);
        encoded.extend_from_slice(&generator());
        encoded.extend_from_slice(&scalar(1));
        encoded.extend_from_slice(&[0x77; 64]);
        encoded.extend_from_slice(&GENERATOR_X);
        encoded.extend_from_slice(&[0x88; 32]);
        encoded.extend_from_slice(&nonce_proof_digest(proof));
        encoded.extend_from_slice(&scalar(1));
        encoded.extend_from_slice(&generator());
        encoded.extend_from_slice(&generator());
        assert_eq!(encoded.len(), MINIMUM_STATEMENT_BYTES + 2);
        (encoded, descriptor_offset)
    }

    fn native_receipt(statement_digest: [u8; 32], member_count: u8) -> Vec<u8> {
        let mut reduction = [0; CERTIFICATE_REDUCTION_PROOF_BYTES];
        reduction[0] = 2;
        let mut step = [0; CERTIFICATE_STEP_PROOF_BYTES];
        step[0] = 2;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"Purify/CertWit/1");
        encoded.extend_from_slice(&CERTIFICATE_PARENT_BASIS_DIGEST);
        encoded.extend_from_slice(&CONTEXT);
        push_u64(&mut encoded, 1);
        encoded.extend_from_slice(&statement_digest);
        encoded.push(member_count);
        for _ in 0..member_count {
            encoded.extend_from_slice(&reduction);
        }
        encoded.extend_from_slice(&step);
        encoded
    }

    struct Fixture {
        encoded: Vec<u8>,
        statement_start: usize,
        descriptor_start: usize,
        proof_count_offset: usize,
        proof_start: usize,
        receipt_start: usize,
    }

    fn fixture() -> Fixture {
        let proof = nonce_proof();
        let (statement, descriptor_offset) = response_statement(&proof);
        let receipt = native_receipt(response_statement_digest(&statement), 1);
        let mut encoded = Vec::new();
        encoded.extend_from_slice(MAGIC);
        push_u64(&mut encoded, 1);
        push_u64(&mut encoded, statement.len() as u64);
        let statement_start = encoded.len();
        encoded.extend_from_slice(&statement);
        let proof_count_offset = encoded.len();
        push_u32(&mut encoded, 1);
        let proof_start = encoded.len();
        encoded.extend_from_slice(&proof);
        push_u64(&mut encoded, receipt.len() as u64);
        let receipt_start = encoded.len();
        encoded.extend_from_slice(&receipt);
        Fixture {
            encoded,
            statement_start,
            descriptor_start: statement_start + descriptor_offset,
            proof_count_offset,
            proof_start,
            receipt_start,
        }
    }

    #[test]
    fn parses_exact_response_proof_and_receipt_joins() {
        let fixture = fixture();
        let witness = CertificateJoinedWitness::parse(&fixture.encoded)
            .expect("canonical joined certificate witness");
        assert_eq!(witness.frame().certificate_context_digest(), CONTEXT);
        assert_eq!(witness.frame().total_responses(), 1);
        assert_eq!(witness.responses().len(), 1);
        assert_eq!(witness.native_receipt().responses().len(), 1);
        assert_eq!(witness.authorization_manifest()[0] & 0x80, 0);

        let response = &witness.responses()[0];
        assert_eq!(response.boundary().ordinal(), 0);
        assert_eq!(response.boundary().member_count(), 1);
        assert_eq!(
            response.statement_digest(),
            witness.native_receipt().responses()[0].statement_digest()
        );
        assert_eq!(response.electorate_index(), 7);
        assert_eq!(response.electorate_weight(), 50);
        assert_eq!(response.signing_key(), GENERATOR_X);
        assert_eq!(response.host_commitment(), [0x22; 32]);
        assert_eq!(response.coalition_core_digest(), [0x33; 32]);
        assert_eq!(response.slot(), [0x44]);
        assert_eq!(response.canonical_body(), [0x55, 0x56]);
        assert_eq!(response.response().bytes, scalar(1));
        assert_eq!(response.key_list_hash(), [0x66; 32]);
        assert!(!response.aggregate_was_negated());
        assert_eq!(response.aggregate_nonce().encoded, generator());
        assert_ne!(response.common_digest(), [0; 32]);
        assert_ne!(response.authorization_digest(), [0; 32]);
        assert_ne!(response.response_binding(), [0; 32]);

        let member = &response.members()[0];
        assert_eq!(member.roster_public_key(), generator());
        assert_eq!(member.coefficient().bytes, scalar(1));
        assert_eq!(&member.host()[..64], &[0x77; 64]);
        assert_eq!(&member.host()[64..], &GENERATOR_X);
        assert_eq!(member.leaf_binding(), [0x88; 32]);
        assert_eq!(
            member.proof_digest(),
            nonce_proof_digest(member.nonce_proof())
        );
        assert_eq!(member.circuit_precommitment().bytes, scalar(1));
        assert_eq!(member.nonce_point().encoded, generator());
        assert_ne!(member.authorization_digest(), [0; 32]);
    }

    #[test]
    fn rejects_outer_framing_and_unbounded_counts() {
        let fixture = fixture();

        let mut wrong_magic = fixture.encoded.clone();
        wrong_magic[0] ^= 1;
        assert!(CertificateJoinedWitness::parse(&wrong_magic).is_err());

        let mut impossible_count = fixture.encoded.clone();
        impossible_count[16..24].copy_from_slice(&CERTIFICATE_MAX_RESPONSES.to_be_bytes());
        assert!(CertificateJoinedWitness::parse(&impossible_count).is_err());

        let mut wrong_proof_count = fixture.encoded.clone();
        wrong_proof_count[fixture.proof_count_offset..fixture.proof_count_offset + 4]
            .copy_from_slice(&0u32.to_be_bytes());
        assert!(CertificateJoinedWitness::parse(&wrong_proof_count).is_err());

        let mut trailing = fixture.encoded;
        trailing.push(0);
        assert!(CertificateJoinedWitness::parse(&trailing).is_err());
    }

    #[test]
    fn rejects_response_proof_and_receipt_mismatches() {
        let fixture = fixture();

        let mut wrong_ordinal = fixture.encoded.clone();
        let ordinal_offset = fixture.statement_start + 1 + 1 + 4 + 32 + 8;
        wrong_ordinal[ordinal_offset..ordinal_offset + 8].copy_from_slice(&1u64.to_be_bytes());
        assert!(CertificateJoinedWitness::parse(&wrong_ordinal).is_err());

        let mut wrong_member_ordinal = fixture.encoded.clone();
        wrong_member_ordinal[fixture.descriptor_start..fixture.descriptor_start + 4]
            .copy_from_slice(&1u32.to_be_bytes());
        assert!(CertificateJoinedWitness::parse(&wrong_member_ordinal).is_err());

        let mut wrong_proof_version = fixture.encoded.clone();
        wrong_proof_version[fixture.proof_start] ^= 1;
        assert!(CertificateJoinedWitness::parse(&wrong_proof_version).is_err());

        let mut wrong_proof_digest = fixture.encoded.clone();
        wrong_proof_digest[fixture.proof_start + 163] ^= 1;
        assert!(CertificateJoinedWitness::parse(&wrong_proof_digest).is_err());

        let mut wrong_receipt_statement = fixture.encoded.clone();
        let receipt_statement_offset = fixture.receipt_start + 16 + 32 + 32 + 8;
        wrong_receipt_statement[receipt_statement_offset] ^= 1;
        assert!(CertificateJoinedWitness::parse(&wrong_receipt_statement).is_err());

        let receipt_context_offset = fixture.receipt_start + 16 + 32;
        let mut wrong_receipt_context = fixture.encoded.clone();
        wrong_receipt_context[receipt_context_offset] ^= 1;
        assert!(CertificateJoinedWitness::parse(&wrong_receipt_context).is_err());

        let statement = &fixture.encoded[fixture.statement_start..fixture.proof_count_offset];
        let receipt = native_receipt(response_statement_digest(statement), 2);
        let receipt_length_offset = fixture.receipt_start - 8;
        let mut wrong_reduction_count = fixture.encoded[..receipt_length_offset].to_vec();
        push_u64(&mut wrong_reduction_count, receipt.len() as u64);
        wrong_reduction_count.extend_from_slice(&receipt);
        assert!(CertificateJoinedWitness::parse(&wrong_reduction_count).is_err());
    }
}
