//! Strict decoder for the native certificate accumulator receipt.
//!
//! Parsing establishes only the canonical public witness syntax selected by
//! the certificate profile. It does not verify the nonce leaves, replay an
//! accumulation transition, decide the pending root, or accept a certificate.

use crate::candidate::CandidateStepProofWitness;
use crate::certificate_profile::{
    certificate_tree_step_count, CertificateResponseBoundary, CertificateWitnessFrame,
    CERTIFICATE_LEAF_ROUNDS, CERTIFICATE_MEMBER_BATCH_CAPACITY, CERTIFICATE_PARENT_BASIS_DIGEST,
    CERTIFICATE_REDUCTION_PROOF_BYTES, CERTIFICATE_ROOT_ROUNDS, CERTIFICATE_STEP_PROOF_BYTES,
};
use crate::circuit_norm::CandidateNormReductionProofWitness;
use crate::secp_native::{canonical_scalar_value, SecpEncodedPointWitness, SecpScalarWitness};
use crate::RelationError;

const MAGIC: &[u8; 16] = b"Purify/CertWit/1";
const HEADER_BYTES: usize = MAGIC.len() + 32 + 32 + 8;
const RESPONSE_HEADER_BYTES: usize = 32 + 1;
const REDUCTION_VERSION: u8 = 2;
const STEP_VERSION: u8 = 2;

/// One statement-bound response from the canonical native witness stream.
pub(crate) struct CertificateNativeResponseWitness {
    boundary: CertificateResponseBoundary,
    statement_digest: [u8; 32],
    reductions: Vec<CandidateNormReductionProofWitness>,
    step: CandidateStepProofWitness,
}

impl CertificateNativeResponseWitness {
    pub(crate) const fn boundary(&self) -> CertificateResponseBoundary {
        self.boundary
    }

    pub(crate) const fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    pub(crate) fn reductions(&self) -> &[CandidateNormReductionProofWitness] {
        &self.reductions
    }

    pub(crate) const fn step(&self) -> &CandidateStepProofWitness {
        &self.step
    }
}

/// Canonical native receipt after profile and secp syntax validation.
pub(crate) struct CertificateNativeReceiptWitness {
    frame: CertificateWitnessFrame,
    responses: Vec<CertificateNativeResponseWitness>,
    tree_steps: Vec<CandidateStepProofWitness>,
}

impl CertificateNativeReceiptWitness {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, RelationError> {
        if bytes.len() < HEADER_BYTES {
            return Err(RelationError::Malformed(
                "certificate native receipt header",
            ));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.array::<16>()? != *MAGIC {
            return Err(RelationError::Malformed("certificate native receipt magic"));
        }
        if cursor.array::<32>()? != CERTIFICATE_PARENT_BASIS_DIGEST {
            return Err(RelationError::Malformed(
                "certificate native receipt basis digest",
            ));
        }
        let context_digest = cursor.array::<32>()?;
        let response_count = u64::from_be_bytes(cursor.array::<8>()?);
        let frame = CertificateWitnessFrame::new(context_digest, response_count)?;
        let response_count_usize = usize::try_from(response_count)
            .map_err(|_| RelationError::Malformed("certificate native response count"))?;

        // Reject an impossible count before iterating or reserving. Each
        // response has at least one reduction.
        let minimum_response_bytes = RESPONSE_HEADER_BYTES
            .checked_add(CERTIFICATE_REDUCTION_PROOF_BYTES)
            .and_then(|size| size.checked_add(CERTIFICATE_STEP_PROOF_BYTES))
            .expect("fixed certificate response size fits usize");
        if response_count_usize > cursor.remaining() / minimum_response_bytes {
            return Err(RelationError::Malformed(
                "certificate native response bytes",
            ));
        }

        let mut responses = Vec::with_capacity(response_count_usize);
        for ordinal in 0..response_count {
            let statement_digest = cursor.array::<32>()?;
            if statement_digest == [0; 32] {
                return Err(RelationError::Malformed(
                    "empty certificate response statement",
                ));
            }
            let member_count = u32::from(cursor.array::<1>()?[0]);
            let boundary = frame.response(ordinal, member_count)?;
            let member_count_usize = usize::try_from(member_count)
                .map_err(|_| RelationError::Malformed("certificate native member count"))?;
            let mut reductions = Vec::with_capacity(member_count_usize);
            for _ in 0..member_count_usize {
                reductions.push(parse_certificate_reduction(
                    cursor.array::<CERTIFICATE_REDUCTION_PROOF_BYTES>()?,
                )?);
            }
            let step = parse_certificate_step(cursor.array::<CERTIFICATE_STEP_PROOF_BYTES>()?)?;
            responses.push(CertificateNativeResponseWitness {
                boundary,
                statement_digest,
                reductions,
                step,
            });
        }

        let tree_step_count = certificate_tree_step_count(response_count)?;
        let tree_step_count_usize = usize::try_from(tree_step_count)
            .map_err(|_| RelationError::Malformed("certificate native tree count"))?;
        let expected_tree_bytes = tree_step_count_usize
            .checked_mul(CERTIFICATE_STEP_PROOF_BYTES)
            .ok_or(RelationError::Malformed("certificate native tree bytes"))?;
        if cursor.remaining() != expected_tree_bytes {
            return Err(RelationError::Malformed("certificate native tree bytes"));
        }
        let mut tree_steps = Vec::with_capacity(tree_step_count_usize);
        for _ in 0..tree_step_count_usize {
            tree_steps.push(parse_certificate_step(
                cursor.array::<CERTIFICATE_STEP_PROOF_BYTES>()?,
            )?);
        }
        cursor.finish()?;
        Ok(Self {
            frame,
            responses,
            tree_steps,
        })
    }

    pub(crate) const fn frame(&self) -> CertificateWitnessFrame {
        self.frame
    }

    pub(crate) fn responses(&self) -> &[CertificateNativeResponseWitness] {
        &self.responses
    }

    pub(crate) fn tree_steps(&self) -> &[CandidateStepProofWitness] {
        &self.tree_steps
    }
}

pub(crate) fn parse_certificate_reduction(
    encoded: [u8; CERTIFICATE_REDUCTION_PROOF_BYTES],
) -> Result<CandidateNormReductionProofWitness, RelationError> {
    if encoded[0] != REDUCTION_VERSION {
        return Err(RelationError::Malformed(
            "certificate native reduction version",
        ));
    }
    let coefficient_evaluation = parse_scalar(
        encoded[1..33]
            .try_into()
            .expect("fixed certificate reduction evaluation"),
    )?;
    let mut left = Vec::with_capacity(CERTIFICATE_LEAF_ROUNDS);
    let mut right = Vec::with_capacity(CERTIFICATE_LEAF_ROUNDS);
    let mut offset = 33;
    for _ in 0..CERTIFICATE_LEAF_ROUNDS {
        left.push(parse_point(
            encoded[offset..offset + 33]
                .try_into()
                .expect("fixed certificate reduction left"),
        )?);
        offset += 33;
        right.push(parse_point(
            encoded[offset..offset + 33]
                .try_into()
                .expect("fixed certificate reduction right"),
        )?);
        offset += 33;
    }
    let terminal_scalar = parse_scalar(
        encoded[offset..offset + 32]
            .try_into()
            .expect("fixed certificate reduction terminal"),
    )?;
    offset += 32;
    let folded_generator = parse_point(
        encoded[offset..offset + 33]
            .try_into()
            .expect("fixed certificate reduction generator"),
    )?;
    if offset + 33 != encoded.len() {
        return Err(RelationError::Malformed(
            "certificate native reduction length",
        ));
    }
    Ok(CandidateNormReductionProofWitness {
        coefficient_evaluation,
        left,
        right,
        terminal_scalar,
        folded_generator,
    })
}

pub(crate) fn parse_certificate_step(
    encoded: [u8; CERTIFICATE_STEP_PROOF_BYTES],
) -> Result<CandidateStepProofWitness, RelationError> {
    if encoded[0] != STEP_VERSION {
        return Err(RelationError::Malformed("certificate native step version"));
    }
    let mut left = Vec::with_capacity(CERTIFICATE_ROOT_ROUNDS);
    let mut right = Vec::with_capacity(CERTIFICATE_ROOT_ROUNDS);
    let mut offset = 1;
    for _ in 0..CERTIFICATE_ROOT_ROUNDS {
        left.push(parse_point(
            encoded[offset..offset + 33]
                .try_into()
                .expect("fixed certificate step left"),
        )?);
        offset += 33;
        right.push(parse_point(
            encoded[offset..offset + 33]
                .try_into()
                .expect("fixed certificate step right"),
        )?);
        offset += 33;
    }
    let terminal_scalar = parse_scalar(
        encoded[offset..offset + 32]
            .try_into()
            .expect("fixed certificate step terminal"),
    )?;
    offset += 32;
    let folded_generator = parse_point(
        encoded[offset..offset + 33]
            .try_into()
            .expect("fixed certificate step generator"),
    )?;
    if offset + 33 != encoded.len() {
        return Err(RelationError::Malformed("certificate native step length"));
    }
    Ok(CandidateStepProofWitness {
        left,
        right,
        terminal_scalar,
        folded_generator,
    })
}

fn parse_scalar(encoded: [u8; 32]) -> Result<SecpScalarWitness, RelationError> {
    let witness = SecpScalarWitness::from_bytes_be(encoded);
    canonical_scalar_value(witness)?;
    Ok(witness)
}

fn parse_point(encoded: [u8; 33]) -> Result<SecpEncodedPointWitness, RelationError> {
    SecpEncodedPointWitness::parse(encoded)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RelationError> {
        let end = self.offset.checked_add(N).ok_or(RelationError::Malformed(
            "certificate native receipt overflow",
        ))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(RelationError::Malformed(
                "truncated certificate native receipt",
            ))?;
        self.offset = end;
        Ok(bytes.try_into().expect("fixed certificate cursor slice"))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn finish(self) -> Result<(), RelationError> {
        if self.offset != self.bytes.len() {
            return Err(RelationError::Malformed(
                "trailing certificate native receipt bytes",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp_constants::SECP256K1_SCALAR_ORDER_BE;

    const CERTIFICATE_MAX_COUNT: u64 = 1 << 60;

    fn encoded_reduction() -> [u8; CERTIFICATE_REDUCTION_PROOF_BYTES] {
        let mut encoded = [0; CERTIFICATE_REDUCTION_PROOF_BYTES];
        encoded[0] = REDUCTION_VERSION;
        encoded
    }

    fn encoded_step() -> [u8; CERTIFICATE_STEP_PROOF_BYTES] {
        let mut encoded = [0; CERTIFICATE_STEP_PROOF_BYTES];
        encoded[0] = STEP_VERSION;
        encoded
    }

    fn encoded_receipt(member_counts: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&CERTIFICATE_PARENT_BASIS_DIGEST);
        encoded.extend_from_slice(&[1; 32]);
        encoded.extend_from_slice(&(member_counts.len() as u64).to_be_bytes());
        for (index, member_count) in member_counts.iter().copied().enumerate() {
            let statement_byte = u8::try_from(index + 1).expect("small test statement");
            encoded.extend_from_slice(&[statement_byte; 32]);
            encoded.push(member_count);
            for _ in 0..member_count {
                encoded.extend_from_slice(&encoded_reduction());
            }
            encoded.extend_from_slice(&encoded_step());
        }
        let tree_steps =
            certificate_tree_step_count(member_counts.len() as u64).expect("valid test tree shape");
        for _ in 0..tree_steps {
            encoded.extend_from_slice(&encoded_step());
        }
        encoded
    }

    #[test]
    fn parses_exact_native_response_and_tree_boundaries() {
        let encoded = encoded_receipt(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1]);
        let receipt = CertificateNativeReceiptWitness::parse(&encoded)
            .expect("canonical native certificate receipt");
        assert_eq!(receipt.frame().total_responses(), 17);
        assert_eq!(receipt.responses().len(), 17);
        assert_eq!(receipt.tree_steps().len(), 3);
        for (ordinal, response) in receipt.responses().iter().enumerate() {
            assert_eq!(response.boundary().ordinal(), ordinal as u64);
            assert_eq!(
                response.reductions().len(),
                if ordinal == 16 { 1 } else { ordinal + 1 }
            );
            assert_eq!(response.statement_digest(), [(ordinal + 1) as u8; 32]);
            assert_eq!(response.step().left.len(), 13);
        }
    }

    #[test]
    fn rejects_wrong_header_and_unbounded_counts_before_allocation() {
        assert_eq!(
            CertificateNativeReceiptWitness::parse(&[]).err(),
            Some(RelationError::Malformed(
                "certificate native receipt header"
            ))
        );

        let mut wrong_magic = encoded_receipt(&[1]);
        wrong_magic[0] ^= 1;
        assert_eq!(
            CertificateNativeReceiptWitness::parse(&wrong_magic).err(),
            Some(RelationError::Malformed("certificate native receipt magic"))
        );

        let mut wrong_basis = encoded_receipt(&[1]);
        wrong_basis[MAGIC.len()] ^= 1;
        assert_eq!(
            CertificateNativeReceiptWitness::parse(&wrong_basis).err(),
            Some(RelationError::Malformed(
                "certificate native receipt basis digest"
            ))
        );

        let mut impossible_count = encoded_receipt(&[1]);
        let count_offset = MAGIC.len() + 32 + 32;
        impossible_count[count_offset..count_offset + 8]
            .copy_from_slice(&CERTIFICATE_MAX_COUNT.to_be_bytes());
        assert_eq!(
            CertificateNativeReceiptWitness::parse(&impossible_count).err(),
            Some(RelationError::Malformed(
                "certificate native response bytes"
            ))
        );
    }

    #[test]
    fn rejects_noncanonical_response_shapes_and_proof_values() {
        let response_offset = HEADER_BYTES;
        let member_count_offset = response_offset + 32;
        let reduction_offset = member_count_offset + 1;

        let mut empty_statement = encoded_receipt(&[1]);
        empty_statement[response_offset..response_offset + 32].fill(0);
        assert_eq!(
            CertificateNativeReceiptWitness::parse(&empty_statement).err(),
            Some(RelationError::Malformed(
                "empty certificate response statement"
            ))
        );

        for invalid_count in [0, (CERTIFICATE_MEMBER_BATCH_CAPACITY + 1) as u8] {
            let mut invalid = encoded_receipt(&[1]);
            invalid[member_count_offset] = invalid_count;
            assert!(CertificateNativeReceiptWitness::parse(&invalid).is_err());
        }

        let mut wrong_version = encoded_receipt(&[1]);
        wrong_version[reduction_offset] = 1;
        assert_eq!(
            CertificateNativeReceiptWitness::parse(&wrong_version).err(),
            Some(RelationError::Malformed(
                "certificate native reduction version"
            ))
        );

        let mut noncanonical_scalar = encoded_receipt(&[1]);
        noncanonical_scalar[reduction_offset + 1..reduction_offset + 33]
            .copy_from_slice(&SECP256K1_SCALAR_ORDER_BE);
        assert_eq!(
            CertificateNativeReceiptWitness::parse(&noncanonical_scalar).err(),
            Some(RelationError::Malformed("noncanonical secp scalar"))
        );

        let mut invalid_point = encoded_receipt(&[1]);
        invalid_point[reduction_offset + 33] = 4;
        assert_eq!(
            CertificateNativeReceiptWitness::parse(&invalid_point).err(),
            Some(RelationError::Malformed("encoded secp point prefix"))
        );
    }

    #[test]
    fn requires_the_exact_canonical_tree_suffix() {
        let encoded = encoded_receipt(&[1, 1]);
        assert!(CertificateNativeReceiptWitness::parse(&encoded).is_ok());

        let mut missing = encoded.clone();
        missing.pop();
        assert_eq!(
            CertificateNativeReceiptWitness::parse(&missing).err(),
            Some(RelationError::Malformed("certificate native tree bytes"))
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            CertificateNativeReceiptWitness::parse(&trailing).err(),
            Some(RelationError::Malformed("certificate native tree bytes"))
        );
    }
}
