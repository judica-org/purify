//! Backend-independent state for linear certificate accumulation.
//!
//! The recursive backend binds this exact 26-field order. One step consumes
//! one authenticated member leaf. Between responses, the partial nonce and
//! response-group fields return to their canonical neutral encodings.

use ff::Field;

use crate::candidate::CandidateRootClaim;
use crate::certificate_profile::{
    CERTIFICATE_MAX_RESPONSES, CERTIFICATE_MEMBER_BATCH_CAPACITY,
    CERTIFICATE_RECURRENCE_STATE_ARITY, CERTIFICATE_ROOT_ROUNDS, CERTIFICATE_ROOT_STATE_ARITY,
    CONTEXT_HIGH_INDEX, CONTEXT_LOW_INDEX, MEMBER_COUNT_INDEX, MEMBER_ORDINAL_INDEX,
    NONCE_PREFIX_INDEX, NONCE_X_INDEX, RECORD_MANIFEST_INDEX, RESPONSE_BINDING_INDEX,
    RESPONSE_ORDINAL_INDEX, ROOT_FACTORS_START, ROOT_PREFIX_INDEX, ROOT_SCALE_INDEX, ROOT_X_INDEX,
    TOTAL_RESPONSES_INDEX,
};
use crate::certificate_recursive_manifest::recursive_manifest_seed;
use crate::secp_native::{
    canonical_scalar_value, coordinate_field_value, encoded_point_value, SecpEncodedPointWitness,
    SecpScalarWitness,
};
use crate::{RelationError, Scalar};

/// Exact public state carried between homogeneous certificate-member steps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CertificateRecurrenceStateWitness {
    pub(crate) root: CandidateRootClaim,
    pub(crate) certificate_context_digest: [u8; 32],
    pub(crate) total_responses: u64,
    pub(crate) partial_nonce: SecpEncodedPointWitness,
    /// Ordered recursive-record manifest with its high digest bit cleared.
    pub(crate) record_manifest: [u8; 32],
    /// Next response to consume, or `total_responses` after completion.
    pub(crate) response_ordinal: u64,
    /// Next member within an active response; zero between responses.
    pub(crate) member_ordinal: u32,
    /// Active response size; zero between responses.
    pub(crate) member_count: u32,
    /// Low-255-bit response-group binding; zero between responses.
    pub(crate) response_binding: [u8; 32],
}

impl CertificateRecurrenceStateWitness {
    pub(crate) fn genesis(
        certificate_context_digest: [u8; 32],
        total_responses: u64,
    ) -> Result<Self, RelationError> {
        let record_manifest = recursive_manifest_seed(certificate_context_digest, total_responses)?;
        let state = Self {
            root: CandidateRootClaim {
                point: SecpEncodedPointWitness::identity(),
                scale: SecpScalarWitness::from_u64(0),
                factors: vec![SecpScalarWitness::from_u64(0); CERTIFICATE_ROOT_ROUNDS],
            },
            certificate_context_digest,
            total_responses,
            partial_nonce: SecpEncodedPointWitness::identity(),
            record_manifest,
            response_ordinal: 0,
            member_ordinal: 0,
            member_count: 0,
            response_binding: [0; 32],
        };
        state.validate()?;
        Ok(state)
    }

    pub(crate) fn state_fields(
        &self,
    ) -> Result<[Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY], RelationError> {
        self.validate()?;
        let root_point = encoded_point_value(self.root.point)?;
        let partial_nonce = encoded_point_value(self.partial_nonce)?;
        let mut state = [Scalar::ZERO; CERTIFICATE_RECURRENCE_STATE_ARITY];
        state[ROOT_PREFIX_INDEX] = Scalar::from(u64::from(self.root.point.encoded[0]));
        state[ROOT_X_INDEX] = root_point.x;
        state[ROOT_SCALE_INDEX] = canonical_scalar_value(self.root.scale)?;
        for (index, factor) in self.root.factors.iter().enumerate() {
            state[ROOT_FACTORS_START + index] = canonical_scalar_value(*factor)?;
        }
        state[CONTEXT_HIGH_INDEX] = short_bytes_to_field(&self.certificate_context_digest[..16]);
        state[CONTEXT_LOW_INDEX] = short_bytes_to_field(&self.certificate_context_digest[16..]);
        state[TOTAL_RESPONSES_INDEX] = Scalar::from(self.total_responses);
        state[NONCE_PREFIX_INDEX] = Scalar::from(u64::from(self.partial_nonce.encoded[0]));
        state[NONCE_X_INDEX] = partial_nonce.x;
        state[RECORD_MANIFEST_INDEX] = coordinate_field_value(self.record_manifest)?;
        state[RESPONSE_ORDINAL_INDEX] = Scalar::from(self.response_ordinal);
        state[MEMBER_ORDINAL_INDEX] = Scalar::from(u64::from(self.member_ordinal));
        state[MEMBER_COUNT_INDEX] = Scalar::from(u64::from(self.member_count));
        state[RESPONSE_BINDING_INDEX] = coordinate_field_value(self.response_binding)?;
        Ok(state)
    }

    fn is_complete(&self) -> bool {
        self.response_ordinal == self.total_responses
            && self.member_count == 0
            && self.member_ordinal == 0
            && self.partial_nonce.encoded == [0; 33]
            && self.response_binding == [0; 32]
    }

    /// Validate the complete public frame before releasing its pending root.
    ///
    /// The returned claim remains unaccepted until the native candidate
    /// decider checks it under the certificate basis.
    pub(crate) fn pending_root_for_decision(
        &self,
        expected_context_digest: [u8; 32],
        expected_total_responses: u64,
        expected_record_manifest: [u8; 32],
    ) -> Result<&CandidateRootClaim, RelationError> {
        self.validate()?;
        if self.certificate_context_digest != expected_context_digest
            || self.total_responses != expected_total_responses
            || self.record_manifest != expected_record_manifest
            || !self.is_complete()
        {
            return Err(RelationError::Malformed(
                "certificate recurrence final frame",
            ));
        }
        Ok(&self.root)
    }

    fn validate(&self) -> Result<(), RelationError> {
        if self.root.factors.len() != CERTIFICATE_ROOT_ROUNDS {
            return Err(RelationError::Malformed(
                "certificate recurrence root factors",
            ));
        }
        if self.certificate_context_digest == [0; 32]
            || self.total_responses == 0
            || self.total_responses > CERTIFICATE_MAX_RESPONSES
            || self.response_ordinal > self.total_responses
            || self.record_manifest[0] & 0x80 != 0
            || self.response_binding[0] & 0x80 != 0
        {
            return Err(RelationError::Malformed(
                "certificate recurrence public frame",
            ));
        }
        let between_responses = self.member_count == 0;
        if between_responses {
            if self.member_ordinal != 0
                || self.partial_nonce.encoded != [0; 33]
                || self.response_binding != [0; 32]
            {
                return Err(RelationError::Malformed(
                    "certificate recurrence neutral response",
                ));
            }
        } else if self.response_ordinal >= self.total_responses
            || self.member_count > CERTIFICATE_MEMBER_BATCH_CAPACITY
            || self.member_ordinal == 0
            || self.member_ordinal >= self.member_count
        {
            return Err(RelationError::Malformed(
                "certificate recurrence active response",
            ));
        }
        Ok(())
    }
}

fn short_bytes_to_field(bytes: &[u8]) -> Scalar {
    debug_assert!(bytes.len() <= 16);
    bytes.iter().fold(Scalar::ZERO, |value, byte| {
        value * Scalar::from(256) + Scalar::from(u64::from(*byte))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn low_digest(byte: u8) -> [u8; 32] {
        let mut digest = [byte; 32];
        digest[0] &= 0x7f;
        digest
    }

    #[test]
    fn recurrence_profile_has_one_frozen_field_order() {
        assert_eq!(CERTIFICATE_ROOT_STATE_ARITY, 16);
        assert_eq!(CERTIFICATE_RECURRENCE_STATE_ARITY, 26);
        assert_eq!(RESPONSE_BINDING_INDEX + 1, 26);

        let state =
            CertificateRecurrenceStateWitness::genesis([0x11; 32], 3).expect("certificate genesis");
        let fields = state.state_fields().expect("certificate state fields");
        assert_eq!(fields[ROOT_PREFIX_INDEX], Scalar::ZERO);
        assert_eq!(fields[ROOT_X_INDEX], Scalar::ZERO);
        assert_eq!(fields[ROOT_SCALE_INDEX], Scalar::ZERO);
        assert!(fields[ROOT_FACTORS_START..CONTEXT_HIGH_INDEX]
            .iter()
            .all(|field| *field == Scalar::ZERO));
        assert_eq!(
            fields[CONTEXT_HIGH_INDEX],
            short_bytes_to_field(&[0x11; 16])
        );
        assert_eq!(fields[CONTEXT_LOW_INDEX], short_bytes_to_field(&[0x11; 16]));
        assert_eq!(fields[TOTAL_RESPONSES_INDEX], Scalar::from(3));
        assert_eq!(fields[NONCE_PREFIX_INDEX], Scalar::ZERO);
        assert_eq!(fields[NONCE_X_INDEX], Scalar::ZERO);
        assert_eq!(fields[RESPONSE_ORDINAL_INDEX], Scalar::ZERO);
        assert_eq!(fields[MEMBER_ORDINAL_INDEX], Scalar::ZERO);
        assert_eq!(fields[MEMBER_COUNT_INDEX], Scalar::ZERO);
        assert_eq!(fields[RESPONSE_BINDING_INDEX], Scalar::ZERO);
        assert!(!state.is_complete());
    }

    #[test]
    fn recurrence_rejects_ambiguous_partial_response_states() {
        let genesis =
            CertificateRecurrenceStateWitness::genesis([0x11; 32], 2).expect("certificate genesis");

        let mut active = genesis.clone();
        active.member_count = 3;
        active.member_ordinal = 1;
        active.response_binding = low_digest(0x33);
        active.partial_nonce = SecpEncodedPointWitness::parse([
            2, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ])
        .expect("generator");
        assert!(active.state_fields().is_ok());

        let mut zero_ordinal = active.clone();
        zero_ordinal.member_ordinal = 0;
        assert!(zero_ordinal.state_fields().is_err());

        let mut past_end = active.clone();
        past_end.member_ordinal = past_end.member_count;
        assert!(past_end.state_fields().is_err());

        let mut neutral_with_nonce = genesis.clone();
        neutral_with_nonce.partial_nonce = active.partial_nonce;
        assert!(neutral_with_nonce.state_fields().is_err());

        let mut high_manifest = genesis.clone();
        high_manifest.record_manifest[0] |= 0x80;
        assert!(high_manifest.state_fields().is_err());

        let mut high_binding = active.clone();
        high_binding.response_binding[0] |= 0x80;
        assert!(high_binding.state_fields().is_err());

        let mut wrong_root_shape = active;
        wrong_root_shape.root.factors.pop();
        assert!(wrong_root_shape.state_fields().is_err());

        let mut finished = genesis;
        finished.response_ordinal = finished.total_responses;
        assert!(finished.state_fields().is_ok());
        assert!(finished.is_complete());
        assert!(finished
            .pending_root_for_decision([0x11; 32], 2, finished.record_manifest)
            .is_ok());
        assert!(finished
            .pending_root_for_decision([0x12; 32], 2, finished.record_manifest)
            .is_err());
        assert!(finished
            .pending_root_for_decision([0x11; 32], 1, finished.record_manifest)
            .is_err());
        assert!(finished
            .pending_root_for_decision([0x11; 32], 2, low_digest(0x77))
            .is_err());
    }
}
