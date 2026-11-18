//! Verifier-derived public frame for one certificate recurrence.
//!
//! This type fixes the recursive initial state and the exact final framing
//! expected from independently admitted certificate records. It does not
//! verify a Nova proof or decide the authenticated accumulation root.

use ff::Field;

use crate::certificate_profile::{
    CERTIFICATE_MEMBER_BATCH_CAPACITY, CERTIFICATE_RECURRENCE_STATE_ARITY, CERTIFICATE_ROOT_BYTES,
    CERTIFICATE_ROOT_STATE_ARITY, CONTEXT_HIGH_INDEX, CONTEXT_LOW_INDEX, MEMBER_COUNT_INDEX,
    MEMBER_ORDINAL_INDEX, NONCE_PREFIX_INDEX, NONCE_X_INDEX, RECORD_MANIFEST_INDEX,
    RESPONSE_BINDING_INDEX, RESPONSE_ORDINAL_INDEX, TOTAL_RESPONSES_INDEX,
};
use crate::certificate_recursive_manifest::recursive_manifest_seed;
use crate::certificate_root::CertificateRoot;
use crate::secp_native::coordinate_field_value;
use crate::{RelationError, Scalar};

/// Public certificate facts from which the verifier derives z0 and zN.
pub(crate) struct CertificateParentInputs {
    initial_state: [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
    expected_context_high: Scalar,
    expected_context_low: Scalar,
    expected_total_responses: Scalar,
    verifier_derived_final_manifest: Scalar,
    total_responses: u64,
    step_count: usize,
}

impl CertificateParentInputs {
    /// Construct one exact recurrence frame from independently derived facts.
    ///
    /// `total_steps` is the checked sum of admitted response member counts.
    /// Its `u128` width lets this boundary reject values that do not fit the
    /// Nova verifier's native `usize` step-count API. The final manifest must
    /// be recomputed from the complete admitted ordered public records. A
    /// proof-supplied manifest must never reach this constructor.
    pub(crate) fn new(
        certificate_context_digest: [u8; 32],
        total_responses: u64,
        total_steps: u128,
        verifier_derived_final_manifest: [u8; 32],
    ) -> Result<Self, RelationError> {
        let initial_manifest =
            recursive_manifest_seed(certificate_context_digest, total_responses)?;
        let maximum_steps = u128::from(total_responses)
            .checked_mul(CERTIFICATE_MEMBER_BATCH_CAPACITY as u128)
            .expect("certificate profile step bound fits u128");
        if total_steps < u128::from(total_responses) || total_steps > maximum_steps {
            return Err(RelationError::Malformed("certificate parent step count"));
        }
        let step_count = usize::try_from(total_steps)
            .map_err(|_| RelationError::Malformed("certificate parent step count"))?;
        if verifier_derived_final_manifest[0] & 0x80 != 0 {
            return Err(RelationError::Malformed(
                "certificate parent final manifest",
            ));
        }

        let context_high = short_bytes_to_field(&certificate_context_digest[..16]);
        let context_low = short_bytes_to_field(&certificate_context_digest[16..]);
        let total_responses_field = Scalar::from(total_responses);
        let initial_manifest_field = coordinate_field_value(initial_manifest)?;
        let verifier_derived_final_manifest =
            coordinate_field_value(verifier_derived_final_manifest)?;
        let root = CertificateRoot::parse(&[0; CERTIFICATE_ROOT_BYTES])?.state_fields();

        let mut initial_state = [Scalar::ZERO; CERTIFICATE_RECURRENCE_STATE_ARITY];
        initial_state[..CERTIFICATE_ROOT_STATE_ARITY].copy_from_slice(&root);
        initial_state[CONTEXT_HIGH_INDEX] = context_high;
        initial_state[CONTEXT_LOW_INDEX] = context_low;
        initial_state[TOTAL_RESPONSES_INDEX] = total_responses_field;
        initial_state[RECORD_MANIFEST_INDEX] = initial_manifest_field;

        Ok(Self {
            initial_state,
            expected_context_high: context_high,
            expected_context_low: context_low,
            expected_total_responses: total_responses_field,
            verifier_derived_final_manifest,
            total_responses,
            step_count,
        })
    }

    pub(crate) fn initial_state(&self) -> &[Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY] {
        &self.initial_state
    }

    pub(crate) const fn step_count(&self) -> usize {
        self.step_count
    }

    /// Validate a proof-authenticated final state and expose its pending root.
    ///
    /// The returned bytes are not certificate acceptance. The native caller
    /// must parse them against the fixed certificate basis and run `decide()`.
    pub(crate) fn validate_authenticated_final_state(
        &self,
        authenticated_final: [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
    ) -> Result<CertificateParentPendingRoot, RelationError> {
        if authenticated_final[CONTEXT_HIGH_INDEX] != self.expected_context_high
            || authenticated_final[CONTEXT_LOW_INDEX] != self.expected_context_low
            || authenticated_final[TOTAL_RESPONSES_INDEX] != self.expected_total_responses
            || authenticated_final[NONCE_PREFIX_INDEX] != Scalar::ZERO
            || authenticated_final[NONCE_X_INDEX] != Scalar::ZERO
            || authenticated_final[RECORD_MANIFEST_INDEX] != self.verifier_derived_final_manifest
            || authenticated_final[RESPONSE_ORDINAL_INDEX] != Scalar::from(self.total_responses)
            || authenticated_final[MEMBER_ORDINAL_INDEX] != Scalar::ZERO
            || authenticated_final[MEMBER_COUNT_INDEX] != Scalar::ZERO
            || authenticated_final[RESPONSE_BINDING_INDEX] != Scalar::ZERO
        {
            return Err(RelationError::Malformed("certificate parent final frame"));
        }
        let root_fields = authenticated_final[..CERTIFICATE_ROOT_STATE_ARITY]
            .try_into()
            .expect("certificate recurrence has a fixed root prefix");
        let root = CertificateRoot::from_state_fields(root_fields)?;
        Ok(CertificateParentPendingRoot {
            canonical_root: *root.canonical_bytes(),
        })
    }
}

/// Framing-validated but still pending certificate accumulation root.
pub(crate) struct CertificateParentPendingRoot {
    canonical_root: [u8; CERTIFICATE_ROOT_BYTES],
}

impl CertificateParentPendingRoot {
    pub(crate) fn canonical_root_bytes(&self) -> &[u8; CERTIFICATE_ROOT_BYTES] {
        &self.canonical_root
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
    use crate::certificate_profile::CERTIFICATE_MAX_RESPONSES;

    const GENERATOR: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn low_digest(byte: u8) -> [u8; 32] {
        let mut digest = [byte; 32];
        digest[0] &= 0x7f;
        digest
    }

    fn inputs() -> CertificateParentInputs {
        CertificateParentInputs::new([0x11; 32], 2, 4, low_digest(0x22))
            .expect("certificate parent inputs")
    }

    fn generator_root() -> CertificateRoot {
        let mut encoded = [0; CERTIFICATE_ROOT_BYTES];
        encoded[..33].copy_from_slice(&GENERATOR);
        encoded[64] = 1;
        for index in 0..crate::certificate_profile::CERTIFICATE_ROOT_ROUNDS {
            encoded[65 + 32 * index + 31] = index as u8 + 2;
        }
        CertificateRoot::parse(&encoded).expect("certificate generator root")
    }

    fn completed_state(
        inputs: &CertificateParentInputs,
    ) -> [Scalar; CERTIFICATE_RECURRENCE_STATE_ARITY] {
        let mut state = *inputs.initial_state();
        state[..CERTIFICATE_ROOT_STATE_ARITY].copy_from_slice(&generator_root().state_fields());
        state[RECORD_MANIFEST_INDEX] = inputs.verifier_derived_final_manifest;
        state[RESPONSE_ORDINAL_INDEX] = Scalar::from(inputs.total_responses);
        state
    }

    #[test]
    fn derives_the_only_canonical_initial_state() {
        let inputs = inputs();
        let state = inputs.initial_state();
        assert_eq!(inputs.step_count(), 4);
        assert!(state[..CERTIFICATE_ROOT_STATE_ARITY]
            .iter()
            .all(|field| *field == Scalar::ZERO));
        assert_eq!(state[CONTEXT_HIGH_INDEX], short_bytes_to_field(&[0x11; 16]));
        assert_eq!(state[CONTEXT_LOW_INDEX], short_bytes_to_field(&[0x11; 16]));
        assert_eq!(state[TOTAL_RESPONSES_INDEX], Scalar::from(2));
        assert_eq!(
            state[RECORD_MANIFEST_INDEX],
            coordinate_field_value(
                recursive_manifest_seed([0x11; 32], 2).expect("recursive manifest seed")
            )
            .expect("manifest field"),
        );
        for index in [
            NONCE_PREFIX_INDEX,
            NONCE_X_INDEX,
            RESPONSE_ORDINAL_INDEX,
            MEMBER_ORDINAL_INDEX,
            MEMBER_COUNT_INDEX,
            RESPONSE_BINDING_INDEX,
        ] {
            assert_eq!(state[index], Scalar::ZERO);
        }
    }

    #[test]
    fn rejects_invalid_counts_and_manifest_frames() {
        assert!(CertificateParentInputs::new([0; 32], 1, 1, low_digest(1)).is_err());
        assert!(CertificateParentInputs::new([1; 32], 0, 1, low_digest(1)).is_err());
        assert!(CertificateParentInputs::new(
            [1; 32],
            CERTIFICATE_MAX_RESPONSES + 1,
            1,
            low_digest(1),
        )
        .is_err());
        assert!(CertificateParentInputs::new([1; 32], 1, 0, low_digest(1)).is_err());
        assert!(CertificateParentInputs::new([1; 32], 2, 1, low_digest(1)).is_err());
        assert!(CertificateParentInputs::new(
            [1; 32],
            1,
            CERTIFICATE_MEMBER_BATCH_CAPACITY as u128 + 1,
            low_digest(1),
        )
        .is_err());

        let mut high_manifest = [1; 32];
        high_manifest[0] |= 0x80;
        assert!(CertificateParentInputs::new([1; 32], 1, 1, high_manifest).is_err());

        let first_unrepresentable_step_count = usize::MAX as u128 + 1;
        assert!(CertificateParentInputs::new(
            [1; 32],
            CERTIFICATE_MAX_RESPONSES,
            first_unrepresentable_step_count,
            low_digest(1),
        )
        .is_err());
    }

    #[test]
    fn validates_every_final_frame_field_before_returning_root() {
        let inputs = inputs();
        let completed = completed_state(&inputs);
        let output = inputs
            .validate_authenticated_final_state(completed)
            .expect("complete certificate final frame");
        assert_eq!(
            output.canonical_root_bytes(),
            generator_root().canonical_bytes()
        );

        for index in [
            CONTEXT_HIGH_INDEX,
            CONTEXT_LOW_INDEX,
            TOTAL_RESPONSES_INDEX,
            NONCE_PREFIX_INDEX,
            NONCE_X_INDEX,
            RECORD_MANIFEST_INDEX,
            RESPONSE_ORDINAL_INDEX,
            MEMBER_ORDINAL_INDEX,
            MEMBER_COUNT_INDEX,
            RESPONSE_BINDING_INDEX,
        ] {
            let mut changed = completed;
            changed[index] += Scalar::ONE;
            assert!(inputs.validate_authenticated_final_state(changed).is_err());
        }

        let mut invalid_root = completed;
        invalid_root[crate::certificate_profile::ROOT_PREFIX_INDEX] = Scalar::from(4);
        assert!(inputs
            .validate_authenticated_final_state(invalid_root)
            .is_err());

        let other_manifest = CertificateParentInputs::new([0x11; 32], 2, 4, low_digest(0x23))
            .expect("other verifier-derived manifest");
        assert!(other_manifest
            .validate_authenticated_final_state(completed)
            .is_err());
    }
}
