//! Canonical pending root for the certificate recurrence.
//!
//! Parsing establishes only the fixed one-term encoding authenticated by the
//! recurrence. Acceptance still requires the native certificate-basis
//! decision.

use ff::Field;

#[cfg(any(test, feature = "prover"))]
use crate::candidate::CandidateRootClaim;
use crate::certificate_profile::{
    CERTIFICATE_ROOT_BYTES, CERTIFICATE_ROOT_ROUNDS, CERTIFICATE_ROOT_STATE_ARITY,
};
#[cfg(any(test, feature = "prover"))]
use crate::secp_native::SecpEncodedPointWitness;
use crate::secp_native::{
    canonical_encoded_point_value, canonical_scalar_value, SecpScalarWitness,
};
use crate::{scalar_to_canonical, RelationError, Scalar};

/// Exact pending root for the fixed 8,192-point certificate basis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CertificateRoot {
    encoded: [u8; CERTIFICATE_ROOT_BYTES],
    state_fields: [Scalar; CERTIFICATE_ROOT_STATE_ARITY],
}

impl CertificateRoot {
    pub(crate) fn parse(encoded: &[u8]) -> Result<Self, RelationError> {
        let encoded: [u8; CERTIFICATE_ROOT_BYTES] = encoded
            .try_into()
            .map_err(|_| RelationError::Malformed("certificate root size"))?;
        let point_encoding = encoded[..33].try_into().expect("fixed point slice");
        let point = canonical_encoded_point_value(point_encoding)?;
        let scale = parse_root_scalar(encoded[33..65].try_into().expect("fixed scale slice"))?;
        let mut state_fields = [Scalar::ZERO; CERTIFICATE_ROOT_STATE_ARITY];
        state_fields[0] = Scalar::from(u64::from(point_encoding[0]));
        state_fields[1] = point.x;
        state_fields[2] = scale;
        for index in 0..CERTIFICATE_ROOT_ROUNDS {
            let offset = 65 + 32 * index;
            state_fields[3 + index] = parse_root_scalar(
                encoded[offset..offset + 32]
                    .try_into()
                    .expect("fixed factor slice"),
            )?;
        }
        Ok(Self {
            encoded,
            state_fields,
        })
    }

    /// Reconstruct the unique encoding from authenticated recurrence fields.
    pub(crate) fn from_state_fields(
        fields: [Scalar; CERTIFICATE_ROOT_STATE_ARITY],
    ) -> Result<Self, RelationError> {
        let prefix = if fields[0] == Scalar::ZERO {
            0
        } else if fields[0] == Scalar::from(2) {
            2
        } else if fields[0] == Scalar::from(3) {
            3
        } else {
            return Err(RelationError::Malformed("certificate root point prefix"));
        };

        let mut encoded = [0; CERTIFICATE_ROOT_BYTES];
        if prefix == 0 {
            if fields[1] != Scalar::ZERO {
                return Err(RelationError::Malformed("certificate root identity point"));
            }
        } else {
            encoded[0] = prefix;
            encoded[1..33].copy_from_slice(&field_to_be(fields[1]));
        }
        encoded[33..65].copy_from_slice(&field_to_be(fields[2]));
        for (index, field) in fields[3..].iter().enumerate() {
            let offset = 65 + 32 * index;
            encoded[offset..offset + 32].copy_from_slice(&field_to_be(*field));
        }
        Self::parse(&encoded)
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8; CERTIFICATE_ROOT_BYTES] {
        &self.encoded
    }

    pub(crate) fn state_fields(&self) -> [Scalar; CERTIFICATE_ROOT_STATE_ARITY] {
        self.state_fields
    }

    #[cfg(any(test, feature = "prover"))]
    pub(crate) fn claim(&self) -> CandidateRootClaim {
        let point = SecpEncodedPointWitness::parse(
            self.encoded[..33].try_into().expect("fixed point slice"),
        )
        .expect("parsed certificate root point remains canonical");
        let scale = SecpScalarWitness::from_bytes_be(
            self.encoded[33..65].try_into().expect("fixed scale slice"),
        );
        let factors = (0..CERTIFICATE_ROOT_ROUNDS)
            .map(|index| {
                let offset = 65 + 32 * index;
                SecpScalarWitness::from_bytes_be(
                    self.encoded[offset..offset + 32]
                        .try_into()
                        .expect("fixed factor slice"),
                )
            })
            .collect();
        CandidateRootClaim {
            point,
            scale,
            factors,
        }
    }
}

fn parse_root_scalar(bytes: [u8; 32]) -> Result<Scalar, RelationError> {
    canonical_scalar_value(SecpScalarWitness::from_bytes_be(bytes))
}

fn field_to_be(value: Scalar) -> [u8; 32] {
    let mut encoded = scalar_to_canonical(&value);
    encoded.reverse();
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp_constants::SECP256K1_SCALAR_ORDER_BE;

    const GENERATOR: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn put_scalar(encoded: &mut [u8; CERTIFICATE_ROOT_BYTES], offset: usize, value: u8) {
        encoded[offset + 31] = value;
    }

    fn generator_root() -> [u8; CERTIFICATE_ROOT_BYTES] {
        let mut encoded = [0; CERTIFICATE_ROOT_BYTES];
        encoded[..33].copy_from_slice(&GENERATOR);
        put_scalar(&mut encoded, 33, 1);
        for index in 0..CERTIFICATE_ROOT_ROUNDS {
            put_scalar(&mut encoded, 65 + 32 * index, index as u8 + 2);
        }
        encoded
    }

    #[test]
    fn identity_and_generator_roots_roundtrip() {
        assert_eq!(CERTIFICATE_ROOT_BYTES, 481);

        let identity =
            CertificateRoot::parse(&[0; CERTIFICATE_ROOT_BYTES]).expect("canonical identity root");
        assert_eq!(identity.canonical_bytes(), &[0; CERTIFICATE_ROOT_BYTES]);
        assert_eq!(
            CertificateRoot::from_state_fields(identity.state_fields())
                .expect("identity from state"),
            identity,
        );
        assert_eq!(identity.claim().factors.len(), CERTIFICATE_ROOT_ROUNDS);

        let encoded = generator_root();
        let generator = CertificateRoot::parse(&encoded).expect("canonical generator root");
        assert_eq!(generator.canonical_bytes(), &encoded);
        assert_eq!(generator.claim().point.encoded, GENERATOR);
        assert_eq!(generator.claim().factors.len(), CERTIFICATE_ROOT_ROUNDS);
        assert_eq!(
            CertificateRoot::from_state_fields(generator.state_fields())
                .expect("generator from state"),
            generator,
        );
    }

    #[test]
    fn rejects_noncanonical_root_encodings_and_fields() {
        let encoded = generator_root();
        assert!(CertificateRoot::parse(&encoded[..CERTIFICATE_ROOT_BYTES - 1]).is_err());

        let mut invalid_prefix = encoded;
        invalid_prefix[0] = 4;
        assert!(CertificateRoot::parse(&invalid_prefix).is_err());

        let mut invalid_identity = encoded;
        invalid_identity[0] = 0;
        assert!(CertificateRoot::parse(&invalid_identity).is_err());

        let mut noncanonical_scale = encoded;
        noncanonical_scale[33..65].copy_from_slice(&SECP256K1_SCALAR_ORDER_BE);
        assert!(CertificateRoot::parse(&noncanonical_scale).is_err());

        let mut noncanonical_factor = encoded;
        noncanonical_factor[65..97].copy_from_slice(&SECP256K1_SCALAR_ORDER_BE);
        assert!(CertificateRoot::parse(&noncanonical_factor).is_err());

        let fields = CertificateRoot::parse(&encoded)
            .expect("canonical generator root")
            .state_fields();
        let mut bad_prefix_field = fields;
        bad_prefix_field[0] = Scalar::from(4);
        assert!(CertificateRoot::from_state_fields(bad_prefix_field).is_err());

        let mut identity_with_x = fields;
        identity_with_x[0] = Scalar::ZERO;
        assert!(CertificateRoot::from_state_fields(identity_with_x).is_err());

        let noncanonical_scalar =
            crate::secp_native::coordinate_field_value(SECP256K1_SCALAR_ORDER_BE)
                .expect("group order is below the coordinate modulus");
        let mut noncanonical_factor_field = fields;
        noncanonical_factor_field[3] = noncanonical_scalar;
        assert!(CertificateRoot::from_state_fields(noncanonical_factor_field).is_err());
    }
}
