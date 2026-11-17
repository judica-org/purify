//! Canonical native secp256k1 values shared by parsing and circuit code.

use crate::{scalar_from_canonical, scalar_to_canonical, RelationError, Scalar};
use ff::Field;

pub const SECP256K1_BASE_FIELD_MODULUS_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

pub const SECP256K1_SCALAR_ORDER_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Raw big-endian witness bytes for one secp256k1 scalar.
///
/// Construction intentionally accepts every 256-bit string. Circuit callers
/// constrain canonicality, while native input boundaries validate it before
/// accepting the value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecpScalarWitness {
    pub bytes: [u8; 32],
}

impl SecpScalarWitness {
    pub const fn from_bytes_be(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self { bytes }
    }
}

/// Parses a canonical big-endian secp256k1 coordinate-field value.
pub fn coordinate_field_value(mut bytes: [u8; 32]) -> Result<Scalar, RelationError> {
    bytes.reverse();
    scalar_from_canonical(&bytes).ok_or(RelationError::Malformed(
        "noncanonical coordinate field element",
    ))
}

/// Parses the canonical integer embedding of one secp256k1 scalar.
pub fn canonical_scalar_value(witness: SecpScalarWitness) -> Result<Scalar, RelationError> {
    if witness.bytes >= SECP256K1_SCALAR_ORDER_BE {
        return Err(RelationError::Malformed("noncanonical secp scalar"));
    }
    coordinate_field_value(witness.bytes)
}

/// Validates a canonical public point encoding and derives its affine value.
pub fn canonical_encoded_point_value(encoded: [u8; 33]) -> Result<PointValue, RelationError> {
    if encoded == [0; 33] {
        return Ok(PointValue {
            x: Scalar::ZERO,
            y: Scalar::ZERO,
            identity: true,
        });
    }
    if encoded[0] != 2 && encoded[0] != 3 {
        return Err(RelationError::Malformed("encoded secp point prefix"));
    }

    let mut x_bytes: [u8; 32] = encoded[1..].try_into().expect("fixed encoded secp x slice");
    x_bytes.reverse();
    let x = scalar_from_canonical(&x_bytes)
        .ok_or(RelationError::Malformed("noncanonical encoded secp x"))?;
    let rhs = x.square() * x + Scalar::from(7);
    let mut y = Option::<Scalar>::from(rhs.sqrt())
        .ok_or(RelationError::Malformed("encoded secp point not on curve"))?;
    let expected_parity = encoded[0] & 1;
    if scalar_to_canonical(&y)[0] & 1 != expected_parity {
        y = -y;
    }
    if scalar_to_canonical(&y)[0] & 1 != expected_parity {
        return Err(RelationError::Malformed("encoded secp point parity"));
    }

    Ok(PointValue {
        x,
        y,
        identity: false,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PointValue {
    pub x: Scalar,
    pub y: Scalar,
    pub identity: bool,
}
