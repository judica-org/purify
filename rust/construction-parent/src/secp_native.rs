//! Canonical native secp256k1 values shared by parsing and circuit code.

use ff::Field;
#[cfg(test)]
use num_bigint::BigUint;

use crate::secp_constants::SECP256K1_SCALAR_ORDER_BE;
use crate::{scalar_from_canonical, scalar_to_canonical, RelationError, Scalar};

/// Raw big-endian witness bytes for one secp256k1 scalar.
///
/// Construction intentionally accepts every 256-bit string. Circuit callers
/// constrain canonicality, while native input boundaries validate it before
/// accepting the value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SecpScalarWitness {
    pub(crate) bytes: [u8; 32],
}

impl SecpScalarWitness {
    pub(crate) const fn from_bytes_be(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    #[cfg(test)]
    pub(crate) fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self { bytes }
    }

    #[cfg(test)]
    pub(crate) fn from_biguint(value: &BigUint) -> Self {
        let encoded = value.to_bytes_be();
        assert!(encoded.len() <= 32);
        let mut bytes = [0; 32];
        bytes[32 - encoded.len()..].copy_from_slice(&encoded);
        Self { bytes }
    }
}

/// Parses a canonical big-endian secp256k1 coordinate-field value.
pub(crate) fn coordinate_field_value(mut bytes: [u8; 32]) -> Result<Scalar, RelationError> {
    bytes.reverse();
    scalar_from_canonical(&bytes).ok_or(RelationError::Malformed(
        "noncanonical coordinate field element",
    ))
}

/// Parses the canonical integer embedding of one secp256k1 scalar.
pub(crate) fn canonical_scalar_value(witness: SecpScalarWitness) -> Result<Scalar, RelationError> {
    if witness.bytes >= SECP256K1_SCALAR_ORDER_BE {
        return Err(RelationError::Malformed("noncanonical secp scalar"));
    }
    coordinate_field_value(witness.bytes)
}

/// Exact 33-byte accumulation-proof point and its affine y opening.
///
/// `encoded` is either the unique all-zero identity or a compressed SEC1
/// point `02/03 || x` with a big-endian x coordinate. `y` is canonical
/// little-endian field data and is not part of the public point encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) struct SecpEncodedPointWitness {
    pub(crate) encoded: [u8; 33],
    pub(crate) y: [u8; 32],
}

#[cfg(test)]
impl SecpEncodedPointWitness {
    pub(crate) const fn identity() -> Self {
        Self {
            encoded: [0; 33],
            y: [0; 32],
        }
    }

    /// Derives the unique affine opening from a canonical public encoding.
    pub(crate) fn parse(encoded: [u8; 33]) -> Result<Self, RelationError> {
        let point = canonical_encoded_point_value(encoded)?;
        Ok(Self {
            encoded,
            y: scalar_to_canonical(&point.y),
        })
    }

    pub(crate) fn from_point_value(point: PointValue) -> Self {
        if point.identity {
            return Self::identity();
        }
        let mut x = scalar_to_canonical(&point.x);
        let y = scalar_to_canonical(&point.y);
        x.reverse();
        let mut encoded = [0; 33];
        encoded[0] = if y[0] & 1 == 0 { 0x02 } else { 0x03 };
        encoded[1..].copy_from_slice(&x);
        Self { encoded, y }
    }
}

/// Validates a canonical public point encoding and derives its affine value.
pub(crate) fn canonical_encoded_point_value(
    encoded: [u8; 33],
) -> Result<PointValue, RelationError> {
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
pub(crate) struct PointValue {
    pub(crate) x: Scalar,
    pub(crate) y: Scalar,
    pub(crate) identity: bool,
}

/// The canonical secp256k1 group generator.
#[cfg(test)]
pub(crate) fn standard_generator() -> PointValue {
    const X: [u8; 32] = [
        0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59, 0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b,
        0x02, 0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55, 0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66,
        0xbe, 0x79,
    ];
    const Y: [u8; 32] = [
        0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c, 0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4, 0x17,
        0xfd, 0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d, 0x65, 0xc4, 0xa3, 0x26, 0x77, 0xda,
        0x3a, 0x48,
    ];
    PointValue {
        x: scalar_from_canonical(&X).expect("generator x is canonical"),
        y: scalar_from_canonical(&Y).expect("generator y is canonical"),
        identity: false,
    }
}

#[cfg(test)]
fn inverse_or_zero(value: Scalar) -> Scalar {
    Option::<Scalar>::from(value.invert()).unwrap_or(Scalar::ZERO)
}

#[cfg(test)]
pub(crate) fn add_point_values(left: PointValue, right: PointValue) -> PointValue {
    if left.identity {
        return right;
    }
    if right.identity {
        return left;
    }
    if left.x != right.x {
        let slope = (right.y - left.y) * inverse_or_zero(right.x - left.x);
        let x = slope.square() - left.x - right.x;
        let y = slope * (left.x - x) - left.y;
        return PointValue {
            x,
            y,
            identity: false,
        };
    }
    if left.y != right.y {
        return PointValue {
            x: Scalar::ZERO,
            y: Scalar::ZERO,
            identity: true,
        };
    }
    let slope = Scalar::from(3) * left.x.square() * inverse_or_zero(Scalar::from(2) * left.y);
    let x = slope.square() - Scalar::from(2) * left.x;
    let y = slope * (left.x - x) - left.y;
    PointValue {
        x,
        y,
        identity: false,
    }
}

#[cfg(test)]
pub(crate) fn scale_point_value(point: PointValue, scalar: &BigUint) -> PointValue {
    let mut accumulator = PointValue {
        x: Scalar::ZERO,
        y: Scalar::ZERO,
        identity: true,
    };
    let mut addend = point;
    for bit in 0..256 {
        if scalar.bit(bit) {
            accumulator = add_point_values(accumulator, addend);
        }
        addend = add_point_values(addend, addend);
    }
    accumulator
}

#[derive(Clone, Copy)]
#[cfg(test)]
pub(crate) struct EncodedPointValue {
    pub(crate) point: PointValue,
    pub(crate) prefix: u8,
}

#[cfg(test)]
pub(crate) fn parse_encoded_point(
    witness: SecpEncodedPointWitness,
) -> Result<EncodedPointValue, RelationError> {
    let mut x_bytes = [0; 32];
    x_bytes.copy_from_slice(&witness.encoded[1..]);
    x_bytes.reverse();
    let x = scalar_from_canonical(&x_bytes)
        .ok_or(RelationError::Malformed("noncanonical encoded secp x"))?;
    let y = scalar_from_canonical(&witness.y)
        .ok_or(RelationError::Malformed("noncanonical encoded secp y"))?;
    let prefix = witness.encoded[0];
    Ok(EncodedPointValue {
        point: PointValue {
            x,
            y,
            identity: prefix == 0,
        },
        prefix,
    })
}

#[cfg(test)]
pub(crate) fn validate_constant_point(point: PointValue) -> Result<(), RelationError> {
    if point.identity {
        if point.x != Scalar::ZERO || point.y != Scalar::ZERO {
            return Err(RelationError::Malformed("noncanonical constant identity"));
        }
    } else if point.y.square() != point.x.square() * point.x + Scalar::from(7) {
        return Err(RelationError::Malformed("constant point off curve"));
    }
    Ok(())
}

/// Validates an exact encoded point constant and returns its affine value.
#[cfg(test)]
pub(crate) fn encoded_point_value(
    witness: SecpEncodedPointWitness,
) -> Result<PointValue, RelationError> {
    let encoded = parse_encoded_point(witness)?;
    validate_constant_point(encoded.point)?;
    let expected_prefix = if encoded.point.identity {
        0
    } else {
        2 + (scalar_to_canonical(&encoded.point.y)[0] & 1)
    };
    if encoded.prefix != expected_prefix {
        return Err(RelationError::Malformed(
            "noncanonical encoded point constant",
        ));
    }
    Ok(encoded.point)
}
