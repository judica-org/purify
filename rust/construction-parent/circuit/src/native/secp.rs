//! Native secp256k1 witness values and group arithmetic for the relation.
//!
//! The statement-level encodings are re-exported so relation code reaches
//! every native secp256k1 helper through one module.

use ff::Field;
use num_bigint::BigUint;

pub use statement::secp::*;
use statement::{scalar_from_canonical, scalar_to_canonical, RelationError, Scalar};

/// Exact 33-byte accumulation-proof point and its affine y opening.
///
/// `encoded` is either the unique all-zero identity or a compressed SEC1
/// point `02/03 || x` with a big-endian x coordinate. `y` is canonical
/// little-endian field data and is not part of the public point encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecpEncodedPointWitness {
    pub encoded: [u8; 33],
    pub y: [u8; 32],
}

impl SecpEncodedPointWitness {
    pub const fn identity() -> Self {
        Self {
            encoded: [0; 33],
            y: [0; 32],
        }
    }

    /// Derives the unique affine opening from a canonical public encoding.
    pub fn parse(encoded: [u8; 33]) -> Result<Self, RelationError> {
        let point = canonical_encoded_point_value(encoded)?;
        Ok(Self {
            encoded,
            y: scalar_to_canonical(&point.y),
        })
    }

    pub fn from_point_value(point: PointValue) -> Self {
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

/// The canonical secp256k1 group generator.
pub fn standard_generator() -> PointValue {
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

fn inverse_or_zero(value: Scalar) -> Scalar {
    Option::<Scalar>::from(value.invert()).unwrap_or(Scalar::ZERO)
}

pub fn add_point_values(left: PointValue, right: PointValue) -> PointValue {
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

pub fn scale_point_value(point: PointValue, scalar: &BigUint) -> PointValue {
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
pub struct EncodedPointValue {
    pub point: PointValue,
    pub prefix: u8,
}

pub fn parse_encoded_point(
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

pub fn validate_constant_point(point: PointValue) -> Result<(), RelationError> {
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
pub fn encoded_point_value(witness: SecpEncodedPointWitness) -> Result<PointValue, RelationError> {
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

/// Encodes an integer below 2^256 as a big-endian scalar witness.
#[cfg(test)]
pub(crate) fn scalar_witness_from_biguint(value: &BigUint) -> SecpScalarWitness {
    let encoded = value.to_bytes_be();
    assert!(encoded.len() <= 32);
    let mut bytes = [0; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    SecpScalarWitness { bytes }
}
