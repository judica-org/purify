//! Transparent native opening-generator derivation.

use ff::Field;
use sha2::{Digest, Sha256};

use crate::secp_native::{add_point_values, PointValue};
use crate::{scalar_from_canonical, scalar_to_canonical, RelationError, Scalar};

const SVDW_NEG_C_BE: [u8; 32] = [
    0xf5, 0xd2, 0xd4, 0x56, 0xca, 0xf8, 0x0e, 0x20, 0xdc, 0xc8, 0x8f, 0x3d, 0x58, 0x68, 0x69, 0xd3,
    0x39, 0xe0, 0x92, 0xea, 0x25, 0xeb, 0x13, 0x2b, 0x82, 0x72, 0xd8, 0x50, 0xe3, 0x2a, 0x03, 0xdd,
];

const SVDW_D_BE: [u8; 32] = [
    0x85, 0x16, 0x95, 0xd4, 0x9a, 0x83, 0xf8, 0xef, 0x91, 0x9b, 0xb8, 0x61, 0x53, 0xcb, 0xcb, 0x16,
    0x63, 0x0f, 0xb6, 0x8a, 0xed, 0x0a, 0x76, 0x6a, 0x3e, 0xc6, 0x93, 0xd6, 0x8e, 0x6a, 0xfa, 0x40,
];

const SECP_SQRT_EXPONENT: [u64; 4] = [
    0xffff_ffff_bfff_ff0c,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x3fff_ffff_ffff_ffff,
];

const OPENING_PAIR_TAG: &[u8] = b"Purify/BPPP/OpeningGeneratorPairV2";
const PUBLIC_HASH_TO_POINT_TAG: &[u8] = b"Purify/BPPP/PublicHashToPointV1";
const FIRST_GENERATION_PREFIX: &[u8] = b"1st generation: ";
const SECOND_GENERATION_PREFIX: &[u8] = b"2nd generation: ";

/// Domain role for a public coefficient-opening reduction.
pub(crate) const REDUCTION_OPENING_BASE_ROLE: u64 = 1;
/// Domain role for a public accumulation transition.
pub(crate) const ACCUMULATION_OPENING_BASE_ROLE: u64 = 2;

fn field_constant_from_be(mut bytes: [u8; 32]) -> Scalar {
    bytes.reverse();
    scalar_from_canonical(&bytes).expect("the pinned secp256k1 field constant is canonical")
}

fn inverse_or_zero(value: Scalar) -> Scalar {
    Option::<Scalar>::from(value.invert()).unwrap_or(Scalar::ZERO)
}

fn quadratic_root(value: Scalar) -> (Scalar, bool) {
    let root = value.pow_vartime(SECP_SQRT_EXPONENT);
    (root, root.square() == value)
}

pub(crate) fn scalar_is_odd(value: Scalar) -> bool {
    scalar_to_canonical(&value)[0] & 1 != 0
}

fn svdw_point_value(input: Scalar) -> PointValue {
    let neg_c = field_constant_from_be(SVDW_NEG_C_BE);
    let d = field_constant_from_be(SVDW_D_BE);
    let input_squared = input.square();
    let wd = input_squared + Scalar::from(8);
    let x3d = -Scalar::from(3) * input_squared;
    let joint_inverse = inverse_or_zero(wd * x3d);
    let x1 = d + neg_c * input_squared * x3d * joint_inverse;
    let x2 = -(x1 + Scalar::ONE);
    let x3 = Scalar::ONE + wd.square() * wd * joint_inverse;

    let (x, mut y) = [x1, x2, x3]
        .into_iter()
        .find_map(|x| {
            let (root, square) = quadratic_root(x.square() * x + Scalar::from(7));
            square.then_some((x, root))
        })
        .expect("the pinned SvdW map always selects a curve point");
    if scalar_is_odd(input) {
        y = -y;
    }
    PointValue {
        x,
        y,
        identity: false,
    }
}

fn tagged_sha256(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    hash.update(message);
    hash.finalize().into()
}

fn public_hash_to_point_value(input: &[u8]) -> Result<PointValue, RelationError> {
    let key = tagged_sha256(PUBLIC_HASH_TO_POINT_TAG, input);
    let map = |prefix: &[u8]| {
        let mut hash = Sha256::new();
        hash.update(prefix);
        hash.update(key);
        let mut input: [u8; 32] = hash.finalize().into();
        input.reverse();
        scalar_from_canonical(&input)
            .map(svdw_point_value)
            .ok_or(RelationError::Malformed("opening generator field sample"))
    };
    Ok(add_point_values(
        map(FIRST_GENERATION_PREFIX)?,
        map(SECOND_GENERATION_PREFIX)?,
    ))
}

/// Derive the two trusted constants used by one transcript opening base.
pub(crate) fn opening_generator_pair(
    basis_digest: [u8; 32],
    role: u64,
) -> Result<[PointValue; 2], RelationError> {
    if !matches!(
        role,
        REDUCTION_OPENING_BASE_ROLE | ACCUMULATION_OPENING_BASE_ROLE
    ) {
        return Err(RelationError::Malformed("opening generator role"));
    }
    let mut points = Vec::with_capacity(2);
    for index in 0..2u8 {
        let mut message = Vec::with_capacity(41);
        message.extend_from_slice(&basis_digest);
        message.extend_from_slice(&role.to_le_bytes());
        message.push(index);
        let seed = tagged_sha256(OPENING_PAIR_TAG, &message);
        let point = public_hash_to_point_value(&seed)?;
        if point.identity {
            return Err(RelationError::Malformed("identity opening generator"));
        }
        points.push(point);
    }
    if points[0] == points[1] {
        return Err(RelationError::Malformed("duplicate opening generators"));
    }
    points
        .try_into()
        .map_err(|_| RelationError::Malformed("opening generator pair"))
}
