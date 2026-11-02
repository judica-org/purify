use super::*;

use crate::construction_manifest::{CONSTRUCTION_ROOT_BYTES, CONSTRUCTION_ROOT_ROUNDS};

const SECP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn generator_encoding() -> [u8; 33] {
    [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ]
}

fn seed_root() -> [u8; CONSTRUCTION_ROOT_BYTES] {
    let mut encoded = [0; CONSTRUCTION_ROOT_BYTES];
    encoded[..33].copy_from_slice(&generator_encoding());
    encoded[64] = 1;
    for index in 0..CONSTRUCTION_ROOT_ROUNDS {
        encoded[65 + 32 * index + 31] = u8::try_from(index + 2).expect("small root factor");
    }
    encoded
}

fn descriptor(binding: u8) -> [u8; CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES] {
    let mut descriptor = [0; CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES];
    descriptor[..32].fill(binding);
    descriptor[63] = 3;
    descriptor
}

fn descriptors(count: usize) -> Vec<u8> {
    (0..count)
        .flat_map(|index| descriptor(u8::try_from(index + 1).expect("small binding")))
        .collect()
}

fn parse(
    count: u32,
    descriptor_bytes: &[u8],
) -> Result<ConstructionParentInputs, ConstructionParentInputError> {
    ConstructionParentInputs::parse(
        [0x31; 32],
        [0x52; 32],
        &seed_root(),
        CONSTRUCTION_PARENT_BASIS_DIGEST,
        CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        count,
        descriptor_bytes,
    )
}

#[test]
fn exact_native_inputs_construct_typed_manifest_values() {
    let encoded = descriptors(2);
    let inputs = parse(2, &encoded).expect("canonical construction parent inputs");
    assert_eq!(inputs.anchors().len(), 2);
    assert!(inputs
        .seed()
        .derive_expected_final(inputs.anchors())
        .is_ok());
    assert_eq!(CONSTRUCTION_PARENT_ANCHOR_DESCRIPTOR_BYTES, 130);
}

#[test]
fn native_profile_digests_are_not_peer_selected() {
    let encoded = descriptors(1);
    let mut basis = CONSTRUCTION_PARENT_BASIS_DIGEST;
    basis[0] ^= 1;
    assert!(matches!(
        ConstructionParentInputs::parse(
            [0x31; 32],
            [0x52; 32],
            &seed_root(),
            basis,
            CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            1,
            &encoded,
        ),
        Err(ConstructionParentInputError::BasisDigest)
    ));

    let mut raw = CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST;
    raw[0] ^= 1;
    assert!(matches!(
        ConstructionParentInputs::parse(
            [0x31; 32],
            [0x52; 32],
            &seed_root(),
            CONSTRUCTION_PARENT_BASIS_DIGEST,
            raw,
            1,
            &encoded,
        ),
        Err(ConstructionParentInputError::RawGeneratorDigest)
    ));
}

#[test]
fn descriptor_count_fixes_the_complete_byte_string() {
    let encoded = descriptors(1);
    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(matches!(
        parse(1, &truncated),
        Err(ConstructionParentInputError::DescriptorSize {
            expected: 130,
            actual: 129
        })
    ));

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(matches!(
        parse(1, &trailing),
        Err(ConstructionParentInputError::DescriptorSize {
            expected: 130,
            actual: 131
        })
    ));
    assert!(matches!(
        parse(2, &encoded),
        Err(ConstructionParentInputError::DescriptorSize {
            expected: 260,
            actual: 130
        })
    ));
}

#[test]
fn seed_and_descriptor_encodings_are_canonical() {
    let encoded = descriptors(1);
    assert!(matches!(
        ConstructionParentInputs::parse(
            [0x31; 32],
            [0x52; 32],
            &seed_root()[..CONSTRUCTION_ROOT_BYTES - 1],
            CONSTRUCTION_PARENT_BASIS_DIGEST,
            CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            1,
            &encoded,
        ),
        Err(ConstructionParentInputError::State(
            ReceiptCycleError::Malformed("construction root size")
        ))
    ));
    assert!(matches!(
        ConstructionParentInputs::parse(
            [0x31; 32],
            [0; 32],
            &seed_root(),
            CONSTRUCTION_PARENT_BASIS_DIGEST,
            CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            1,
            &encoded,
        ),
        Err(ConstructionParentInputError::State(
            ReceiptCycleError::Malformed("unresolved construction setup record")
        ))
    ));
    assert!(matches!(
        parse(0, &[]),
        Err(ConstructionParentInputError::State(
            ReceiptCycleError::Malformed("empty construction payload")
        ))
    ));
}

#[test]
fn descriptors_reject_invalid_scalars_and_points() {
    let mut zero = descriptor(1);
    zero[32..64].fill(0);
    assert!(matches!(
        parse(1, &zero),
        Err(ConstructionParentInputError::State(
            ReceiptCycleError::Malformed("zero construction precommitment")
        ))
    ));

    let mut noncanonical = descriptor(1);
    noncanonical[32..64].copy_from_slice(&SECP_ORDER);
    assert!(matches!(
        parse(1, &noncanonical),
        Err(ConstructionParentInputError::State(
            ReceiptCycleError::Malformed("noncanonical secp scalar")
        ))
    ));

    let mut malformed_point = descriptor(1);
    malformed_point[64] = 4;
    assert!(matches!(
        parse(1, &malformed_point),
        Err(ConstructionParentInputError::State(
            ReceiptCycleError::Malformed("encoded secp point prefix")
        ))
    ));

    let mut malformed_offset = descriptor(1);
    malformed_offset[97] = 4;
    assert!(matches!(
        parse(1, &malformed_offset),
        Err(ConstructionParentInputError::State(
            ReceiptCycleError::Malformed("encoded secp point prefix")
        ))
    ));
}
