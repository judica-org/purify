use super::*;

use crate::secp_constants::SECP256K1_SCALAR_ORDER_BE as SECP_ORDER;

fn recovery_root() -> [u8; 64] {
    [0x71; 64]
}

fn descriptor(binding: u8) -> [u8; CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES] {
    let mut descriptor = [0; CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES];
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
    setup_count: u32,
    anchor_count: u32,
    descriptor_bytes: &[u8],
) -> Result<ConstructionParentInputs, ConstructionParentInputError> {
    ConstructionParentInputs::parse(
        [0x31; 32],
        [0x52; 32],
        recovery_root(),
        CONSTRUCTION_PARENT_BASIS_DIGEST,
        CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        setup_count,
        anchor_count,
        descriptor_bytes,
    )
}

#[test]
fn exact_native_inputs_construct_typed_manifest_values() {
    let encoded = descriptors(2);
    let inputs = parse(1, 1, &encoded).expect("canonical construction parent inputs");
    assert_eq!(inputs.leaves().len(), 2);
    assert_eq!(inputs.step_count(), 2);
    assert_eq!(
        inputs.initial_state(),
        &inputs
            .seed()
            .initial_state_fields()
            .expect("expected initial state")
    );
    let expected_suffix = inputs
        .seed()
        .derive_expected_final(inputs.leaves())
        .expect("expected final manifest")
        .state_suffix_fields()
        .expect("expected final suffix");
    assert_eq!(inputs.expected_suffix(), expected_suffix);
    assert_eq!(CONSTRUCTION_PARENT_LEAF_DESCRIPTOR_BYTES, 130);
}

#[test]
fn phase_boundary_changes_z0_and_final_manifest_at_fixed_total() {
    let encoded = descriptors(3);
    let one_setup = parse(1, 2, &encoded).expect("one setup and two anchors");
    let two_setups = parse(2, 1, &encoded).expect("two setups and one anchor");

    assert_ne!(one_setup.initial_state(), two_setups.initial_state());
    assert_ne!(one_setup.expected_suffix(), two_setups.expected_suffix());
    assert_eq!(one_setup.step_count(), two_setups.step_count());
}

#[test]
fn native_profile_digests_are_not_peer_selected() {
    let encoded = descriptors(2);
    let mut basis = CONSTRUCTION_PARENT_BASIS_DIGEST;
    basis[0] ^= 1;
    assert!(matches!(
        ConstructionParentInputs::parse(
            [0x31; 32],
            [0x52; 32],
            recovery_root(),
            basis,
            CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            1,
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
            recovery_root(),
            CONSTRUCTION_PARENT_BASIS_DIGEST,
            raw,
            1,
            1,
            &encoded,
        ),
        Err(ConstructionParentInputError::RawGeneratorDigest)
    ));
}

#[test]
fn descriptor_count_fixes_the_complete_byte_string() {
    let encoded = descriptors(2);
    let mut truncated = encoded.clone();
    truncated.pop();
    assert!(matches!(
        parse(1, 1, &truncated),
        Err(ConstructionParentInputError::DescriptorSize {
            expected: 260,
            actual: 259
        })
    ));

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(matches!(
        parse(1, 1, &trailing),
        Err(ConstructionParentInputError::DescriptorSize {
            expected: 260,
            actual: 261
        })
    ));
    assert!(matches!(
        parse(2, 1, &encoded),
        Err(ConstructionParentInputError::DescriptorSize {
            expected: 390,
            actual: 260
        })
    ));
}

#[test]
fn seed_and_descriptor_encodings_are_canonical() {
    let encoded = descriptors(2);
    assert!(matches!(
        ConstructionParentInputs::parse(
            [0x31; 32],
            [0; 32],
            recovery_root(),
            CONSTRUCTION_PARENT_BASIS_DIGEST,
            CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            1,
            1,
            &encoded,
        ),
        Err(ConstructionParentInputError::State(
            RelationError::Malformed("unresolved construction setup record")
        ))
    ));
    assert!(matches!(
        parse(0, 1, &encoded),
        Err(ConstructionParentInputError::State(
            RelationError::Malformed("empty construction phase")
        ))
    ));
    assert!(matches!(
        ConstructionParentInputs::parse(
            [0x31; 32],
            [0x52; 32],
            [0; 64],
            CONSTRUCTION_PARENT_BASIS_DIGEST,
            CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            1,
            1,
            &encoded,
        ),
        Err(ConstructionParentInputError::State(
            RelationError::Malformed("empty recovery root")
        ))
    ));
}

#[test]
fn descriptors_reject_invalid_scalars_and_points() {
    let mut zero = descriptors(2);
    zero[32..64].fill(0);
    assert!(matches!(
        parse(1, 1, &zero),
        Err(ConstructionParentInputError::State(
            RelationError::Malformed("zero construction precommitment")
        ))
    ));

    let mut noncanonical = descriptors(2);
    noncanonical[32..64].copy_from_slice(&SECP_ORDER);
    assert!(matches!(
        parse(1, 1, &noncanonical),
        Err(ConstructionParentInputError::State(
            RelationError::Malformed("noncanonical secp scalar")
        ))
    ));

    let mut malformed_point = descriptors(2);
    malformed_point[64] = 4;
    assert!(matches!(
        parse(1, 1, &malformed_point),
        Err(ConstructionParentInputError::State(
            RelationError::Malformed("encoded secp point prefix")
        ))
    ));

    let mut malformed_offset = descriptors(2);
    malformed_offset[97] = 4;
    assert!(matches!(
        parse(1, 1, &malformed_offset),
        Err(ConstructionParentInputError::State(
            RelationError::Malformed("encoded secp point prefix")
        ))
    ));
}
