use super::*;

use ff::Field;
use std::io::Cursor;

use crate::construction_manifest::{
    ConstructionManifestLeaf, ConstructionManifestSeed, ConstructionRoot,
};
use crate::construction_profile::CONSTRUCTION_ROOT_ROUNDS;
use crate::secp_constants::SECP256K1_SCALAR_ORDER_BE as SECP_ORDER;
use crate::secp_native::{coordinate_field_value, SecpEncodedPointWitness, SecpScalarWitness};

fn generator_encoding() -> [u8; 33] {
    [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ]
}

fn root() -> ConstructionRoot {
    let mut encoded = [0; CONSTRUCTION_ROOT_BYTES];
    encoded[..33].copy_from_slice(&generator_encoding());
    encoded[64] = 1;
    for index in 0..CONSTRUCTION_ROOT_ROUNDS {
        encoded[65 + 32 * index + 31] = u8::try_from(index + 2).expect("small factor");
    }
    ConstructionRoot::parse(&encoded).expect("canonical construction root")
}

fn leaf(binding: u8) -> ConstructionManifestLeaf {
    ConstructionManifestLeaf::new(
        [binding; 32],
        SecpScalarWitness::from_u64(3).bytes,
        SecpEncodedPointWitness::identity().encoded,
        SecpEncodedPointWitness::identity().encoded,
    )
    .expect("canonical construction manifest leaf")
}

fn authenticated_state() -> ([Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY], [Scalar; 2]) {
    let root = root();
    let seed = ConstructionManifestSeed::new([0x31; 32], [0x52; 32], [0x71; 64], 1, 1)
        .expect("construction manifest seed");
    let expected_suffix = seed
        .derive_expected_final(&[leaf(0x61), leaf(0x62)])
        .expect("expected construction final state")
        .state_suffix_fields()
        .expect("expected construction suffix");
    let mut state = [Scalar::ZERO; CONSTRUCTION_RECURRENCE_STATE_ARITY];
    state[..CONSTRUCTION_ROOT_STATE_ARITY].copy_from_slice(&root.state_fields());
    state[CONSTRUCTION_ROOT_STATE_ARITY..].copy_from_slice(&expected_suffix);
    (state, expected_suffix)
}

#[test]
fn authenticated_final_state_yields_only_the_canonical_pending_root() {
    let (state, expected_suffix) = authenticated_state();
    let output = validated_output_from_authenticated_state(state, expected_suffix)
        .expect("authenticated construction parent output");
    assert_eq!(output.canonical_root_bytes(), root().canonical_bytes());
}

#[test]
fn authenticated_final_state_binds_manifest_and_index() {
    let (state, expected_suffix) = authenticated_state();
    let mut wrong_manifest = state;
    wrong_manifest[CONSTRUCTION_ROOT_STATE_ARITY] += Scalar::ONE;
    assert!(matches!(
        validated_output_from_authenticated_state(wrong_manifest, expected_suffix),
        Err(ConstructionParentVerifierError::FinalManifest)
    ));

    let mut wrong_index = state;
    wrong_index[CONSTRUCTION_ROOT_STATE_ARITY + 1] += Scalar::ONE;
    assert!(matches!(
        validated_output_from_authenticated_state(wrong_index, expected_suffix),
        Err(ConstructionParentVerifierError::FinalIndex)
    ));
}

#[test]
fn authenticated_final_state_rejects_malformed_pending_roots() {
    let (state, expected_suffix) = authenticated_state();

    let mut bad_prefix = state;
    bad_prefix[0] = Scalar::from(4);
    assert!(matches!(
        validated_output_from_authenticated_state(bad_prefix, expected_suffix),
        Err(ConstructionParentVerifierError::State(
            RelationError::Malformed("construction root point prefix")
        ))
    ));

    let mut bad_identity = state;
    bad_identity[0] = Scalar::ZERO;
    assert!(matches!(
        validated_output_from_authenticated_state(bad_identity, expected_suffix),
        Err(ConstructionParentVerifierError::State(
            RelationError::Malformed("construction root identity point")
        ))
    ));

    let mut bad_scalar = state;
    bad_scalar[2] = coordinate_field_value(SECP_ORDER).expect("group order is below field modulus");
    assert!(matches!(
        validated_output_from_authenticated_state(bad_scalar, expected_suffix),
        Err(ConstructionParentVerifierError::State(
            RelationError::Malformed("noncanonical secp scalar")
        ))
    ));
}

#[test]
fn qualified_loader_authenticates_before_decoding() {
    let mut artifact = Cursor::new(vec![0xa5; 16]);
    assert!(matches!(
        load_qualified_construction_parent_verifier(&mut artifact),
        Err(DirectNovaVerifierArtifactError::Length)
    ));
    assert_eq!(artifact.position(), 16);
}
