use super::*;

use ff::Field;

use crate::construction_manifest::{
    ConstructionManifestAnchor, ConstructionManifestSeed, ConstructionRoot,
    CONSTRUCTION_ROOT_ROUNDS,
};
use crate::parent_relation::SecpEncodedPointWitness;
use crate::secp_scalar::{coordinate_field_value, SecpScalarWitness};

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

fn root() -> ConstructionRoot {
    let mut encoded = [0; CONSTRUCTION_ROOT_BYTES];
    encoded[..33].copy_from_slice(&generator_encoding());
    encoded[64] = 1;
    for index in 0..CONSTRUCTION_ROOT_ROUNDS {
        encoded[65 + 32 * index + 31] = u8::try_from(index + 2).expect("small factor");
    }
    ConstructionRoot::parse(&encoded).expect("canonical construction root")
}

fn anchor(binding: u8) -> ConstructionManifestAnchor {
    ConstructionManifestAnchor::new(
        [binding; 32],
        SecpScalarWitness::from_u64(3),
        SecpEncodedPointWitness::identity(),
        SecpEncodedPointWitness::identity(),
    )
    .expect("canonical construction manifest anchor")
}

fn authenticated_state() -> ([Scalar; ANCHOR_RECURRENCE_STATE_ARITY], [Scalar; 2]) {
    let root = root();
    let seed = ConstructionManifestSeed::new([0x31; 32], [0x52; 32], root.clone(), 2)
        .expect("construction manifest seed");
    let expected_suffix = seed
        .derive_expected_final(&[anchor(0x61), anchor(0x62)])
        .expect("expected construction final state")
        .state_suffix_fields()
        .expect("expected construction suffix");
    let mut state = [Scalar::ZERO; ANCHOR_RECURRENCE_STATE_ARITY];
    state[..CONSTRUCTION_ROOT_STATE_ARITY]
        .copy_from_slice(&root.state_fields().expect("construction root fields"));
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
            ReceiptCycleError::Malformed("construction root point prefix")
        ))
    ));

    let mut bad_identity = state;
    bad_identity[0] = Scalar::ZERO;
    assert!(matches!(
        validated_output_from_authenticated_state(bad_identity, expected_suffix),
        Err(ConstructionParentVerifierError::State(
            ReceiptCycleError::Malformed("construction root identity point")
        ))
    ));

    let mut bad_scalar = state;
    bad_scalar[2] = coordinate_field_value(SECP_ORDER).expect("group order is below field modulus");
    assert!(matches!(
        validated_output_from_authenticated_state(bad_scalar, expected_suffix),
        Err(ConstructionParentVerifierError::State(
            ReceiptCycleError::Malformed("noncanonical secp scalar")
        ))
    ));
}

#[test]
fn qualified_verifier_artifact_identity_is_frozen() {
    assert_eq!(
        QUALIFIED_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT.encoded_length(),
        638_174_560
    );
    assert_eq!(
        QUALIFIED_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT.digest(),
        [
            0x7b, 0x2f, 0xca, 0xfb, 0x64, 0x75, 0xc8, 0x70, 0x92, 0x5c, 0x2c, 0x00, 0xb0, 0xab,
            0x9e, 0xba, 0x53, 0x9b, 0xc5, 0x40, 0xe3, 0x4d, 0xb1, 0x46, 0x78, 0xcf, 0x00, 0x52,
            0x13, 0xbd, 0xeb, 0xd5,
        ]
    );
}

#[test]
#[ignore = "requires the separately qualified 609 MiB verifier artifact"]
fn qualified_verifier_artifact_loads_exactly() {
    let path = std::env::var_os("PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT")
        .expect("qualified verifier artifact path");
    let mut artifact = std::fs::File::open(path).expect("open qualified verifier artifact");
    let verifier = load_qualified_construction_parent_verifier(&mut artifact)
        .expect("authenticate and load qualified verifier artifact");
    assert_eq!(
        verifier.expected(),
        &QUALIFIED_CONSTRUCTION_PARENT_NOVA_SUITE
    );
    assert_eq!(verifier.metadata().proof_length, 12_466);
    assert_eq!(verifier.metadata().codec_sequence_count, 125);
}
