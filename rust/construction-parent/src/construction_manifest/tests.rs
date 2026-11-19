use super::*;

use crate::secp_constants::{
    SECP256K1_BASE_FIELD_MODULUS_BE as SECP_FIELD, SECP256K1_SCALAR_ORDER_BE as SECP_ORDER,
};

fn generator() -> SecpEncodedPointWitness {
    let mut encoded = [0; 33];
    encoded[0] = 2;
    encoded[1..].copy_from_slice(&[
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ]);
    SecpEncodedPointWitness {
        encoded,
        y: [
            0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c, 0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4,
            0x17, 0xfd, 0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d, 0x65, 0xc4, 0xa3, 0x26,
            0x77, 0xda, 0x3a, 0x48,
        ],
    }
}

fn put_u64_scalar(encoded: &mut [u8; CONSTRUCTION_ROOT_BYTES], offset: usize, value: u64) {
    encoded[offset + 24..offset + 32].copy_from_slice(&value.to_be_bytes());
}

fn seed_bytes() -> [u8; CONSTRUCTION_ROOT_BYTES] {
    let mut encoded = [0; CONSTRUCTION_ROOT_BYTES];
    encoded[..33].copy_from_slice(&generator().encoded);
    put_u64_scalar(&mut encoded, 33, 1);
    for index in 0..CONSTRUCTION_ROOT_ROUNDS {
        put_u64_scalar(&mut encoded, 65 + 32 * index, index as u64 + 2);
    }
    encoded
}

fn nonzero_root() -> ConstructionRoot {
    ConstructionRoot::parse(&seed_bytes()).expect("canonical nonzero root")
}

fn recovery_root() -> [u8; 64] {
    [0x71; 64]
}

fn manifest_seed(setup_count: u32, anchor_count: u32) -> ConstructionManifestSeed {
    ConstructionManifestSeed::new(
        [0x31; 32],
        [0x52; 32],
        recovery_root(),
        setup_count,
        anchor_count,
    )
    .expect("construction manifest seed")
}

fn leaf(
    marker: u8,
    coefficient_commitment: SecpEncodedPointWitness,
    anchored_offset: SecpEncodedPointWitness,
) -> ConstructionManifestLeaf {
    ConstructionManifestLeaf::new(
        [marker; 32],
        SecpScalarWitness::from_u64(u64::from(marker) + 1).bytes,
        coefficient_commitment.encoded,
        anchored_offset.encoded,
    )
    .expect("construction manifest leaf")
}

#[test]
fn root_claim_is_byte_identical_and_maps_to_18_fields() {
    assert_eq!(CONSTRUCTION_ROOT_BYTES, 545);
    let encoded = seed_bytes();
    let root = ConstructionRoot::parse(&encoded).expect("root claim");
    assert_eq!(root.canonical_bytes(), &encoded);
    let claim = root.claim();
    assert_eq!(claim.point, generator());
    assert_eq!(claim.factors.len(), CONSTRUCTION_ROOT_ROUNDS);

    let fields = root.state_fields();
    assert_eq!(fields.len(), CONSTRUCTION_ROOT_STATE_ARITY);
    assert_eq!(fields[0], Scalar::from(2));
    assert_eq!(
        fields[1],
        canonical_encoded_point_value(generator().encoded)
            .expect("generator")
            .x
    );
    assert_eq!(fields[2], Scalar::ONE);
    for index in 0..CONSTRUCTION_ROOT_ROUNDS {
        assert_eq!(fields[3 + index], Scalar::from(index as u64 + 2));
    }
    let reconstructed =
        ConstructionRoot::from_state_fields(fields).expect("root reconstructed from fields");
    assert_eq!(reconstructed, root);
    assert_eq!(reconstructed.canonical_bytes(), &encoded);

    let mut odd_encoded = encoded;
    odd_encoded[0] = 3;
    let odd = ConstructionRoot::parse(&odd_encoded).expect("odd root point");
    assert_eq!(odd.claim().point.y[0] & 1, 1);
    assert_eq!(odd.state_fields()[0], Scalar::from(3));
    assert_eq!(
        ConstructionRoot::from_state_fields(odd.state_fields())
            .expect("odd root reconstructed")
            .canonical_bytes(),
        &odd_encoded
    );
}

#[test]
fn root_claim_parser_rejects_noncanonical_encodings() {
    assert!(ConstructionRoot::parse(&seed_bytes()[..CONSTRUCTION_ROOT_BYTES - 1]).is_err());

    let mut bad_prefix = seed_bytes();
    bad_prefix[0] = 4;
    assert!(ConstructionRoot::parse(&bad_prefix).is_err());

    let mut identity = seed_bytes();
    identity[..33].fill(0);
    let identity = ConstructionRoot::parse(&identity).expect("identity root point");
    let identity_fields = identity.state_fields();
    assert_eq!(&identity_fields[..2], &[Scalar::ZERO, Scalar::ZERO]);
    assert_eq!(
        ConstructionRoot::from_state_fields(identity_fields)
            .expect("identity root reconstructed")
            .canonical_bytes(),
        identity.canonical_bytes()
    );

    let mut noncanonical_identity = seed_bytes();
    noncanonical_identity[0] = 0;
    assert!(ConstructionRoot::parse(&noncanonical_identity).is_err());

    let mut bad_x = seed_bytes();
    bad_x[1..33].copy_from_slice(&SECP_FIELD);
    assert!(ConstructionRoot::parse(&bad_x).is_err());

    // x = 0 is canonical, but x^3 + 7 is a nonsquare modulo secp256k1 p.
    let mut nonsquare_x = seed_bytes();
    nonsquare_x[1..33].fill(0);
    assert!(ConstructionRoot::parse(&nonsquare_x).is_err());

    let mut bad_scale = seed_bytes();
    bad_scale[33..65].copy_from_slice(&SECP_ORDER);
    assert!(ConstructionRoot::parse(&bad_scale).is_err());

    let mut bad_factor = seed_bytes();
    bad_factor[65..97].copy_from_slice(&SECP_ORDER);
    assert!(ConstructionRoot::parse(&bad_factor).is_err());

    let fields = nonzero_root().state_fields();
    let mut invalid_prefix = fields;
    invalid_prefix[0] = Scalar::from(4);
    assert!(ConstructionRoot::from_state_fields(invalid_prefix).is_err());

    let mut invalid_identity = fields;
    invalid_identity[0] = Scalar::ZERO;
    assert!(ConstructionRoot::from_state_fields(invalid_identity).is_err());

    let mut nonsquare_point = fields;
    nonsquare_point[1] = Scalar::ZERO;
    assert!(ConstructionRoot::from_state_fields(nonsquare_point).is_err());

    let noncanonical_scalar = coordinate_field_value(SECP_ORDER).expect("group order below field");
    let mut noncanonical_scale = fields;
    noncanonical_scale[2] = noncanonical_scalar;
    assert!(ConstructionRoot::from_state_fields(noncanonical_scale).is_err());

    let mut noncanonical_factor = fields;
    noncanonical_factor[3] = noncanonical_scalar;
    assert!(ConstructionRoot::from_state_fields(noncanonical_factor).is_err());
}

#[test]
fn initial_state_is_fully_verifier_derived_and_starts_at_zero() {
    let seed = manifest_seed(1, 1);
    assert_eq!(seed.root.canonical_bytes(), &[0; CONSTRUCTION_ROOT_BYTES]);
    let witness = seed
        .initial_recurrence_witness()
        .expect("nonzero initial manifest");
    assert_eq!(witness.index, 0);
    assert_eq!(
        witness.manifest,
        seed.initial_manifest().expect("nonzero initial manifest")
    );
    assert_eq!(witness.root, seed.root.claim());

    let fields = seed.initial_state_fields().expect("initial state fields");
    assert_eq!(
        witness.state_fields().expect("recurrence witness fields"),
        fields
    );
    assert_eq!(fields.len(), CONSTRUCTION_STATE_ARITY);
    assert_eq!(
        &fields[..CONSTRUCTION_ROOT_STATE_ARITY],
        &seed.root.state_fields()
    );
    assert_eq!(
        fields[CONSTRUCTION_ROOT_STATE_ARITY],
        coordinate_field_value(seed.initial_manifest().expect("nonzero initial manifest"))
            .expect("manifest field")
    );
    assert_eq!(fields[CONSTRUCTION_ROOT_STATE_ARITY + 1], Scalar::ZERO);
}

#[test]
fn initial_manifest_binds_statement_setup_root_and_counts() {
    let baseline = manifest_seed(1, 1)
        .initial_manifest()
        .expect("nonzero baseline manifest");
    let changed_statement =
        ConstructionManifestSeed::new([0x32; 32], [0x52; 32], recovery_root(), 1, 1)
            .expect("changed statement")
            .initial_manifest()
            .expect("nonzero changed statement manifest");
    let changed_setup =
        ConstructionManifestSeed::new([0x31; 32], [0x53; 32], recovery_root(), 1, 1)
            .expect("changed setup")
            .initial_manifest()
            .expect("nonzero changed setup manifest");
    let changed_recovery_root =
        ConstructionManifestSeed::new([0x31; 32], [0x52; 32], [0x72; 64], 1, 1)
            .expect("changed recovery root seed")
            .initial_manifest()
            .expect("nonzero changed recovery root manifest");
    let changed_setup_count = manifest_seed(2, 1)
        .initial_manifest()
        .expect("nonzero changed setup count manifest");
    let changed_anchor_count = manifest_seed(1, 2)
        .initial_manifest()
        .expect("nonzero changed anchor count manifest");

    for changed in [
        changed_statement,
        changed_setup,
        changed_recovery_root,
        changed_setup_count,
        changed_anchor_count,
    ] {
        assert_ne!(changed, baseline);
    }
}

#[test]
fn initial_manifest_binds_phase_boundary_with_the_same_total() {
    let one_setup = manifest_seed(1, 2)
        .initial_manifest()
        .expect("one-setup initial manifest");
    let two_setups = manifest_seed(2, 1)
        .initial_manifest()
        .expect("two-setup initial manifest");
    assert_ne!(one_setup, two_setups);
}

#[test]
fn initial_seed_rejects_unresolved_and_empty_inputs() {
    assert!(ConstructionManifestSeed::new([0x31; 32], [0; 32], recovery_root(), 1, 1).is_err());
    assert!(ConstructionManifestSeed::new([0x31; 32], [0x52; 32], [0; 64], 1, 1).is_err());
    assert!(ConstructionManifestSeed::new([0x31; 32], [0x52; 32], recovery_root(), 0, 1).is_err());
    assert!(ConstructionManifestSeed::new([0x31; 32], [0x52; 32], recovery_root(), 1, 0).is_err());
    assert!(
        ConstructionManifestSeed::new([0x31; 32], [0x52; 32], recovery_root(), u32::MAX, 1)
            .is_err()
    );
}

#[test]
fn ordered_iteration_binds_count_order_and_substitution() {
    let first = leaf(0x11, generator(), SecpEncodedPointWitness::identity());
    let second = leaf(0x22, SecpEncodedPointWitness::identity(), generator());
    let seed = manifest_seed(1, 1);
    let expected = seed
        .derive_expected_final(&[first, second])
        .expect("ordered manifest");
    assert_eq!(expected.index(), 2);
    assert_eq!(
        expected
            .state_suffix_fields()
            .expect("final manifest fields"),
        [
            coordinate_field_value(expected.manifest()).expect("final manifest field"),
            Scalar::from(2),
        ]
    );

    let reversed = seed
        .derive_expected_final(&[second, first])
        .expect("reversed manifest");
    assert_ne!(reversed.manifest(), expected.manifest());

    let substituted = leaf(0x12, generator(), SecpEncodedPointWitness::identity());
    let substituted = seed
        .derive_expected_final(&[substituted, second])
        .expect("substituted manifest");
    assert_ne!(substituted.manifest(), expected.manifest());

    assert!(manifest_seed(2, 1)
        .derive_expected_final(&[first, second])
        .is_err());
    assert!(manifest_seed(2, 2)
        .derive_expected_final(&[first, second])
        .is_err());
}

#[test]
fn step_manifest_binds_every_constrained_public_input() {
    let prior = manifest_seed(1, 1)
        .initial_manifest()
        .expect("nonzero prior manifest");
    let baseline_leaf = leaf(0x11, generator(), SecpEncodedPointWitness::identity());
    let baseline = derive_step_manifest(
        &ConstructionManifestStepInput::new(prior, 0, baseline_leaf).expect("baseline input"),
    )
    .expect("baseline manifest");

    let changed_prior =
        ConstructionManifestStepInput::new([0; 32], 0, baseline_leaf).expect("changed prior");
    let changed_index =
        ConstructionManifestStepInput::new(prior, 1, baseline_leaf).expect("changed index");
    let changed_binding = ConstructionManifestStepInput::new(
        prior,
        0,
        leaf(0x12, generator(), SecpEncodedPointWitness::identity()),
    )
    .expect("changed binding");
    let changed_precommitment = ConstructionManifestStepInput::new(
        prior,
        0,
        ConstructionManifestLeaf::new(
            [0x11; 32],
            SecpScalarWitness::from_u64(0x99).bytes,
            generator().encoded,
            SecpEncodedPointWitness::identity().encoded,
        )
        .expect("changed precommitment leaf"),
    )
    .expect("changed precommitment");
    let changed_commitment = ConstructionManifestStepInput::new(
        prior,
        0,
        leaf(
            0x11,
            SecpEncodedPointWitness::identity(),
            SecpEncodedPointWitness::identity(),
        ),
    )
    .expect("changed coefficient commitment");
    let changed_offset =
        ConstructionManifestStepInput::new(prior, 0, leaf(0x11, generator(), generator()))
            .expect("changed anchored offset");

    for changed in [
        changed_prior,
        changed_index,
        changed_binding,
        changed_precommitment,
        changed_commitment,
        changed_offset,
    ] {
        assert_ne!(
            derive_step_manifest(&changed).expect("changed manifest"),
            baseline
        );
    }
}

#[test]
fn step_input_rejects_noncanonical_fields_points_and_precommitments() {
    let valid = leaf(0x11, generator(), SecpEncodedPointWitness::identity());
    assert!(ConstructionManifestStepInput::new(SECP_FIELD, 0, valid).is_err());
    assert!(ConstructionManifestLeaf::new(
        [0x11; 32],
        SecpScalarWitness::from_u64(0).bytes,
        generator().encoded,
        SecpEncodedPointWitness::identity().encoded,
    )
    .is_err());
    assert!(ConstructionManifestLeaf::new(
        [0x11; 32],
        SECP_ORDER,
        generator().encoded,
        SecpEncodedPointWitness::identity().encoded,
    )
    .is_err());

    let mut bad_point = generator();
    bad_point.encoded[0] = 4;
    assert!(ConstructionManifestLeaf::new(
        [0x11; 32],
        SecpScalarWitness::from_u64(1).bytes,
        bad_point.encoded,
        SecpEncodedPointWitness::identity().encoded,
    )
    .is_err());
}

#[test]
fn manifest_leaf_validates_public_point_encodings() {
    let coefficient = generator().encoded;
    let mut odd_encoding = generator().encoded;
    odd_encoding[0] = 3;

    ConstructionManifestLeaf::new(
        [0x41; 32],
        SecpScalarWitness::from_u64(7).bytes,
        coefficient,
        odd_encoding,
    )
    .expect("manifest leaf from canonical public points");
}

#[test]
fn step_index_is_zero_based_and_overflow_checked() {
    let seed = manifest_seed(1, 1);
    let leaf = leaf(0x11, generator(), SecpEncodedPointWitness::identity());
    let initial = seed.initial_manifest().expect("nonzero initial manifest");
    let zero = ConstructionManifestStepInput::new(initial, 0, leaf).expect("zero-based step");
    let one = ConstructionManifestStepInput::new(initial, 1, leaf).expect("next-index step");
    assert_ne!(
        derive_step_manifest(&zero).expect("zero manifest"),
        derive_step_manifest(&one).expect("one manifest")
    );
    assert_eq!(
        derive_step_manifest(&zero).expect("first step"),
        ConstructionManifestState {
            manifest: initial,
            index: 0
        }
        .advance(leaf)
        .expect("one-step manifest")
        .manifest()
    );
    assert_eq!(
        derive_step_manifest(&zero).expect("stable first step"),
        [
            0x7b, 0x78, 0xe4, 0xc7, 0x5c, 0x38, 0xf3, 0xa5, 0x69, 0x63, 0x19, 0x9a, 0x99, 0x45,
            0x60, 0x83, 0x06, 0x01, 0x66, 0x66, 0x3e, 0x2b, 0x37, 0x1e, 0x48, 0x13, 0x43, 0x2a,
            0xc7, 0xea, 0x46, 0x11,
        ]
    );

    let exhausted = ConstructionManifestState {
        manifest: seed.initial_manifest().expect("nonzero initial manifest"),
        index: u32::MAX,
    };
    assert!(exhausted.advance(leaf).is_err());
}

#[test]
fn initial_manifest_vector_is_stable() {
    assert_eq!(
        manifest_seed(1, 1)
            .initial_manifest()
            .expect("nonzero initial manifest"),
        [
            0x62, 0xe9, 0xee, 0xef, 0x66, 0x4c, 0x32, 0x24, 0x46, 0x7d, 0xae, 0x69, 0x2b, 0x52,
            0xef, 0x0a, 0x06, 0x02, 0x07, 0x4f, 0xb9, 0x60, 0xd0, 0x71, 0xce, 0xac, 0xb1, 0xef,
            0x45, 0x1d, 0xd9, 0x99,
        ]
    );
}
