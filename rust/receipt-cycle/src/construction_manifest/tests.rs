use super::*;

const SECP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const SECP_FIELD: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

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

fn put_u64_scalar(encoded: &mut [u8; CONSTRUCTION_SEED_ROOT_BYTES], offset: usize, value: u64) {
    encoded[offset + 24..offset + 32].copy_from_slice(&value.to_be_bytes());
}

fn seed_bytes() -> [u8; CONSTRUCTION_SEED_ROOT_BYTES] {
    let mut encoded = [0; CONSTRUCTION_SEED_ROOT_BYTES];
    encoded[..33].copy_from_slice(&generator().encoded);
    put_u64_scalar(&mut encoded, 33, 1);
    for index in 0..CONSTRUCTION_ROOT_ROUNDS {
        put_u64_scalar(&mut encoded, 65 + 32 * index, index as u64 + 2);
    }
    encoded
}

fn seed_root() -> ConstructionRegistrySeedRoot {
    ConstructionRegistrySeedRoot::parse(&seed_bytes()).expect("canonical registry seed")
}

fn manifest_seed(count: u64) -> ConstructionManifestSeed {
    ConstructionManifestSeed::new([0x31; 32], [0x52; 32], seed_root(), count)
        .expect("construction manifest seed")
}

fn anchor(
    marker: u8,
    coefficient_commitment: SecpEncodedPointWitness,
    anchored_offset: SecpEncodedPointWitness,
) -> ConstructionManifestAnchor {
    ConstructionManifestAnchor::new(
        [marker; 32],
        SecpScalarWitness::from_u64(u64::from(marker) + 1),
        coefficient_commitment,
        anchored_offset,
    )
    .expect("construction manifest anchor")
}

#[test]
fn registry_seed_is_byte_identical_and_maps_to_18_fields() {
    let encoded = seed_bytes();
    let root = ConstructionRegistrySeedRoot::parse(&encoded).expect("registry seed");
    assert_eq!(root.canonical_bytes(), &encoded);
    assert_eq!(root.claim.point, generator());
    assert_eq!(root.claim.factors.len(), CONSTRUCTION_ROOT_ROUNDS);

    let fields = root.state_fields().expect("root state fields");
    assert_eq!(fields.len(), CONSTRUCTION_ROOT_STATE_ARITY);
    assert_eq!(fields[0], Scalar::from(2));
    assert_eq!(
        fields[1],
        encoded_point_value(generator()).expect("generator").x
    );
    assert_eq!(fields[2], Scalar::ONE);
    for index in 0..CONSTRUCTION_ROOT_ROUNDS {
        assert_eq!(fields[3 + index], Scalar::from(index as u64 + 2));
    }

    let mut odd_encoded = encoded;
    odd_encoded[0] = 3;
    let odd = ConstructionRegistrySeedRoot::parse(&odd_encoded).expect("odd root point");
    assert_eq!(odd.claim.point.y[0] & 1, 1);
    assert_eq!(
        odd.state_fields().expect("odd root fields")[0],
        Scalar::from(3)
    );
}

#[test]
fn registry_seed_parser_rejects_noncanonical_root_encodings() {
    assert!(
        ConstructionRegistrySeedRoot::parse(&seed_bytes()[..CONSTRUCTION_SEED_ROOT_BYTES - 1])
            .is_err()
    );

    let mut bad_prefix = seed_bytes();
    bad_prefix[0] = 4;
    assert!(ConstructionRegistrySeedRoot::parse(&bad_prefix).is_err());

    let mut identity = seed_bytes();
    identity[..33].fill(0);
    let identity = ConstructionRegistrySeedRoot::parse(&identity).expect("identity root point");
    assert_eq!(
        &identity.state_fields().expect("identity root fields")[..2],
        &[Scalar::ZERO, Scalar::ZERO]
    );

    let mut noncanonical_identity = seed_bytes();
    noncanonical_identity[0] = 0;
    assert!(ConstructionRegistrySeedRoot::parse(&noncanonical_identity).is_err());

    let mut bad_x = seed_bytes();
    bad_x[1..33].copy_from_slice(&SECP_FIELD);
    assert!(ConstructionRegistrySeedRoot::parse(&bad_x).is_err());

    // x = 0 is canonical, but x^3 + 7 is a nonsquare modulo secp256k1 p.
    let mut nonsquare_x = seed_bytes();
    nonsquare_x[1..33].fill(0);
    assert!(ConstructionRegistrySeedRoot::parse(&nonsquare_x).is_err());

    let mut bad_scale = seed_bytes();
    bad_scale[33..65].copy_from_slice(&SECP_ORDER);
    assert!(ConstructionRegistrySeedRoot::parse(&bad_scale).is_err());

    let mut bad_factor = seed_bytes();
    bad_factor[65..97].copy_from_slice(&SECP_ORDER);
    assert!(ConstructionRegistrySeedRoot::parse(&bad_factor).is_err());
}

#[test]
fn initial_state_is_fully_verifier_derived_and_starts_at_zero() {
    let seed = manifest_seed(2);
    let witness = seed.initial_recurrence_witness();
    assert_eq!(witness.index, 0);
    assert_eq!(witness.manifest, seed.initial_manifest());
    assert_eq!(witness.root, seed.root.claim());

    let fields = seed.initial_state_fields().expect("initial state fields");
    assert_eq!(
        witness.state_fields().expect("recurrence witness fields"),
        fields
    );
    assert_eq!(fields.len(), CONSTRUCTION_STATE_ARITY);
    assert_eq!(
        &fields[..CONSTRUCTION_ROOT_STATE_ARITY],
        &seed.root.state_fields().expect("root fields")
    );
    assert_eq!(
        fields[CONSTRUCTION_ROOT_STATE_ARITY],
        coordinate_field_value(seed.initial_manifest()).expect("manifest field")
    );
    assert_eq!(fields[CONSTRUCTION_ROOT_STATE_ARITY + 1], Scalar::ZERO);
}

#[test]
fn initial_manifest_binds_statement_setup_root_and_count() {
    let baseline = manifest_seed(2).initial_manifest();
    let changed_statement = ConstructionManifestSeed::new([0x32; 32], [0x52; 32], seed_root(), 2)
        .expect("changed statement")
        .initial_manifest();
    let changed_setup = ConstructionManifestSeed::new([0x31; 32], [0x53; 32], seed_root(), 2)
        .expect("changed setup")
        .initial_manifest();
    let mut changed_root_bytes = seed_bytes();
    put_u64_scalar(&mut changed_root_bytes, 65, 99);
    let changed_root = ConstructionManifestSeed::new(
        [0x31; 32],
        [0x52; 32],
        ConstructionRegistrySeedRoot::parse(&changed_root_bytes).expect("changed root"),
        2,
    )
    .expect("changed root seed")
    .initial_manifest();
    let changed_count = manifest_seed(3).initial_manifest();

    for changed in [
        changed_statement,
        changed_setup,
        changed_root,
        changed_count,
    ] {
        assert_ne!(changed, baseline);
    }
}

#[test]
fn initial_seed_rejects_unresolved_empty_and_overflow_inputs() {
    assert!(ConstructionManifestSeed::new([0x31; 32], [0; 32], seed_root(), 1).is_err());
    assert!(ConstructionManifestSeed::new([0x31; 32], [0x52; 32], seed_root(), 0).is_err());
    assert!(ConstructionManifestSeed::new(
        [0x31; 32],
        [0x52; 32],
        seed_root(),
        u64::from(u32::MAX),
    )
    .is_ok());
    assert!(ConstructionManifestSeed::new(
        [0x31; 32],
        [0x52; 32],
        seed_root(),
        u64::from(u32::MAX) + 1,
    )
    .is_err());
}

#[test]
fn ordered_iteration_binds_count_order_and_substitution() {
    let first = anchor(0x11, generator(), SecpEncodedPointWitness::identity());
    let second = anchor(0x22, SecpEncodedPointWitness::identity(), generator());
    let seed = manifest_seed(2);
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

    let substituted = anchor(0x12, generator(), SecpEncodedPointWitness::identity());
    let substituted = seed
        .derive_expected_final(&[substituted, second])
        .expect("substituted manifest");
    assert_ne!(substituted.manifest(), expected.manifest());

    assert!(manifest_seed(3)
        .derive_expected_final(&[first, second])
        .is_err());
    assert!(manifest_seed(1)
        .derive_expected_final(&[first, second])
        .is_err());
}

#[test]
fn step_manifest_binds_every_constrained_public_input() {
    let prior = manifest_seed(1).initial_manifest();
    let baseline_anchor = anchor(0x11, generator(), SecpEncodedPointWitness::identity());
    let baseline = derive_step_manifest(
        &ConstructionManifestStepInput::new(prior, 0, baseline_anchor).expect("baseline input"),
    )
    .expect("baseline manifest");

    let changed_prior =
        ConstructionManifestStepInput::new([0; 32], 0, baseline_anchor).expect("changed prior");
    let changed_index =
        ConstructionManifestStepInput::new(prior, 1, baseline_anchor).expect("changed index");
    let changed_binding = ConstructionManifestStepInput::new(
        prior,
        0,
        anchor(0x12, generator(), SecpEncodedPointWitness::identity()),
    )
    .expect("changed binding");
    let changed_precommitment = ConstructionManifestStepInput::new(
        prior,
        0,
        ConstructionManifestAnchor::new(
            [0x11; 32],
            SecpScalarWitness::from_u64(0x99),
            generator(),
            SecpEncodedPointWitness::identity(),
        )
        .expect("changed precommitment anchor"),
    )
    .expect("changed precommitment");
    let changed_commitment = ConstructionManifestStepInput::new(
        prior,
        0,
        anchor(
            0x11,
            SecpEncodedPointWitness::identity(),
            SecpEncodedPointWitness::identity(),
        ),
    )
    .expect("changed coefficient commitment");
    let changed_offset =
        ConstructionManifestStepInput::new(prior, 0, anchor(0x11, generator(), generator()))
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
    let valid = anchor(0x11, generator(), SecpEncodedPointWitness::identity());
    assert!(ConstructionManifestStepInput::new(SECP_FIELD, 0, valid).is_err());
    assert!(ConstructionManifestAnchor::new(
        [0x11; 32],
        SecpScalarWitness::from_u64(0),
        generator(),
        SecpEncodedPointWitness::identity(),
    )
    .is_err());
    assert!(ConstructionManifestAnchor::new(
        [0x11; 32],
        SecpScalarWitness::from_bytes_be(SECP_ORDER),
        generator(),
        SecpEncodedPointWitness::identity(),
    )
    .is_err());

    let mut bad_point = generator();
    bad_point.encoded[0] = 4;
    assert!(ConstructionManifestAnchor::new(
        [0x11; 32],
        SecpScalarWitness::from_u64(1),
        bad_point,
        SecpEncodedPointWitness::identity(),
    )
    .is_err());
}

#[test]
fn step_index_is_zero_based_and_overflow_checked() {
    let seed = manifest_seed(1);
    let anchor = anchor(0x11, generator(), SecpEncodedPointWitness::identity());
    let zero = ConstructionManifestStepInput::new(seed.initial_manifest(), 0, anchor)
        .expect("zero-based step");
    let one = ConstructionManifestStepInput::new(seed.initial_manifest(), 1, anchor)
        .expect("next-index step");
    assert_ne!(
        derive_step_manifest(&zero).expect("zero manifest"),
        derive_step_manifest(&one).expect("one manifest")
    );
    assert_eq!(
        derive_step_manifest(&zero).expect("first step"),
        seed.derive_expected_final(&[anchor])
            .expect("one-step manifest")
            .manifest()
    );
    assert_eq!(
        derive_step_manifest(&zero).expect("stable first step"),
        [
            0xb3, 0xd1, 0xab, 0x68, 0x41, 0x15, 0x55, 0xec, 0x21, 0x9f, 0xe7, 0x2a, 0x7b, 0x40,
            0x25, 0x89, 0x37, 0x58, 0x52, 0x3d, 0x15, 0x5c, 0x6a, 0x8c, 0x0c, 0xb1, 0x44, 0x2a,
            0xbd, 0xcc, 0x2a, 0x0a,
        ]
    );

    let exhausted = ConstructionManifestState {
        manifest: seed.initial_manifest(),
        index: u32::MAX,
    };
    assert!(exhausted.advance(anchor).is_err());
}

#[test]
fn initial_manifest_vector_is_stable() {
    assert_eq!(
        manifest_seed(2).initial_manifest(),
        [
            0xcc, 0x3a, 0x4e, 0x76, 0x09, 0x52, 0xf1, 0xc6, 0x45, 0x6c, 0xaa, 0xbe, 0x5a, 0x67,
            0xb6, 0xc7, 0x4d, 0xea, 0xd5, 0x34, 0xa9, 0xb1, 0x34, 0x09, 0x62, 0x4b, 0x84, 0x0f,
            0x1e, 0x2c, 0xa9, 0x44,
        ]
    );
}
