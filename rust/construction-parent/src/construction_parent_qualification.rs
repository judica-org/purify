use ff::Field;
use nova_snark::{
    frontend::{
        gadgets::num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError,
        Variable,
    },
    nova::{PublicParams, PublicParamsShapeMetrics, R1CSShapeMetrics},
    traits::circuit::StepCircuit,
};
use sha2::{Digest, Sha256};

use crate::candidate::{CandidateRootClaim, CandidateStepProofWitness};
use crate::circuit_norm::{
    CandidateNormReductionProofWitness, ManifestBoundConstructionLeafStatementV4,
};
use crate::circuit_transcript::{
    CircuitCommitmentModeV4, CircuitPointPairWitnessV4, CircuitProofTranscriptWitnessV4,
    CircuitTranscriptShapeV4,
};
use crate::construction_manifest::ConstructionRoot;
use crate::construction_parent_prover_fixture::ConstructionParentProverFixture;
use crate::construction_profile::{
    CONSTRUCTION_LEAF_GATE_COUNT, CONSTRUCTION_LEAF_NORM_LENGTH, CONSTRUCTION_LEAF_ROUNDS,
    CONSTRUCTION_PARENT_BASIS_DIGEST, CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
    CONSTRUCTION_RECURRENCE_STATE_ARITY, CONSTRUCTION_ROOT_BYTES, CONSTRUCTION_ROOT_ROUNDS,
    CONSTRUCTION_ROOT_STATE_ARITY,
};
use crate::construction_recurrence::{
    validate_production_shape, ConstructionRecurrenceStateWitness,
};
use crate::fixed_serde::{NovaCompressedProofShape, NovaR1csDimensions};
use crate::nova_construction_recurrence::{
    ConstructionParentStep, TestConstructionParentStep, PROVISIONAL_CONSTRUCTION_PARENT_RELATION_ID,
};
use crate::nova_relation_identity::direct_step_relation_shape;
use crate::nova_session::{
    NovaSessionStep, NovaSessionSuite, SelectedNovaSessionSuite,
    MIXED_CONSTRUCTION_QUALIFICATION_VERSIONS, PROVISIONAL_CONSTRUCTION_PARENT_PROOF_LENGTH,
};
use crate::nova_types::{DirectNovaPrimaryEngine, DirectNovaScalar, DirectNovaSecondaryEngine};
use crate::secp_native::{standard_generator, SecpEncodedPointWitness, SecpScalarWitness};
use crate::{scalar_to_canonical, Scalar};

const DIRECT_PARENT_AUXILIARY: usize = 7_609_070;
const DIRECT_PARENT_CONSTRAINTS: usize = 7_653_610;

type ConstructionParentNovaSuite =
    SelectedNovaSessionSuite<CONSTRUCTION_RECURRENCE_STATE_ARITY, ConstructionParentStep>;

struct BoundQualificationFixture {
    initial_state: [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
    final_state: [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
    steps: Vec<ConstructionParentStep>,
}

struct CheckingWitnessCS {
    inputs: Vec<Scalar>,
    auxiliary: Vec<Scalar>,
    constraints: usize,
    first_unsatisfied: Option<usize>,
}

impl CheckingWitnessCS {
    fn new() -> Self {
        Self::with_auxiliary_capacity(0)
    }

    fn with_auxiliary_capacity(capacity: usize) -> Self {
        Self {
            inputs: vec![Scalar::ONE],
            auxiliary: Vec::with_capacity(capacity),
            constraints: 0,
            first_unsatisfied: None,
        }
    }

    fn value(&self, variable: Variable) -> Scalar {
        match variable.get_unchecked() {
            Index::Input(index) => self.inputs[index],
            Index::Aux(index) => self.auxiliary[index],
        }
    }

    fn evaluate(&self, linear: &LinearCombination<Scalar>) -> Scalar {
        linear
            .iter()
            .fold(Scalar::ZERO, |value, (variable, coefficient)| {
                value + self.value(variable) * coefficient
            })
    }

    fn assert_satisfied(&self) {
        assert_eq!(
            self.first_unsatisfied,
            None,
            "constraint {} is unsatisfied",
            self.first_unsatisfied.unwrap_or_default()
        );
    }
}

impl ConstraintSystem<Scalar> for CheckingWitnessCS {
    type Root = Self;

    fn alloc<F, A, AR>(&mut self, _annotation: A, value: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.auxiliary.len();
        self.auxiliary.push(value()?);
        Ok(Variable::new_unchecked(Index::Aux(index)))
    }

    fn alloc_input<F, A, AR>(
        &mut self,
        _annotation: A,
        value: F,
    ) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<Scalar, SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let index = self.inputs.len();
        self.inputs.push(value()?);
        Ok(Variable::new_unchecked(Index::Input(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _annotation: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LB: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
        LC: FnOnce(LinearCombination<Scalar>) -> LinearCombination<Scalar>,
    {
        let a = self.evaluate(&a(LinearCombination::zero()));
        let b = self.evaluate(&b(LinearCombination::zero()));
        let c = self.evaluate(&c(LinearCombination::zero()));
        if self.first_unsatisfied.is_none() && a * b != c {
            self.first_unsatisfied = Some(self.constraints);
        }
        self.constraints = self.constraints.checked_add(1).expect("constraint count");
    }

    fn push_namespace<NR, N>(&mut self, _name: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
    }

    fn pop_namespace(&mut self) {}

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

fn fixed_bincode_shape_length(metrics: R1CSShapeMetrics) -> u64 {
    let padded_dimension = metrics
        .constraints
        .max(metrics.variables)
        .next_power_of_two() as u64;
    let nonzero_terms = (metrics.a_terms + metrics.b_terms + metrics.c_terms) as u64;
    40 * nonzero_terms + 24 * padded_dimension + 144
}

fn fixed_bincode_verifier_payload_length(metrics: PublicParamsShapeMetrics) -> u64 {
    let primary_dimension = metrics
        .primary
        .constraints
        .max(metrics.primary.variables)
        .next_power_of_two() as u64;
    let secondary_dimension = metrics
        .secondary
        .constraints
        .max(metrics.secondary.variables)
        .next_power_of_two() as u64;
    fixed_bincode_shape_length(metrics.primary)
        + fixed_bincode_shape_length(metrics.secondary)
        + 33 * (primary_dimension + secondary_dimension)
        + 352
}

fn small_leaf_shape() -> CircuitTranscriptShapeV4 {
    CircuitTranscriptShapeV4 {
        mode: CircuitCommitmentModeV4::Public,
        gate_count: 2,
        commitment_count: 1,
        n_vec_len: 4,
        l_vec_len: 4,
    }
}

fn production_leaf_shape() -> CircuitTranscriptShapeV4 {
    CircuitTranscriptShapeV4 {
        mode: CircuitCommitmentModeV4::Public,
        gate_count: CONSTRUCTION_LEAF_GATE_COUNT,
        commitment_count: 1,
        n_vec_len: CONSTRUCTION_LEAF_NORM_LENGTH,
        l_vec_len: CONSTRUCTION_LEAF_NORM_LENGTH,
    }
}

fn identity_pair() -> CircuitPointPairWitnessV4 {
    CircuitPointPairWitnessV4 {
        encoded: [0; 65],
        first_y: [0; 32],
        second_y: [0; 32],
    }
}

fn zero_transcript_witness(shape: CircuitTranscriptShapeV4) -> CircuitProofTranscriptWitnessV4 {
    CircuitProofTranscriptWitnessV4 {
        public_commitments: vec![SecpEncodedPointWitness::identity()],
        raw_commitment: SecpEncodedPointWitness::identity(),
        coefficient_commitment: SecpEncodedPointWitness::identity(),
        anchored_offset: SecpEncodedPointWitness::identity(),
        anchored_commitment: SecpEncodedPointWitness::identity(),
        batched_public_commitment: SecpEncodedPointWitness::identity(),
        dlog_nonce: SecpEncodedPointWitness::identity(),
        dlog_response: SecpScalarWitness::from_u64(0),
        mask_commitment: SecpEncodedPointWitness::identity(),
        t2: SecpScalarWitness::from_u64(0),
        combined_commitment: SecpEncodedPointWitness::identity(),
        rounds: vec![identity_pair(); shape.round_count()],
        terminal_n: SecpScalarWitness::from_u64(0),
        terminal_l: SecpScalarWitness::from_u64(0),
    }
}

fn zero_reduction_proof(shape: CircuitTranscriptShapeV4) -> CandidateNormReductionProofWitness {
    CandidateNormReductionProofWitness {
        coefficient_evaluation: SecpScalarWitness::from_u64(0),
        left: vec![SecpEncodedPointWitness::identity(); shape.round_count()],
        right: vec![SecpEncodedPointWitness::identity(); shape.round_count()],
        terminal_scalar: SecpScalarWitness::from_u64(0),
        folded_generator: SecpEncodedPointWitness::identity(),
    }
}

fn zero_candidate_step() -> CandidateStepProofWitness {
    CandidateStepProofWitness {
        left: vec![SecpEncodedPointWitness::identity(); CONSTRUCTION_ROOT_ROUNDS],
        right: vec![SecpEncodedPointWitness::identity(); CONSTRUCTION_ROOT_ROUNDS],
        terminal_scalar: SecpScalarWitness::from_u64(1),
        folded_generator: SecpEncodedPointWitness::identity(),
    }
}

fn prior_state(manifest_byte: u8) -> ConstructionRecurrenceStateWitness {
    ConstructionRecurrenceStateWitness {
        root: CandidateRootClaim {
            point: SecpEncodedPointWitness::from_point_value(standard_generator()),
            scale: SecpScalarWitness::from_u64(0),
            factors: vec![SecpScalarWitness::from_u64(0); CONSTRUCTION_ROOT_ROUNDS],
        },
        manifest: [manifest_byte; 32],
        index: u32::from(manifest_byte),
    }
}

fn candidate_root(root: &CandidateRootClaim) -> ConstructionRoot {
    assert_eq!(root.factors.len(), CONSTRUCTION_ROOT_ROUNDS);
    let mut encoded = [0; CONSTRUCTION_ROOT_BYTES];
    encoded[..33].copy_from_slice(&root.point.encoded);
    encoded[33..65].copy_from_slice(&root.scale.bytes);
    for (index, factor) in root.factors.iter().enumerate() {
        let offset = 65 + 32 * index;
        encoded[offset..offset + 32].copy_from_slice(&factor.bytes);
    }
    ConstructionRoot::parse(&encoded).expect("canonical construction root")
}

fn recurrence_state_from_fields(
    fields: [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
    expected_index: u32,
) -> ConstructionRecurrenceStateWitness {
    let root_fields = fields[..CONSTRUCTION_ROOT_STATE_ARITY]
        .try_into()
        .expect("fixed construction root state");
    let root = ConstructionRoot::from_state_fields(root_fields)
        .expect("authenticated construction root fields");
    let manifest_field = fields[CONSTRUCTION_ROOT_STATE_ARITY];
    let mut manifest = scalar_to_canonical(&manifest_field);
    manifest.reverse();
    assert_eq!(
        fields[CONSTRUCTION_ROOT_STATE_ARITY + 1],
        Scalar::from(u64::from(expected_index))
    );
    ConstructionRecurrenceStateWitness {
        root: root.claim(),
        manifest,
        index: expected_index,
    }
}

fn production_direct_step(binding_byte: u8, manifest_byte: u8) -> ConstructionParentStep {
    let shape = production_leaf_shape();
    ConstructionParentStep::new(
        prior_state(manifest_byte),
        ManifestBoundConstructionLeafStatementV4 {
            shape,
            circuit_binding_digest: [binding_byte; 32],
            raw_generator_digest: CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            basis_digest: CONSTRUCTION_PARENT_BASIS_DIGEST,
        },
        zero_transcript_witness(shape),
        zero_reduction_proof(shape),
        zero_candidate_step(),
    )
    .expect("production direct step")
}

fn synthesize_output(
    step: &ConstructionParentStep,
) -> [Scalar; CONSTRUCTION_RECURRENCE_STATE_ARITY] {
    let mut cs = CheckingWitnessCS::with_auxiliary_capacity(DIRECT_PARENT_AUXILIARY);
    let inputs = step
        .input_state()
        .iter()
        .enumerate()
        .map(|(index, value)| {
            AllocatedNum::alloc_input(cs.namespace(|| format!("state {index}")), || Ok(*value))
                .expect("state input")
        })
        .collect::<Vec<_>>();
    let outputs = step
        .synthesize(&mut cs, &inputs)
        .expect("construction recurrence");
    assert_eq!(outputs.len(), CONSTRUCTION_RECURRENCE_STATE_ARITY);
    let values =
        std::array::from_fn(|index| outputs[index].get_value().expect("recurrence output"));
    cs.assert_satisfied();
    assert_eq!(cs.auxiliary.len(), DIRECT_PARENT_AUXILIARY);
    assert_eq!(cs.constraints, DIRECT_PARENT_CONSTRAINTS);
    values
}

#[test]
fn production_shape_is_exact() {
    assert_eq!(CONSTRUCTION_RECURRENCE_STATE_ARITY, 20);
    assert_eq!(CONSTRUCTION_LEAF_ROUNDS, 14);
    let shape = production_leaf_shape();
    let statement = ManifestBoundConstructionLeafStatementV4 {
        shape,
        circuit_binding_digest: [0x31; 32],
        raw_generator_digest: CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        basis_digest: CONSTRUCTION_PARENT_BASIS_DIGEST,
    };
    validate_production_shape(
        statement,
        &zero_reduction_proof(shape),
        &zero_candidate_step(),
    )
    .expect("production shape");
}

#[test]
fn checking_witness_cs_rejects_a_false_equation() {
    let mut cs = CheckingWitnessCS::new();
    let value =
        AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(Scalar::from(2u64))).expect("value");
    cs.enforce(
        || "false equation",
        |linear| linear + value.get_variable(),
        |linear| linear + CheckingWitnessCS::one(),
        |linear| linear + CheckingWitnessCS::one(),
    );
    assert_eq!(cs.first_unsatisfied, Some(0));
}

#[test]
fn direct_construction_step_fixes_profile_and_input_state() {
    let shape = production_leaf_shape();
    let state = prior_state(1);
    let expected_input = state.state_fields().expect("input state");
    let statement = ManifestBoundConstructionLeafStatementV4 {
        shape,
        circuit_binding_digest: [0x31; 32],
        raw_generator_digest: CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        basis_digest: CONSTRUCTION_PARENT_BASIS_DIGEST,
    };
    let transcript = zero_transcript_witness(shape);
    let reduction = zero_reduction_proof(shape);
    let proof = zero_candidate_step();

    let mut wrong_statement = statement;
    wrong_statement.basis_digest[0] ^= 1;
    assert!(ConstructionParentStep::new(
        state.clone(),
        wrong_statement,
        transcript.clone(),
        reduction.clone(),
        proof.clone(),
    )
    .is_err());
    let mut wrong_statement = statement;
    wrong_statement.raw_generator_digest[0] ^= 1;
    assert!(ConstructionParentStep::new(
        state.clone(),
        wrong_statement,
        transcript.clone(),
        reduction.clone(),
        proof.clone(),
    )
    .is_err());

    let step = ConstructionParentStep::new(state, statement, transcript, reduction, proof)
        .expect("production direct step");
    assert_eq!(step.arity(), CONSTRUCTION_RECURRENCE_STATE_ARITY);
    assert_eq!(step.input_state(), &expected_input);
    assert_eq!(
        NovaSessionStep::relation_id(&step),
        PROVISIONAL_CONSTRUCTION_PARENT_RELATION_ID
    );

    let shape = small_leaf_shape();
    let test_step = TestConstructionParentStep::new(
        prior_state(1),
        ManifestBoundConstructionLeafStatementV4 {
            shape,
            circuit_binding_digest: [0x31; 32],
            raw_generator_digest: CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
            basis_digest: CONSTRUCTION_PARENT_BASIS_DIGEST,
        },
        zero_transcript_witness(shape),
        zero_reduction_proof(shape),
        zero_candidate_step(),
    )
    .expect("small direct step");
    assert_eq!(test_step.arity(), CONSTRUCTION_RECURRENCE_STATE_ARITY);
}

#[test]
#[ignore = "run explicitly in release mode; streams the pending relation"]
fn direct_construction_step_relation_shape_is_deterministic() {
    let first_step = production_direct_step(0x31, 1);
    let first = direct_step_relation_shape::<CONSTRUCTION_RECURRENCE_STATE_ARITY, _>(&first_step)
        .expect("first production relation");
    let second = direct_step_relation_shape::<CONSTRUCTION_RECURRENCE_STATE_ARITY, _>(
        &production_direct_step(0x32, 2),
    )
    .expect("second production relation");

    assert_eq!(first, second);
    assert_eq!(first.inputs(), 21);
    assert_eq!(first.auxiliary(), DIRECT_PARENT_AUXILIARY);
    assert_eq!(first.constraints(), DIRECT_PARENT_CONSTRAINTS);
    eprintln!(
        "pending relation_id={} inputs={} auxiliary={} constraints={}",
        hex(first.relation_id().bytes()),
        first.inputs(),
        first.auxiliary(),
        first.constraints(),
    );
}

#[test]
#[ignore = "run explicitly in release mode; checks provisional geometry"]
fn direct_construction_step_augmented_shape_matches_provisional_slot() {
    let step = production_direct_step(0x31, 1);
    let augmented =
        PublicParams::<DirectNovaPrimaryEngine, DirectNovaSecondaryEngine, _>::shape_metrics(&step)
            .expect("direct construction augmented shapes");
    let verifier_payload_length = fixed_bincode_verifier_payload_length(augmented);
    let proof_shape = NovaCompressedProofShape::from_suite_dimensions(
        NovaR1csDimensions::new(augmented.primary.constraints, augmented.primary.variables),
        NovaR1csDimensions::new(
            augmented.secondary.constraints,
            augmented.secondary.variables,
        ),
        CONSTRUCTION_RECURRENCE_STATE_ARITY,
    )
    .expect("direct construction proof shape");

    eprintln!(
        "qualification-pending augmented shape={augmented:#?}\n\
         verifier_payload_length={verifier_payload_length}\n\
         proof_length={} proof_sequences={}",
        proof_shape.encoded_len(),
        proof_shape.sequence_count(),
    );
    assert_eq!(augmented.primary.constraints, 9_418_599);
    assert_eq!(augmented.primary.variables, 9_372_280);
    assert_eq!(augmented.primary.public_inputs, 2);
    assert_eq!(augmented.primary.a_terms, 21_463_305);
    assert_eq!(augmented.primary.b_terms, 10_222_989);
    assert_eq!(augmented.primary.c_terms, 19_099_894);
    assert_eq!(augmented.secondary.constraints, 728_974);
    assert_eq!(augmented.secondary.variables, 728_211);
    assert_eq!(augmented.secondary.public_inputs, 2);
    assert_eq!(augmented.secondary.a_terms, 1_676_035);
    assert_eq!(augmented.secondary.b_terms, 736_338);
    assert_eq!(augmented.secondary.c_terms, 1_568_376);
    assert_eq!(verifier_payload_length, 3_206_748_264);
    assert_eq!(
        proof_shape.encoded_len(),
        PROVISIONAL_CONSTRUCTION_PARENT_PROOF_LENGTH
    );
    assert_eq!(proof_shape.sequence_count(), 152);
}

#[test]
fn production_relation_digests_match_the_native_leaf_profile() {
    assert_eq!(
        CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        [
            0x10, 0x1c, 0xdb, 0x8d, 0x99, 0x28, 0x00, 0xb0, 0x3c, 0x39, 0x24, 0x6e, 0xb9, 0x20,
            0xc8, 0x37, 0xa8, 0x04, 0x0c, 0x5a, 0x36, 0xa0, 0x97, 0x0f, 0x0e, 0xbf, 0x85, 0x51,
            0x11, 0x21, 0xca, 0x8a,
        ]
    );
    assert_eq!(
        CONSTRUCTION_PARENT_BASIS_DIGEST,
        [
            0x3e, 0x22, 0x80, 0x71, 0x8c, 0xf5, 0x97, 0x0d, 0xaf, 0x53, 0xb8, 0xec, 0x3f, 0xf1,
            0x1d, 0x59, 0x2a, 0x71, 0x48, 0x35, 0x14, 0xba, 0x91, 0xa6, 0xf1, 0xb3, 0x72, 0x08,
            0xad, 0x9e, 0xb5, 0x94,
        ]
    );
    assert_ne!(
        CONSTRUCTION_PARENT_RAW_GENERATOR_DIGEST,
        CONSTRUCTION_PARENT_BASIS_DIGEST
    );
}

fn read_qualification_fixture(environment: &str) -> ConstructionParentProverFixture {
    let path = std::env::var_os(environment)
        .unwrap_or_else(|| panic!("set {environment} before qualification"));
    let bytes = std::fs::read(path).expect("read construction parent prover fixture");
    eprintln!(
        "unqualified_wit3_fixture={environment} bytes={} sha256={}",
        bytes.len(),
        hex(&Sha256::digest(&bytes)),
    );
    ConstructionParentProverFixture::parse(&bytes)
        .expect("parse construction parent prover fixture")
}

fn assert_matching_public_fixtures(
    accepted: &ConstructionParentProverFixture,
    nondeciding: &ConstructionParentProverFixture,
) {
    assert_ne!(accepted.setup_leaf_count, 0);
    assert_ne!(accepted.anchor_leaf_count, 0);
    assert_eq!(accepted.setup_leaf_count, nondeciding.setup_leaf_count);
    assert_eq!(accepted.anchor_leaf_count, nondeciding.anchor_leaf_count);
    assert_eq!(nondeciding.leaves.len(), accepted.leaves.len());
    assert_eq!(accepted.inputs.leaves(), nondeciding.inputs.leaves());
    assert_eq!(
        accepted
            .inputs
            .seed()
            .initial_state_fields()
            .expect("accepted initial state"),
        nondeciding
            .inputs
            .seed()
            .initial_state_fields()
            .expect("nondeciding initial state")
    );
    for (accepted_leaf, nondeciding_leaf) in accepted.leaves.iter().zip(&nondeciding.leaves) {
        assert_eq!(accepted_leaf.statement, nondeciding_leaf.statement);
        assert_eq!(
            accepted_leaf.transcript.public_commitments,
            nondeciding_leaf.transcript.public_commitments
        );
    }
    assert_ne!(
        accepted.expected_root.canonical_bytes(),
        nondeciding.expected_root.canonical_bytes()
    );
}

fn bind_qualification_fixture(
    fixture: &ConstructionParentProverFixture,
) -> BoundQualificationFixture {
    let initial_state = fixture
        .inputs
        .seed()
        .initial_state_fields()
        .expect("verifier-derived qualification z0");
    let expected_suffix = fixture
        .inputs
        .seed()
        .derive_expected_final(fixture.inputs.leaves())
        .expect("independent final construction manifest")
        .state_suffix_fields()
        .expect("final construction manifest fields");
    let mut state = fixture
        .inputs
        .seed()
        .initial_recurrence_witness()
        .expect("initial qualification recurrence witness");
    assert_eq!(
        state.state_fields().expect("initial recurrence state"),
        initial_state
    );

    let mut expected_input = initial_state;
    let mut steps = Vec::with_capacity(fixture.leaves.len());
    for (index, leaf) in fixture.leaves.iter().enumerate() {
        let step = ConstructionParentStep::new(
            state,
            leaf.statement,
            leaf.transcript.clone(),
            leaf.reduction.clone(),
            leaf.step.clone(),
        )
        .expect("qualification recurrence");
        assert_eq!(*step.input_state(), expected_input);
        assert_eq!(
            NovaSessionStep::relation_id(&step),
            PROVISIONAL_CONSTRUCTION_PARENT_RELATION_ID
        );
        let output = synthesize_output(&step);
        state = recurrence_state_from_fields(
            output,
            u32::try_from(index + 1).expect("qualification leaf index fits u32"),
        );
        expected_input = output;
        steps.push(step);
    }

    assert_eq!(
        &expected_input[CONSTRUCTION_ROOT_STATE_ARITY..],
        expected_suffix.as_slice()
    );
    assert_eq!(
        candidate_root(&state.root).canonical_bytes(),
        fixture.expected_root.canonical_bytes()
    );
    BoundQualificationFixture {
        initial_state,
        final_state: expected_input,
        steps,
    }
}

fn bind_both_qualification_fixtures(
    accepted: &ConstructionParentProverFixture,
    nondeciding: &ConstructionParentProverFixture,
) -> (
    ConstructionParentStep,
    BoundQualificationFixture,
    BoundQualificationFixture,
) {
    assert_matching_public_fixtures(accepted, nondeciding);
    let accepted_bound = bind_qualification_fixture(accepted);
    let nondeciding_bound = bind_qualification_fixture(nondeciding);
    assert_eq!(
        accepted_bound.initial_state,
        nondeciding_bound.initial_state
    );
    assert_ne!(accepted_bound.final_state, nondeciding_bound.final_state);
    let trusted_step = accepted_bound.steps[0].clone();
    assert!(accepted_bound
        .steps
        .iter()
        .chain(&nondeciding_bound.steps)
        .all(|step| {
            NovaSessionStep::relation_id(step) == PROVISIONAL_CONSTRUCTION_PARENT_RELATION_ID
        }));
    (trusted_step, accepted_bound, nondeciding_bound)
}

fn produce_qualification_proof(
    suite: &ConstructionParentNovaSuite,
    initial_state: [DirectNovaScalar; CONSTRUCTION_RECURRENCE_STATE_ARITY],
    steps: Vec<ConstructionParentStep>,
) -> Vec<u8> {
    let step_count = steps.len();
    let mut session = suite
        .start(initial_state, step_count)
        .expect("start qualification proof session");
    for (index, step) in steps.into_iter().enumerate() {
        eprintln!(
            "sha_parent_qualification: folding recurrence {}/{}",
            index + 1,
            step_count
        );
        session = session
            .add_step(step)
            .expect("fold qualification recurrence");
    }
    session
        .finish()
        .expect("verify and compress qualification proof")
}

fn qualification_output_path(environment: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(
        std::env::var_os(environment)
            .unwrap_or_else(|| panic!("set {environment} before qualification")),
    );
    assert!(!path.as_os_str().is_empty(), "{environment} is empty");
    assert!(!path.exists(), "{environment} already exists");
    path
}

fn write_new_qualification_output(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;

    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create new qualification output");
    output
        .write_all(bytes)
        .expect("write complete qualification output");
    output.sync_all().expect("sync qualification output");
    eprintln!(
        "sha_parent_qualification: output={} bytes={}",
        path.display(),
        bytes.len()
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
#[ignore = "requires both fixtures and synthesizes production recurrences"]
fn exported_sha_parent_fixtures_reconstruct_one_shape() {
    let accepted = read_qualification_fixture("PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE");
    let nondeciding =
        read_qualification_fixture("PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROVER_FIXTURE");
    let (trusted_step, accepted_bound, nondeciding_bound) =
        bind_both_qualification_fixtures(&accepted, &nondeciding);
    assert_eq!(accepted_bound.steps.len(), accepted.leaves.len());
    assert_eq!(nondeciding_bound.steps.len(), nondeciding.leaves.len());
    assert_eq!(
        NovaSessionStep::relation_id(&trusted_step),
        PROVISIONAL_CONSTRUCTION_PARENT_RELATION_ID
    );
}

#[test]
#[ignore = "run explicitly under the native resource gate"]
fn native_profile_sha_parent_qualification_is_exact() {
    let total_started = std::time::Instant::now();
    let accepted_proof_path = qualification_output_path("PURIFY_CONSTRUCTION_PARENT_PROOF_OUT");
    let nondeciding_proof_path =
        qualification_output_path("PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROOF_OUT");
    let artifact_path =
        qualification_output_path("PURIFY_CONSTRUCTION_PARENT_VERIFIER_ARTIFACT_OUT");
    let accepted = read_qualification_fixture("PURIFY_CONSTRUCTION_PARENT_PROVER_FIXTURE");
    let nondeciding =
        read_qualification_fixture("PURIFY_CONSTRUCTION_PARENT_NONDECIDING_PROVER_FIXTURE");
    let (mut trusted_step, mut accepted_bound, mut nondeciding_bound) =
        bind_both_qualification_fixtures(&accepted, &nondeciding);
    drop(accepted);
    drop(nondeciding);

    let relation_shape =
        direct_step_relation_shape::<CONSTRUCTION_RECURRENCE_STATE_ARITY, _>(&trusted_step)
            .expect("stream exact qualification relation");
    let relation_id = relation_shape.relation_id();
    trusted_step.set_qualification_relation_id(relation_id);
    for step in accepted_bound
        .steps
        .iter_mut()
        .chain(&mut nondeciding_bound.steps)
    {
        step.set_qualification_relation_id(relation_id);
    }
    assert!(accepted_bound
        .steps
        .iter()
        .chain(&nondeciding_bound.steps)
        .all(|step| NovaSessionStep::relation_id(step) == relation_id));
    eprintln!(
        "sha_parent_qualification: relation_id={} relation_inputs={} \
         relation_auxiliary={} relation_constraints={}",
        hex(relation_id.bytes()),
        relation_shape.inputs(),
        relation_shape.auxiliary(),
        relation_shape.constraints(),
    );

    let setup_started = std::time::Instant::now();
    eprintln!("sha_parent_qualification: constructing transparent parameters");
    let unselected =
        NovaSessionSuite::<CONSTRUCTION_RECURRENCE_STATE_ARITY, ConstructionParentStep>::setup(
            trusted_step,
        )
        .expect("unselected mixed qualification suite");
    let selected = unselected
        .select_generated_for_qualification(MIXED_CONSTRUCTION_QUALIFICATION_VERSIONS)
        .expect("select generated mixed qualification suite");
    let metadata = selected.metadata();
    let versions = MIXED_CONSTRUCTION_QUALIFICATION_VERSIONS.values();
    eprintln!(
        "sha_parent_qualification: setup_seconds={:.3}\n\
         payload_version={} statement_version={} manifest_version={} \
         native_decision_version={}\nrelation_id={}\n\
         public_parameter_digest={}\nsuite_id={}\nmetadata={metadata:#?}\n\
         expected_suite={:#?}",
        setup_started.elapsed().as_secs_f64(),
        versions.0,
        versions.1,
        versions.2,
        versions.3,
        hex(metadata.relation_id.bytes()),
        hex(&metadata.public_parameter_digest),
        hex(selected.expected().suite_id().bytes()),
        selected.expected(),
    );

    let z0 = accepted_bound.initial_state;
    let accepted_final = accepted_bound.final_state;
    let nondeciding_final = nondeciding_bound.final_state;
    let step_count = accepted_bound.steps.len();
    assert_eq!(nondeciding_bound.steps.len(), step_count);

    let accepted_proof = produce_qualification_proof(&selected, z0, accepted_bound.steps);
    let nondeciding_proof = produce_qualification_proof(&selected, z0, nondeciding_bound.steps);
    assert_eq!(accepted_proof.len(), metadata.proof_length);
    assert_eq!(nondeciding_proof.len(), metadata.proof_length);
    eprintln!(
        "accepted_proof_sha256={}\nnondeciding_proof_sha256={}",
        hex(&Sha256::digest(&accepted_proof)),
        hex(&Sha256::digest(&nondeciding_proof)),
    );

    let verifier = selected.into_verifier();
    let expected_suite = verifier.expected();
    verifier
        .verify_exact(&z0, step_count, &accepted_final, &accepted_proof)
        .expect("verify accepted qualification proof");
    verifier
        .verify_exact(&z0, step_count, &nondeciding_final, &nondeciding_proof)
        .expect("verify nondeciding qualification proof");
    let mut artifact = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&artifact_path)
        .expect("create new qualification verifier artifact");
    let descriptor = verifier
        .write_artifact(&mut artifact)
        .expect("write qualification verifier artifact");
    artifact
        .sync_all()
        .expect("sync qualification verifier artifact");
    eprintln!(
        "verifier_artifact={}\nartifact_bytes={}\nartifact_decoded_bytes={}\n\
         artifact_tagged_digest={}",
        artifact_path.display(),
        descriptor.encoded_length(),
        descriptor.decoded_payload_length(),
        hex(&descriptor.digest()),
    );
    drop(artifact);
    drop(verifier);

    let mut artifact = std::fs::File::open(&artifact_path)
        .expect("open qualification verifier artifact for reload");
    let loaded = crate::nova_session::SelectedNovaVerifier::<
        CONSTRUCTION_RECURRENCE_STATE_ARITY,
        ConstructionParentStep,
    >::from_artifact_reader(&mut artifact, expected_suite, &descriptor)
    .expect("reload qualification verifier artifact");
    loaded
        .verify_exact(&z0, step_count, &accepted_final, &accepted_proof)
        .expect("reloaded verifier accepts qualification proof");
    loaded
        .verify_exact(&z0, step_count, &nondeciding_final, &nondeciding_proof)
        .expect("reloaded verifier accepts nondeciding proof");
    write_new_qualification_output(&accepted_proof_path, &accepted_proof);
    write_new_qualification_output(&nondeciding_proof_path, &nondeciding_proof);
    eprintln!(
        "sha_parent_qualification: total_seconds={:.3}",
        total_started.elapsed().as_secs_f64()
    );
}
