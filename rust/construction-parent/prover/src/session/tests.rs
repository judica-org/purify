use ff::Field;
use nova_snark::frontend::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};

use super::setup::SessionSuite;
use super::*;
use crate::artifact_writer::{identity_of_bytes, ArtifactWriteError};
use circuit::relation::identity::step_relation_shape;
use statement::Scalar;
use verifier::artifact::ArtifactIdentity;
use verifier::codec::R1csDimensions;
use verifier::nova::{
    CompressedProof, Key, LoadError, Verifier, VerifyError, VERIFIER_ARTIFACT_FORMAT,
};
use verifier::suite::{ConstructionVersions, R1csSize, SuiteParameters};

const TEST_ARITY: usize = 20;

const TEST_VERSIONS: ConstructionVersions = ConstructionVersions {
    payload: 0x0102_0304,
    statement: 0x1112_1314,
    manifest: 0x2122_2324,
    native_decision: 0x3132_3334,
};
/// The self-consistent synthetic profile the verifier crate's suite tests
/// pin: its ID is the tagged hash of exactly these values.
const TEST_SUITE: Suite = Suite {
    parameters: SuiteParameters {
        versions: TEST_VERSIONS,
        state_arity: 20,
        relation_id: [0x11; 32],
        public_parameter_digest: [0x22; 32],
        primary: R1csSize {
            constraints: 101,
            variables: 103,
        },
        secondary: R1csSize {
            constraints: 107,
            variables: 109,
        },
    },
    proof_length: 6_376,
    proof_sequences: 62,
    suite_id: [
        0x75, 0xaf, 0xf8, 0x3f, 0x39, 0x05, 0x05, 0x67, 0x86, 0x99, 0x2a, 0xb4, 0x24, 0x9f, 0x29,
        0x4b, 0x6b, 0x62, 0xab, 0x02, 0x64, 0x69, 0xfa, 0xad, 0x60, 0xfa, 0xb4, 0xfb, 0x3c, 0x47,
        0xed, 0x03,
    ],
};

fn source_state(seed: u64) -> [Scalar; TEST_ARITY] {
    std::array::from_fn(|index| Scalar::from(seed + index as u64))
}

fn increment(state: [Scalar; TEST_ARITY]) -> [Scalar; TEST_ARITY] {
    state.map(|value| value + Scalar::ONE)
}

#[derive(Clone)]
struct TestSessionStep {
    input_state: [Scalar; TEST_ARITY],
    increment: bool,
}

impl TestSessionStep {
    fn new(input_state: [Scalar; TEST_ARITY], increment: bool) -> Self {
        Self {
            input_state,
            increment,
        }
    }
}

impl StepCircuit<Scalar> for TestSessionStep {
    fn arity(&self) -> usize {
        TEST_ARITY
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        if z.len() != TEST_ARITY {
            return Err(SynthesisError::Unsatisfiable(
                "test session state arity".to_owned(),
            ));
        }
        if !self.increment {
            return Ok(z.to_vec());
        }
        z.iter()
            .enumerate()
            .map(|(index, input)| {
                let next =
                    AllocatedNum::alloc(cs.namespace(|| format!("next state {index}")), || {
                        input
                            .get_value()
                            .map(|value| value + Scalar::ONE)
                            .ok_or(SynthesisError::AssignmentMissing)
                    })?;
                cs.enforce(
                    || format!("increment state {index}"),
                    |linear| linear + input.get_variable() + CS::one(),
                    |linear| linear + CS::one(),
                    |linear| linear + next.get_variable(),
                );
                Ok(next)
            })
            .collect()
    }
}

impl SessionStep<TEST_ARITY> for TestSessionStep {
    fn relation_id(&self) -> RelationId {
        step_relation_shape::<TEST_ARITY, _>(self)
            .expect("test session relation")
            .relation_id()
    }

    fn input_state(&self) -> &[Scalar; TEST_ARITY] {
        &self.input_state
    }
}

fn load_slice(
    artifact: &[u8],
    suite: &Suite,
    identity: &ArtifactIdentity,
) -> Result<Verifier, LoadError> {
    Verifier::load(&mut std::io::Cursor::new(artifact), suite, identity)
}

fn fixed_suite_fixture() -> (SuiteMetadata, ProofShape) {
    let proof_shape = ProofShape::from_suite_dimensions(
        R1csDimensions::new(101, 103),
        R1csDimensions::new(107, 109),
        TEST_ARITY,
    )
    .expect("synthetic suite proof shape");
    let metadata = SuiteMetadata {
        relation_id: RelationId::from_frozen_bytes([0x11; 32]),
        public_parameter_digest: [0x22; 32],
        primary_constraints: 101,
        secondary_constraints: 107,
        primary_variables: 103,
        secondary_variables: 109,
        proof_length: proof_shape.encoded_len(),
        codec_sequence_count: proof_shape.sequence_count(),
    };
    (metadata, proof_shape)
}

#[test]
fn bound_step_with_another_shape_fails_relation_check() {
    let trusted = TestSessionStep::new(source_state(3), true);
    let different = TestSessionStep::new(source_state(3), false);

    assert!(validate_step_relation(trusted.relation_id(), &trusted).is_ok());
    assert_eq!(
        validate_step_relation(trusted.relation_id(), &different),
        Err(SessionError::StepRelation)
    );
}

fn mismatch(label: &'static str) -> SessionError {
    SuiteError::Mismatch(label).into()
}

#[test]
fn exact_suite_profile_rejects_every_metadata_drift() {
    let (metadata, proof_shape) = fixed_suite_fixture();
    let expected = TEST_SUITE;
    assert_eq!(
        metadata
            .validate::<TEST_ARITY>(&expected)
            .expect("exact local suite profile"),
        proof_shape
    );

    assert_eq!(
        metadata.validate::<21>(&expected),
        Err(mismatch("state arity"))
    );

    let mut changed = expected;
    changed.parameters.relation_id[0] ^= 1;
    assert_eq!(
        metadata.validate::<TEST_ARITY>(&changed),
        Err(mismatch("relation ID"))
    );

    let mut changed = expected;
    changed.parameters.public_parameter_digest[0] ^= 1;
    assert_eq!(
        metadata.validate::<TEST_ARITY>(&changed),
        Err(mismatch("public-parameter digest"))
    );

    for label in [
        "primary constraints",
        "secondary constraints",
        "primary variables",
        "secondary variables",
        "proof length",
    ] {
        let mut changed = expected;
        match label {
            "primary constraints" => changed.parameters.primary.constraints += 1,
            "secondary constraints" => changed.parameters.secondary.constraints += 1,
            "primary variables" => changed.parameters.primary.variables += 1,
            "secondary variables" => changed.parameters.secondary.variables += 1,
            "proof length" => changed.proof_length += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            metadata.validate::<TEST_ARITY>(&changed),
            Err(mismatch(label))
        );
    }

    let mut changed = expected;
    changed.proof_sequences += 1;
    assert_eq!(
        metadata.validate::<TEST_ARITY>(&changed),
        Err(mismatch("codec sequence count"))
    );

    let mut changed = expected;
    changed.parameters.versions.payload = 0x0102_0305;
    assert_eq!(
        metadata.validate::<TEST_ARITY>(&changed),
        Err(mismatch("suite ID"))
    );

    let mut changed = expected;
    changed.suite_id = [0x55; 32];
    assert_eq!(
        metadata.validate::<TEST_ARITY>(&changed),
        Err(mismatch("suite ID"))
    );
}

#[test]
fn exact_suite_prechecks_relation_before_parameter_setup() {
    let trusted_step = TestSessionStep::new(source_state(3), true);
    static WRONG_RELATION_SUITE: Suite = {
        let mut suite = TEST_SUITE;
        suite.parameters.relation_id = [0; 32];
        suite
    };
    assert!(matches!(
        SessionSuite::<TEST_ARITY, TestSessionStep>::setup_exact(
            trusted_step,
            &WRONG_RELATION_SUITE,
        ),
        Err(SessionError::Suite(SuiteError::Mismatch("relation ID")))
    ));
}

#[test]
#[ignore = "explicit slow real two-step Nova session"]
fn tiny_twenty_state_session_round_trips_canonically() {
    let source_z0 = source_state(3);
    let source_z1 = increment(source_z0);
    let source_z2 = increment(source_z1);
    let z0 = source_z0;
    let z1 = source_z1;
    let z2 = source_z2;

    let trusted_step = TestSessionStep::new(source_z0, true);
    let first_step = TestSessionStep::new(source_z0, true);
    let second_step = TestSessionStep::new(source_z1, true);
    let suite = SessionSuite::<TEST_ARITY, TestSessionStep>::setup(trusted_step)
        .expect("unselected tiny direct Nova suite");
    let metadata = suite.metadata();
    let proof_shape = suite.verifier.proof_shape.clone();
    let expected: &'static Suite = Box::leak(Box::new(
        metadata
            .generated_suite::<TEST_ARITY>(TEST_VERSIONS)
            .expect("derived tiny suite profile"),
    ));
    assert_eq!(
        metadata
            .validate::<TEST_ARITY>(expected)
            .expect("derived tiny suite profile validates"),
        proof_shape
    );
    let selected = suite.select(expected).expect("select tiny Nova suite");
    assert_eq!(selected.expected(), expected);

    let incomplete = selected.start(z0, 2).expect("incomplete session");
    assert!(matches!(
        incomplete.finish(),
        Err(SessionError::StepCount {
            expected: 2,
            actual: 0
        })
    ));

    let discontinuous = selected
        .start(z0, 2)
        .expect("discontinuous session")
        .add_step(second_step.clone());
    assert!(matches!(discontinuous, Err(SessionError::StateContinuity)));

    let session = selected
        .start(z0, 2)
        .expect("two-step session")
        .add_step(first_step)
        .expect("first fold")
        .add_step(second_step)
        .expect("second fold");
    let proof = session.finish().expect("compress two-step proof");
    assert_eq!(proof.len(), metadata.proof_length);
    let verifier = selected.into_verifier();
    assert_eq!(verifier.expected(), expected);
    assert_eq!(verifier.metadata(), metadata);

    let verifier_key_bytes = bincode::serde::encode_to_vec(
        &verifier.inner.verifier_key,
        bincode::config::legacy()
            .with_little_endian()
            .with_fixed_int_encoding(),
    )
    .expect("encode real-circuit verifier key");
    let (verifier_only_key, consumed) = bincode::serde::decode_from_slice::<Key, _>(
        &verifier_key_bytes,
        bincode::config::legacy()
            .with_little_endian()
            .with_fixed_int_encoding(),
    )
    .expect("decode verifier-only key");
    assert_eq!(consumed, verifier_key_bytes.len());
    assert_eq!(
        bincode::serde::encode_to_vec(
            &verifier_only_key,
            bincode::config::legacy()
                .with_little_endian()
                .with_fixed_int_encoding(),
        )
        .expect("re-encode verifier-only key"),
        verifier_key_bytes
    );
    let fixed_shape = proof_shape.as_fixed_serde_shape();
    let verifier_only_proof = fixed_shape
        .decode_canonical::<CompressedProof>(&proof)
        .expect("decode verifier-only proof");
    assert_eq!(
        fixed_shape
            .encode(&verifier_only_proof)
            .expect("re-encode verifier-only proof"),
        proof
    );
    assert_eq!(
        verifier_only_proof
            .verify(&verifier_only_key, 2, &z0)
            .expect("verify with uninhabited circuit marker"),
        z2
    );

    let mut first_artifact = std::io::Cursor::new(Vec::new());
    let first_descriptor = verifier
        .write_artifact(&mut first_artifact)
        .expect("write selected verifier artifact");
    assert!(first_descriptor.encoded_length() > 72);
    assert!(first_descriptor.decoded_payload_length() > 0);
    assert_ne!(first_descriptor.digest(), [0; 32]);
    eprintln!("tiny_sha256_artifact={first_descriptor:#?}");
    let first_artifact = first_artifact.into_inner();
    let mut second_artifact = std::io::Cursor::new(Vec::new());
    let second_descriptor = verifier
        .write_artifact(&mut second_artifact)
        .expect("rewrite selected verifier artifact");
    assert_eq!(second_artifact.into_inner(), first_artifact);
    assert_eq!(second_descriptor, first_descriptor);

    let mut nonempty = std::io::Cursor::new(vec![0]);
    assert!(matches!(
        verifier.write_artifact(&mut nonempty),
        Err(ArtifactWriteError::DestinationNotEmpty)
    ));

    let mut artifact_reader = std::io::Cursor::new(first_artifact.as_slice());
    artifact_reader.set_position(7);
    let loaded = Verifier::load(&mut artifact_reader, expected, &first_descriptor)
        .expect("load selected verifier artifact");
    assert!(matches!(
        load_slice(&first_artifact, &TEST_SUITE, &first_descriptor),
        Err(LoadError::Header("suite ID"))
    ));
    assert_eq!(
        loaded
            .verify_final(&z0, 2, &proof)
            .expect("authenticate final state"),
        z2
    );
    verifier
        .verify_exact(&z0, 2, &z2, &proof)
        .expect("verify canonical proof");

    let wrong_length = ArtifactIdentity::new(
        first_descriptor.encoded_length() + 1,
        first_descriptor.decoded_payload_length(),
        first_descriptor.digest(),
    );
    assert!(matches!(
        load_slice(&first_artifact, expected, &wrong_length,),
        Err(LoadError::Length)
    ));
    let wrong_digest = ArtifactIdentity::new(
        first_descriptor.encoded_length(),
        first_descriptor.decoded_payload_length(),
        [0; 32],
    );
    assert!(matches!(
        load_slice(&first_artifact, expected, &wrong_digest,),
        Err(LoadError::Digest)
    ));

    let mut corrupted_payload = first_artifact.clone();
    corrupted_payload[72] ^= 1;
    assert!(matches!(
        load_slice(&corrupted_payload, expected, &first_descriptor,),
        Err(LoadError::Digest)
    ));

    let mut malformed_header = first_artifact.clone();
    malformed_header[0] ^= 1;
    let mut malformed_reader = std::io::Cursor::new(malformed_header);
    malformed_reader.set_position(11);
    assert!(matches!(
        Verifier::load(&mut malformed_reader, expected, &first_descriptor,),
        Err(LoadError::Digest)
    ));
    assert_eq!(
        malformed_reader.position(),
        first_descriptor.encoded_length()
    );

    let mut extra_bytes = first_artifact.clone();
    extra_bytes.push(0);
    let mut extra_reader = std::io::Cursor::new(extra_bytes);
    extra_reader.set_position(13);
    assert!(matches!(
        Verifier::load(&mut extra_reader, expected, &first_descriptor,),
        Err(LoadError::Length)
    ));

    for (offset, label) in [
        (0, "magic"),
        (19, "encoding version"),
        (20, "suite ID"),
        (55, "state arity"),
        (63, "compressed payload length"),
        (71, "decoded payload length"),
    ] {
        let mut malformed = first_artifact.clone();
        malformed[offset] ^= 1;
        let descriptor = identity_of_bytes(
            &VERIFIER_ARTIFACT_FORMAT,
            &malformed,
            first_descriptor.decoded_payload_length(),
        );
        assert!(matches!(
            load_slice(
            &malformed,
                expected,
                &descriptor,
            ),
            Err(LoadError::Header(actual)) if actual == label
        ));
    }

    let mut truncated = first_artifact.clone();
    truncated.pop();
    let truncated_descriptor = identity_of_bytes(
        &VERIFIER_ARTIFACT_FORMAT,
        &truncated,
        first_descriptor.decoded_payload_length(),
    );
    assert!(matches!(
        load_slice(&truncated, expected, &truncated_descriptor,),
        Err(LoadError::Header("compressed payload length"))
    ));

    let payload_length =
        u64::try_from(truncated.len() - 72).expect("test artifact payload length fits u64");
    truncated[56..64].copy_from_slice(&payload_length.to_be_bytes());
    let truncated_descriptor = identity_of_bytes(
        &VERIFIER_ARTIFACT_FORMAT,
        &truncated,
        first_descriptor.decoded_payload_length(),
    );
    assert!(matches!(
        load_slice(&truncated, expected, &truncated_descriptor,),
        Err(LoadError::Decode(_)) | Err(LoadError::Io(_))
    ));

    let mut trailing = first_artifact.clone();
    trailing.push(0);
    let payload_length =
        u64::try_from(trailing.len() - 72).expect("test artifact payload length fits u64");
    trailing[56..64].copy_from_slice(&payload_length.to_be_bytes());
    let trailing_descriptor = identity_of_bytes(
        &VERIFIER_ARTIFACT_FORMAT,
        &trailing,
        first_descriptor.decoded_payload_length(),
    );
    assert!(matches!(
        load_slice(&trailing, expected, &trailing_descriptor,),
        Err(LoadError::Length)
    ));

    let mut short = proof.clone();
    short.pop();
    assert!(matches!(
        loaded.verify_final(&z0, 2, &short),
        Err(VerifyError::ProofLength { .. })
    ));
    let malformed = vec![0xff; proof.len()];
    assert!(loaded.verify_final(&z0, 2, &malformed).is_err());
    assert!(matches!(
        loaded.verify_final(&z0, 0, &proof),
        Err(VerifyError::StepCount {
            expected: 1,
            actual: 0
        })
    ));

    let mut wrong_final = z2;
    wrong_final[0] += Scalar::ONE;
    assert!(matches!(
        verifier.verify_exact(&z0, 2, &wrong_final, &proof),
        Err(VerifyError::FinalState)
    ));
    assert!(verifier.verify_exact(&z0, 1, &z1, &proof).is_err());
    assert!(!matches!(
        loaded.verify_final(&z0, 1, &proof),
        Ok(state) if state == z1
    ));
}
