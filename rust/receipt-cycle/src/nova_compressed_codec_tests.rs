//! Explicit real-proof coverage for the internal Nova codec.

use std::cmp::max;

use ff::PrimeField;
use nova_snark::{
    frontend::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError},
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{ipa_pc, Secp256k1Sha256Engine, Secq256k1Sha256Engine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
};
use rayon::ThreadPoolBuilder;

use crate::fixed_serde::{FixedSerdeError, NovaCompressedProofShape, NovaR1csDimensions};

type PrimaryEngine = Secp256k1Sha256Engine;
type SecondaryEngine = Secq256k1Sha256Engine;
type Scalar = <PrimaryEngine as Engine>::Scalar;
type PrimaryEvaluationEngine = ipa_pc::EvaluationEngine<PrimaryEngine>;
type SecondaryEvaluationEngine = ipa_pc::EvaluationEngine<SecondaryEngine>;
type PrimarySnark = RelaxedR1CSSNARK<PrimaryEngine, PrimaryEvaluationEngine>;
type SecondarySnark = RelaxedR1CSSNARK<SecondaryEngine, SecondaryEvaluationEngine>;
type CompressedProof = CompressedSNARK<
    PrimaryEngine,
    SecondaryEngine,
    FixedMultiplyCircuit,
    PrimarySnark,
    SecondarySnark,
>;

#[derive(Clone, Debug)]
struct FixedMultiplyCircuit {
    multiplier: Scalar,
}

impl StepCircuit<Scalar> for FixedMultiplyCircuit {
    fn arity(&self) -> usize {
        1
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        if z.len() != self.arity() {
            return Err(SynthesisError::Unsatisfiable(
                "fixed multiply state arity".to_owned(),
            ));
        }

        let input_value = z[0].get_value();
        let left = AllocatedNum::alloc(cs.namespace(|| "left"), || {
            input_value.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let right = AllocatedNum::alloc(cs.namespace(|| "right"), || Ok(self.multiplier))?;
        let output = AllocatedNum::alloc(cs.namespace(|| "output"), || {
            Ok(input_value.ok_or(SynthesisError::AssignmentMissing)? * self.multiplier)
        })?;

        cs.enforce(
            || "left * right = output",
            |linear| linear + left.get_variable(),
            |linear| linear + right.get_variable(),
            |linear| linear + output.get_variable(),
        );
        cs.enforce(
            || "left = state",
            |linear| linear + left.get_variable(),
            |linear| linear + CS::one(),
            |linear| linear + z[0].get_variable(),
        );

        Ok(vec![output])
    }
}

fn run_real_proof_codec_fixture() {
    let steps = [
        FixedMultiplyCircuit {
            multiplier: Scalar::from(3u64),
        },
        FixedMultiplyCircuit {
            multiplier: Scalar::from(5u64),
        },
    ];
    let initial_state = vec![Scalar::from(2u64)];

    let pp = PublicParams::<PrimaryEngine, SecondaryEngine, FixedMultiplyCircuit>::setup(
        &steps[0],
        &*PrimarySnark::ck_floor(),
        &*SecondarySnark::ck_floor(),
    )
    .expect("transparent public parameters");
    assert_ne!(pp.digest().to_repr().as_ref(), &[0; 32]);
    let (primary_constraints, secondary_constraints) = pp.num_constraints();
    let (primary_variables, secondary_variables) = pp.num_variables();
    assert!(primary_constraints > 0 && secondary_constraints > 0);
    assert!(primary_variables > 0 && secondary_variables > 0);

    let primary_rounds = max(primary_constraints, primary_variables)
        .next_power_of_two()
        .ilog2() as usize;
    let secondary_rounds = max(secondary_constraints, secondary_variables)
        .next_power_of_two()
        .ilog2() as usize;
    let expected_sequence_count = 20 + 3 * (primary_rounds + secondary_rounds);
    let expected_encoded_len = 1_676 + 32 + 290 * (primary_rounds + secondary_rounds);

    let proof_shape = NovaCompressedProofShape::from_suite_dimensions(
        NovaR1csDimensions::new(primary_constraints, primary_variables),
        NovaR1csDimensions::new(secondary_constraints, secondary_variables),
        1,
    )
    .expect("compressed proof shape");
    assert_eq!(proof_shape.sequence_count(), expected_sequence_count);
    assert_eq!(proof_shape.encoded_len(), expected_encoded_len);

    let mut recursive = RecursiveSNARK::new(&pp, &steps[0], &initial_state)
        .expect("recursive proof initialization");
    for step in &steps {
        recursive
            .prove_step(&pp, step)
            .expect("fold fixed multiply step");
    }
    assert_eq!(
        recursive
            .verify(&pp, steps.len(), &initial_state)
            .expect("recursive proof verification"),
        vec![Scalar::from(30u64)]
    );

    let (prover_key, verifier_key) = CompressedProof::setup(&pp).expect("Spartan setup");
    let compressed =
        CompressedProof::prove(&pp, &prover_key, &recursive).expect("Spartan compression");
    let fixed_shape = proof_shape.as_fixed_serde_shape();
    let encoded = fixed_shape.encode(&compressed).expect("canonical encoding");
    assert_eq!(encoded.len(), expected_encoded_len);

    let mut malformed_first_point = encoded.clone();
    malformed_first_point[0] = 0xff;
    assert!(matches!(
        fixed_shape.decode_canonical::<CompressedProof>(&malformed_first_point),
        Err(FixedSerdeError::Value(_))
    ));

    let mut trailing_byte = encoded.clone();
    trailing_byte.push(0);
    assert!(matches!(
        fixed_shape.decode_canonical::<CompressedProof>(&trailing_byte),
        Err(FixedSerdeError::EncodedLength)
    ));

    drop(compressed);
    drop(prover_key);
    drop(recursive);
    drop(pp);

    let decoded = fixed_shape
        .decode_canonical::<CompressedProof>(&encoded)
        .expect("canonical decoding");
    assert_eq!(
        decoded
            .verify(&verifier_key, steps.len(), &initial_state)
            .expect("decoded compressed proof verification"),
        vec![Scalar::from(30u64)]
    );
}

#[test]
#[ignore = "explicit slow real Nova proof codec fixture"]
fn real_nova_compressed_proof_round_trips_canonically() {
    let pool = ThreadPoolBuilder::new()
        .num_threads(1)
        .thread_name(|_| "purify-nova-codec-test".to_owned())
        .build()
        .expect("one-thread Rayon pool");
    pool.install(run_real_proof_codec_fixture);
}
