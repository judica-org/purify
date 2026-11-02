//! Exact Secq R1CS constraints for the candidate Poseidon permutation.

use std::array;

use bulletproofs_cycle::r1cs::{ConstraintSystem, LinearCombination};
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;

use crate::poseidon::{parameters, FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH};
use crate::Scalar;

/// Nonlinear multiplier count for one permutation. The MDS layer is linear.
pub(crate) const POSEIDON_PERMUTATION_MULTIPLIERS: usize =
    (FULL_ROUNDS * WIDTH + PARTIAL_ROUNDS) * 3;

fn normalize(value: LinearCombination<Scalar>) -> LinearCombination<Scalar> {
    let mut normalized = LinearCombination::default();
    for (variable, coefficient) in value.terms {
        if coefficient == Scalar::ZERO {
            continue;
        }
        if let Some((_, existing)) = normalized
            .terms
            .iter_mut()
            .find(|(candidate, _)| *candidate == variable)
        {
            *existing += coefficient;
        } else {
            normalized.terms.push((variable, coefficient));
        }
    }
    normalized
        .terms
        .retain(|(_, coefficient)| *coefficient != Scalar::ZERO);
    normalized
}

fn pow5<CS: ConstraintSystem<Secq256k1Cycle>>(
    cs: &mut CS,
    value: LinearCombination<Scalar>,
) -> LinearCombination<Scalar> {
    let original = value.clone();
    let (_, _, square) = cs.multiply(value.clone(), value);
    let (_, _, fourth) = cs.multiply(square.into(), square.into());
    let (_, _, fifth) = cs.multiply(fourth.into(), original);
    fifth.into()
}

/// Constrain one Poseidon permutation and return its three output lanes.
pub(crate) fn permute<CS: ConstraintSystem<Secq256k1Cycle>>(
    cs: &mut CS,
    mut state: [LinearCombination<Scalar>; WIDTH],
) -> [LinearCombination<Scalar>; WIDTH] {
    let parameters = parameters();
    for round in 0..FULL_ROUNDS + PARTIAL_ROUNDS {
        for (index, value) in state.iter_mut().enumerate() {
            *value = value.clone() + parameters.round_constants[round * WIDTH + index];
        }

        let full = !(FULL_ROUNDS / 2..FULL_ROUNDS / 2 + PARTIAL_ROUNDS).contains(&round);
        if full {
            for value in &mut state {
                *value = pow5(cs, value.clone());
            }
        } else {
            state[0] = pow5(cs, state[0].clone());
        }

        state = array::from_fn(|row| {
            normalize(
                (0..WIDTH).fold(LinearCombination::default(), |sum, column| {
                    sum + state[column].clone() * parameters.mds[row][column]
                }),
            )
        });
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    use bulletproofs_cycle::r1cs::{Metrics, Prover, R1CSError, R1CSProof, Variable, Verifier};
    use bulletproofs_cycle::{BulletproofGens, PedersenGens};
    use ff::Field;
    use merlin::Transcript;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::poseidon;

    struct ShapeConstraintSystem {
        transcript: Transcript,
        multipliers: usize,
        constraints: usize,
    }

    impl ShapeConstraintSystem {
        fn new() -> Self {
            Self {
                transcript: Transcript::new(b"Purify/PoseidonGadget/Shape/v1"),
                multipliers: 0,
                constraints: 0,
            }
        }
    }

    impl ConstraintSystem<Secq256k1Cycle> for ShapeConstraintSystem {
        fn transcript(&mut self) -> &mut Transcript {
            &mut self.transcript
        }

        fn multiply(
            &mut self,
            left: LinearCombination<Scalar>,
            right: LinearCombination<Scalar>,
        ) -> (Variable<Scalar>, Variable<Scalar>, Variable<Scalar>) {
            let variables = self
                .allocate_multiplier(Some((Scalar::ZERO, Scalar::ZERO)))
                .expect("shape multiplier has an assignment");
            self.constrain(left - variables.0);
            self.constrain(right - variables.1);
            variables
        }

        fn allocate(&mut self, assignment: Option<Scalar>) -> Result<Variable<Scalar>, R1CSError> {
            assignment.ok_or(R1CSError::MissingAssignment)?;
            Ok(Variable::committed(self.multipliers))
        }

        fn allocate_multiplier(
            &mut self,
            assignment: Option<(Scalar, Scalar)>,
        ) -> Result<(Variable<Scalar>, Variable<Scalar>, Variable<Scalar>), R1CSError> {
            assignment.ok_or(R1CSError::MissingAssignment)?;
            let index = self.multipliers;
            self.multipliers += 1;
            Ok((
                Variable::multiplier_left(index),
                Variable::multiplier_right(index),
                Variable::multiplier_output(index),
            ))
        }

        fn metrics(&self) -> Metrics {
            Metrics {
                multipliers: self.multipliers,
                constraints: self.constraints,
                phase_one_constraints: self.constraints,
                phase_two_constraints: 0,
            }
        }

        fn constrain(&mut self, _expression: LinearCombination<Scalar>) {
            self.constraints += 1;
        }
    }

    fn install<CS: ConstraintSystem<Secq256k1Cycle>>(
        cs: &mut CS,
        input: [Scalar; WIDTH],
        output: [Scalar; WIDTH],
    ) {
        let constrained = permute(cs, input.map(LinearCombination::from));
        for index in 0..WIDTH {
            cs.constrain(constrained[index].clone() - output[index]);
        }
    }

    #[test]
    fn permutation_shape_and_cost_are_input_independent() {
        let first_input = [Scalar::ZERO, Scalar::ONE, Scalar::from(2)];
        let second_input = [Scalar::from(9), Scalar::from(11), Scalar::from(13)];

        let mut first = ShapeConstraintSystem::new();
        install(&mut first, first_input, poseidon::permute(first_input));
        let mut second = ShapeConstraintSystem::new();
        install(&mut second, second_input, poseidon::permute(second_input));

        assert_eq!(first.metrics(), second.metrics());
        assert_eq!(
            first.metrics().multipliers,
            POSEIDON_PERMUTATION_MULTIPLIERS
        );
        assert_eq!(
            first.metrics().constraints,
            2 * POSEIDON_PERMUTATION_MULTIPLIERS + WIDTH
        );
    }

    #[test]
    #[ignore = "run explicitly in release mode; Bulletproof proving is slow in debug mode"]
    fn backend_proof_binds_input_and_output() {
        let input = [Scalar::ZERO, Scalar::ONE, Scalar::from(2)];
        let output = poseidon::permute(input);
        let generators = PedersenGens::<Secq256k1Cycle>::default();

        let mut prover = Prover::<Secq256k1Cycle, _>::new(
            &generators,
            Transcript::new(b"Purify/PoseidonGadget/ProofTest/v1"),
        );
        install(&mut prover, input, output);
        assert_eq!(
            prover.metrics().multipliers,
            POSEIDON_PERMUTATION_MULTIPLIERS
        );
        let proof_generators = BulletproofGens::<Secq256k1Cycle>::new(512, 1);
        let proof = prover
            .prove(&proof_generators, &mut ChaCha20Rng::from_seed([0x51; 32]))
            .expect("prove Poseidon permutation");
        assert_eq!(
            proof.to_bytes().len(),
            R1CSProof::<Secq256k1Cycle>::single_phase_wire_len(
                POSEIDON_PERMUTATION_MULTIPLIERS.next_power_of_two().ilog2() as usize,
            )
        );

        let verify = |candidate_input, candidate_output| {
            let mut verifier = Verifier::<Secq256k1Cycle, _>::new(Transcript::new(
                b"Purify/PoseidonGadget/ProofTest/v1",
            ));
            install(&mut verifier, candidate_input, candidate_output);
            verifier.verify(
                &proof,
                &generators,
                &proof_generators,
                &mut ChaCha20Rng::from_seed([0x91; 32]),
            )
        };

        verify(input, output).expect("verify Poseidon permutation");

        let mut changed_output = output;
        changed_output[0] += Scalar::ONE;
        assert!(verify(input, changed_output).is_err());

        let mut changed_input = input;
        changed_input[2] += Scalar::ONE;
        assert!(verify(changed_input, output).is_err());
    }
}
