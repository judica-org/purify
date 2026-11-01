//! Composable candidate algebraic transcript primitives.
//!
//! These constraints are migration foundations. They do not select a receipt,
//! BPPP, or accumulation transcript suite.

use std::array;

use ff::Field;

use crate::poseidon::{parameters, FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH};
use crate::relation_builder::{Builder, Expression};

fn pow5(builder: &mut Builder, value: &Expression) -> Expression {
    let square = builder.multiply(value, value);
    let fourth = builder.multiply(&square, &square);
    builder.multiply(&fourth, value)
}

/// Constrain one exact candidate Poseidon permutation.
pub(crate) fn permute(
    builder: &mut Builder,
    mut state: [Expression; WIDTH],
) -> [Expression; WIDTH] {
    let parameters = parameters();
    for round in 0..FULL_ROUNDS + PARTIAL_ROUNDS {
        for (index, value) in state.iter_mut().enumerate() {
            *value = value.clone().add(&Expression::constant(
                parameters.round_constants[round * WIDTH + index],
            ));
        }

        let full = !(FULL_ROUNDS / 2..FULL_ROUNDS / 2 + PARTIAL_ROUNDS).contains(&round);
        if full {
            for value in &mut state {
                *value = pow5(builder, value);
            }
        } else {
            state[0] = pow5(builder, &state[0]);
        }

        state = array::from_fn(|row| {
            (0..WIDTH).fold(Expression::constant(crate::Scalar::ZERO), |sum, column| {
                sum.add(&state[column].clone().scale(parameters.mds[row][column]))
            })
        });
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;

    use crate::{poseidon, proof_wire_len, prove, verify, ReceiptCycleError, Scalar};

    fn build_relation(
        input: [Scalar; WIDTH],
        expected: [Scalar; WIDTH],
    ) -> Result<(Vec<u8>, Vec<u8>), ReceiptCycleError> {
        let mut builder = Builder::default();
        let input = input.map(|value| builder.allocate(value));
        let expected = expected.map(|value| builder.allocate(value));
        let output = permute(&mut builder, input);
        for index in 0..WIDTH {
            builder.constrain_equal(&output[index], &expected[index]);
        }
        builder.finish()
    }

    #[test]
    fn builder_permutation_matches_native_and_has_fixed_shape() {
        let first = [Scalar::ZERO, Scalar::ONE, Scalar::from(2)];
        let second = [Scalar::from(9), Scalar::from(11), Scalar::from(13)];
        let (first_circuit, _) =
            build_relation(first, poseidon::permute(first)).expect("first relation");
        let (second_circuit, _) =
            build_relation(second, poseidon::permute(second)).expect("second relation");
        assert_eq!(first_circuit, second_circuit);
        assert_eq!(
            u32::from_le_bytes(first_circuit[1..5].try_into().expect("gate count")),
            270
        );
        assert_eq!(proof_wire_len(&first_circuit).expect("proof size"), 1019);
    }

    #[test]
    fn builder_permutation_proof_binds_the_output() {
        let input = [Scalar::from(3), Scalar::from(5), Scalar::from(8)];
        let output = poseidon::permute(input);
        let (circuit, assignment) = build_relation(input, output).expect("relation");
        let statement = b"builder Poseidon foundation";
        let proof = prove(&circuit, &assignment, statement, [0x61; 32]).expect("proof");
        verify(&circuit, statement, &proof).expect("verification");

        let mut changed = output;
        changed[1] += Scalar::ONE;
        let (_, false_assignment) = build_relation(input, changed).expect("false relation");
        let false_proof =
            prove(&circuit, &false_assignment, statement, [0x62; 32]).expect("false proof");
        assert!(verify(&circuit, statement, &false_proof).is_err());
    }
}
