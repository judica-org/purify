//! Candidate algebraic permutation for proof-dependent transcript data.
//!
//! This module deliberately does not select a receipt or BPPP transcript
//! suite. It provides the reproducible native primitive needed to test that
//! migration before any accepted proof format changes.

use std::array;
use std::sync::OnceLock;

use bulletproofs_cycle::Cycle;
use ff::Field;
use golden_halo2curves::Secq256k1Cycle;

use crate::Scalar;

pub(crate) const WIDTH: usize = 3;
pub(crate) const FULL_ROUNDS: usize = 8;
pub(crate) const PARTIAL_ROUNDS: usize = 64;
const FIELD_BITS: usize = 256;
const ROUND_CONSTANTS: usize = WIDTH * (FULL_ROUNDS + PARTIAL_ROUNDS);

type Matrix = [[Scalar; WIDTH]; WIDTH];

pub(crate) struct Parameters {
    pub(crate) round_constants: [Scalar; ROUND_CONSTANTS],
    pub(crate) mds: Matrix,
}

struct Grain {
    state: [u8; 80],
}

impl Grain {
    fn new() -> Self {
        let mut state = [1; 80];
        let mut offset = 0;
        write_bits(&mut state, &mut offset, 1, 2); // prime field
        write_bits(&mut state, &mut offset, 0, 4); // x^alpha S-box
        write_bits(&mut state, &mut offset, FIELD_BITS, 12);
        write_bits(&mut state, &mut offset, WIDTH, 12);
        write_bits(&mut state, &mut offset, FULL_ROUNDS, 10);
        write_bits(&mut state, &mut offset, PARTIAL_ROUNDS, 10);
        assert_eq!(offset, 50);

        let mut grain = Self { state };
        for _ in 0..160 {
            grain.shift();
        }
        grain
    }

    fn shift(&mut self) -> u8 {
        let next = self.state[62]
            ^ self.state[51]
            ^ self.state[38]
            ^ self.state[23]
            ^ self.state[13]
            ^ self.state[0];
        self.state.rotate_left(1);
        self.state[79] = next;
        next
    }

    fn next_bit(&mut self) -> u8 {
        let mut control = self.shift();
        while control == 0 {
            self.shift();
            control = self.shift();
        }
        self.shift()
    }

    fn next_bytes_be(&mut self) -> [u8; 32] {
        let mut bytes = [0; 32];
        for bit in 0..FIELD_BITS {
            bytes[bit / 8] |= self.next_bit() << (7 - bit % 8);
        }
        bytes
    }

    fn next_canonical(&mut self) -> Option<Scalar> {
        let mut bytes = self.next_bytes_be();
        bytes.reverse();
        Secq256k1Cycle::scalar_from_canonical(&bytes)
    }

    fn next_reduced(&mut self) -> Scalar {
        let mut bytes = self.next_bytes_be();
        bytes.reverse();
        let mut wide = [0; 64];
        wide[..32].copy_from_slice(&bytes);
        Secq256k1Cycle::scalar_from_wide(&wide)
    }
}

fn write_bits(state: &mut [u8; 80], offset: &mut usize, value: usize, width: usize) {
    assert!(width <= usize::BITS as usize);
    assert!(value < (1usize << width));
    for bit in (0..width).rev() {
        state[*offset] = ((value >> bit) & 1) as u8;
        *offset += 1;
    }
}

fn generate_parameters() -> Parameters {
    let mut grain = Grain::new();
    let mut constants = Vec::with_capacity(ROUND_CONSTANTS);
    while constants.len() < ROUND_CONSTANTS {
        if let Some(value) = grain.next_canonical() {
            constants.push(value);
        }
    }

    loop {
        let values: [Scalar; 2 * WIDTH] = array::from_fn(|_| grain.next_reduced());
        if values
            .iter()
            .enumerate()
            .any(|(index, value)| values[..index].contains(value))
        {
            continue;
        }

        let mut mds = [[Scalar::ZERO; WIDTH]; WIDTH];
        let mut valid = true;
        for row in 0..WIDTH {
            for column in 0..WIDTH {
                let sum = values[row] + values[WIDTH + column];
                let inverse: Option<Scalar> = sum.invert().into();
                let Some(inverse) = inverse else {
                    valid = false;
                    break;
                };
                mds[row][column] = inverse;
            }
        }
        if valid && secure_mds(&mds) {
            return Parameters {
                round_constants: constants
                    .try_into()
                    .expect("the fixed number of constants was generated"),
                mds,
            };
        }
    }
}

pub(crate) fn parameters() -> &'static Parameters {
    static PARAMETERS: OnceLock<Parameters> = OnceLock::new();
    PARAMETERS.get_or_init(generate_parameters)
}

fn identity() -> Matrix {
    array::from_fn(|row| {
        array::from_fn(|column| {
            if row == column {
                Scalar::ONE
            } else {
                Scalar::ZERO
            }
        })
    })
}

fn matrix_multiply(left: &Matrix, right: &Matrix) -> Matrix {
    array::from_fn(|row| {
        array::from_fn(|column| {
            (0..WIDTH).fold(Scalar::ZERO, |sum, index| {
                sum + left[row][index] * right[index][column]
            })
        })
    })
}

pub(crate) fn mix(matrix: &Matrix, vector: &[Scalar; WIDTH]) -> [Scalar; WIDTH] {
    array::from_fn(|row| {
        (0..WIDTH).fold(Scalar::ZERO, |sum, column| {
            sum + matrix[row][column] * vector[column]
        })
    })
}

fn matrix_power(matrix: &Matrix, mut exponent: usize) -> Matrix {
    let mut result = identity();
    let mut base = *matrix;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = matrix_multiply(&result, &base);
        }
        base = matrix_multiply(&base, &base);
        exponent >>= 1;
    }
    result
}

fn determinant(matrix: &Matrix) -> Scalar {
    matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1])
        - matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0])
        + matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0])
}

fn proportional(left: &[Scalar; WIDTH], right: &[Scalar; WIDTH]) -> bool {
    (0..WIDTH).all(|first| {
        (first + 1..WIDTH).all(|second| left[first] * right[second] == left[second] * right[first])
    })
}

fn krylov_secure(matrix: &Matrix) -> bool {
    let basis = [Scalar::ONE, Scalar::ZERO, Scalar::ZERO];
    let first = mix(matrix, &basis);
    let second = mix(matrix, &first);
    let columns = array::from_fn(|row| [basis[row], first[row], second[row]]);
    determinant(&columns) != Scalar::ZERO
}

fn algorithm_one_secure(matrix: &Matrix) -> bool {
    let powers = [identity(), *matrix, matrix_power(matrix, 2)];
    for exponent in 1..=2 {
        let current = &powers[exponent];
        let diagonal = array::from_fn(|row| {
            array::from_fn(|column| {
                if row == column {
                    current[0][0]
                } else {
                    Scalar::ZERO
                }
            })
        });
        if *current == diagonal {
            return false;
        }

        let source = if exponent == 1 { current } else { matrix };
        let vector = [Scalar::ZERO, source[0][2], -source[0][1]];
        if vector == [Scalar::ZERO; WIDTH] || proportional(&vector, &mix(current, &vector)) {
            return false;
        }

        for power in powers.iter().take(exponent + 1).skip(1) {
            if exponent == 1 {
                if power[0][1] == Scalar::ZERO && power[0][2] == Scalar::ZERO {
                    return false;
                }
            } else if proportional(&vector, &mix(power, &vector)) {
                return false;
            }
        }
    }
    true
}

fn secure_mds(matrix: &Matrix) -> bool {
    algorithm_one_secure(matrix)
        && krylov_secure(matrix)
        && (2..=4 * WIDTH).all(|power| krylov_secure(&matrix_power(matrix, power)))
}

fn pow5(value: Scalar) -> Scalar {
    let square = value.square();
    square.square() * value
}

pub(crate) fn permute(mut state: [Scalar; WIDTH]) -> [Scalar; WIDTH] {
    let parameters = parameters();
    for round in 0..FULL_ROUNDS + PARTIAL_ROUNDS {
        for (index, value) in state.iter_mut().enumerate() {
            *value += parameters.round_constants[round * WIDTH + index];
        }
        let full = !(FULL_ROUNDS / 2..FULL_ROUNDS / 2 + PARTIAL_ROUNDS).contains(&round);
        if full {
            state = state.map(pow5);
        } else {
            state[0] = pow5(state[0]);
        }
        state = mix(&parameters.mds, &state);
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    use sha2::{Digest, Sha256};

    fn decode(value: &str) -> Scalar {
        assert_eq!(value.len(), 64);
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex");
        }
        bytes.reverse();
        Secq256k1Cycle::scalar_from_canonical(&bytes).expect("canonical vector element")
    }

    fn encode(value: &Scalar) -> String {
        let mut bytes = Secq256k1Cycle::scalar_to_canonical(value);
        bytes.reverse();
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn digest(values: impl IntoIterator<Item = Scalar>) -> String {
        let mut digest = Sha256::new();
        for value in values {
            let mut bytes = Secq256k1Cycle::scalar_to_canonical(&value);
            bytes.reverse();
            digest.update(bytes);
        }
        format!("{:x}", digest.finalize())
    }

    #[test]
    fn parameters_match_the_pinned_generator() {
        let parameters = parameters();
        assert_eq!(
            digest(parameters.round_constants),
            "de0209e6db9909a2bebd435499a3dd1e199626ac0d1415b55f832c8dd5bdca6d"
        );
        assert_eq!(
            digest(parameters.mds.into_iter().flatten()),
            "b214b9440fa5cb193ab6bc98fad114eaad5da447dc61629c03ab1805328945d5"
        );
        assert!(secure_mds(&parameters.mds));
    }

    #[test]
    fn permutation_matches_cross_language_vectors() {
        let vectors = include_str!("../tests/vectors/poseidon_secp256k1_p.txt");
        for line in vectors.lines().filter(|line| line.starts_with("vector ")) {
            let words: Vec<_> = line.split_ascii_whitespace().skip(1).collect();
            assert_eq!(words.len(), 2 * WIDTH);
            let input = array::from_fn(|index| decode(words[index]));
            let expected: [String; WIDTH] = array::from_fn(|index| words[WIDTH + index].to_owned());
            assert_eq!(permute(input).map(|value| encode(&value)), expected);
        }
    }
}
