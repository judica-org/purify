//! The two qualified proof vectors against the shipped proof codec.
//!
//! These need no verifier artifact. They exercise the fixed codec that every
//! untrusted proof byte passes through before Nova sees it.

use purify_construction_parent::codec::{FixedSerdeError, ProofShape};
use purify_construction_parent::nova::CompressedProof;
use purify_construction_parent::suite::{QUALIFIED, QUALIFIED_PROOF_LENGTH};

const ACCEPTED: &[u8] =
    include_bytes!("../../../../tests/vectors/construction_parent_sha256_accepted.proof");
const NONDECIDING: &[u8] =
    include_bytes!("../../../../tests/vectors/construction_parent_sha256_nondeciding.proof");

fn qualified_shape() -> ProofShape {
    QUALIFIED
        .proof_shape()
        .expect("the qualified suite is self-consistent")
}

fn decode(shape: &ProofShape, proof: &[u8]) -> Result<CompressedProof, FixedSerdeError> {
    shape.as_fixed_serde_shape().decode_canonical(proof)
}

#[test]
fn qualified_proofs_decode_under_the_qualified_shape() {
    let shape = qualified_shape();
    for proof in [ACCEPTED, NONDECIDING] {
        assert_eq!(proof.len(), QUALIFIED_PROOF_LENGTH);
        assert!(decode(&shape, proof).is_ok());
    }
}

#[test]
fn a_proof_of_any_other_length_is_rejected() {
    let shape = qualified_shape();
    let mut extended = ACCEPTED.to_vec();
    extended.push(0);
    for proof in [
        &[][..],
        &ACCEPTED[1..],
        &ACCEPTED[..ACCEPTED.len() - 1],
        &extended,
    ] {
        assert_eq!(
            decode(&shape, proof).err(),
            Some(FixedSerdeError::EncodedLength)
        );
    }
}

/// Flips one bit at a time across both proofs.
///
/// The codec must never panic on a damaged proof. Whatever it does accept is
/// canonical by construction, so the only other requirement is that it rejects
/// some damage itself rather than passing everything on.
#[test]
fn single_bit_damage_never_panics() {
    let shape = qualified_shape();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for proof in [ACCEPTED, NONDECIDING] {
        // A stride coprime to every field width visits each kind of field.
        for position in (0..proof.len()).step_by(7) {
            let mut damaged = proof.to_vec();
            damaged[position] ^= 1 << (position % 8);
            match decode(&shape, &damaged) {
                Ok(_) => accepted += 1,
                Err(_) => rejected += 1,
            }
        }
    }
    assert!(accepted > 0, "scalar damage still decodes");
    assert!(rejected > 0, "point damage is rejected by the codec");
}
