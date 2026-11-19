//! Exact accountable-signature hashes for direct Nova relations.
//!
//! These constraints reproduce the BIP340-tagged SHA-256 framing in
//! `puresign/accountable.cpp`. Public-key validity and the response equation
//! remain separate relation checks; this module binds only the exact bytes and
//! the full-width challenge reduction.

use nova_snark::frontend::{gadgets::boolean::Boolean, ConstraintSystem, SynthesisError};
use sha2::{Digest as _, Sha256};

use crate::nova_secp_scalar::{nonzero_scalar_from_sha256, CanonicalSecpScalar};
use crate::nova_sha256_transcript::{constrain_sha256, NovaByte};
use crate::Scalar;

const NONCE_TAG: &[u8] = b"Purify/Accountable/Nonce/v2";
const CHALLENGE_TAG: &[u8] = b"Purify/Accountable/Challenge/v2";

/// Accountable context bytes whose semantic validity is checked by callers.
pub(crate) struct DirectAccountableContext<'a> {
    signing_key: &'a [NovaByte; 32],
    host_commitment: &'a [NovaByte; 32],
    coalition_core_digest: &'a [NovaByte; 32],
    slot: &'a [NovaByte],
}

impl<'a> DirectAccountableContext<'a> {
    /// Build one fixed-shape accountable context.
    ///
    /// Slice lengths become constants in the relation shape. A caller that
    /// admits multiple lengths must select and authenticate the intended
    /// relation profile outside this primitive.
    pub(crate) fn new(
        signing_key: &'a [NovaByte; 32],
        host_commitment: &'a [NovaByte; 32],
        coalition_core_digest: &'a [NovaByte; 32],
        slot: &'a [NovaByte],
    ) -> Result<Self, SynthesisError> {
        if slot.is_empty() || u64::try_from(slot.len()).is_err() {
            return Err(synthesis_error("accountable slot length"));
        }
        Ok(Self {
            signing_key,
            host_commitment,
            coalition_core_digest,
            slot,
        })
    }
}

pub(crate) struct DirectAccountableChallenge {
    digest: [NovaByte; 32],
    scalar: CanonicalSecpScalar,
}

impl DirectAccountableChallenge {
    pub(crate) fn digest(&self) -> &[NovaByte; 32] {
        &self.digest
    }

    pub(crate) fn scalar(&self) -> &CanonicalSecpScalar {
        &self.scalar
    }
}

fn synthesis_error(label: &'static str) -> SynthesisError {
    SynthesisError::Unsatisfiable(label.to_owned())
}

fn append_constant(output: &mut Vec<NovaByte>, value: &[u8]) {
    output.extend(value.iter().copied().map(NovaByte::constant));
}

fn tagged_prefix(tag: &[u8]) -> Vec<NovaByte> {
    let tag_hash = Sha256::digest(tag);
    let mut output = Vec::with_capacity(64);
    append_constant(&mut output, &tag_hash);
    append_constant(&mut output, &tag_hash);
    output
}

fn append_context(output: &mut Vec<NovaByte>, context: &DirectAccountableContext<'_>) {
    output.extend_from_slice(context.signing_key);
    output.extend_from_slice(context.host_commitment);
    output.extend_from_slice(context.coalition_core_digest);
    append_constant(
        output,
        &u64::try_from(context.slot.len())
            .expect("validated accountable slot length")
            .to_be_bytes(),
    );
    output.extend_from_slice(context.slot);
}

/// Constrain the exact deterministic nonce-evaluation input.
pub(crate) fn constrain_accountable_nonce_input<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    context: &DirectAccountableContext<'_>,
) -> Result<[NovaByte; 32], SynthesisError> {
    let mut encoded = tagged_prefix(NONCE_TAG);
    append_context(&mut encoded, context);
    constrain_sha256(cs.namespace(|| "accountable nonce hash"), &encoded)
}

/// Constrain the exact response challenge and full secp256k1 reduction.
pub(crate) fn constrain_accountable_challenge<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    context: &DirectAccountableContext<'_>,
    canonical_body: &[NovaByte],
) -> Result<DirectAccountableChallenge, SynthesisError> {
    let body_length = u64::try_from(canonical_body.len())
        .map_err(|_| synthesis_error("accountable body length"))?;
    let mut encoded = tagged_prefix(CHALLENGE_TAG);
    append_context(&mut encoded, context);
    append_constant(&mut encoded, &body_length.to_be_bytes());
    encoded.extend_from_slice(canonical_body);
    let digest = constrain_sha256(cs.namespace(|| "accountable challenge hash"), &encoded)?;
    let bits_le = digest
        .iter()
        .rev()
        .flat_map(|byte| byte.bits_le().iter().cloned())
        .collect::<Vec<Boolean>>();
    let scalar =
        nonzero_scalar_from_sha256(cs.namespace(|| "accountable challenge scalar"), &bits_le)?;
    Ok(DirectAccountableChallenge { digest, scalar })
}

#[cfg(test)]
mod tests {
    use nova_snark::frontend::{
        gadgets::boolean::Boolean, util_cs::test_cs::TestConstraintSystem, ConstraintSystem,
    };
    use num_bigint::{BigInt, Sign};

    use super::*;
    use crate::nova_secp_scalar::constant_scalar;
    use crate::secp_constants::SECP256K1_SCALAR_ORDER_BE;
    use crate::secp_native::SecpScalarWitness;

    #[derive(Clone)]
    struct Fixture {
        signing_key: [u8; 32],
        host_commitment: [u8; 32],
        coalition_core_digest: [u8; 32],
        slot: Vec<u8>,
        body: Vec<u8>,
    }

    fn fixture() -> Fixture {
        Fixture {
            signing_key: [
                0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
                0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
                0x16, 0xf8, 0x17, 0x98,
            ],
            host_commitment: [0x22; 32],
            coalition_core_digest: [0x33; 32],
            slot: b"accountable-slot\0v2".to_vec(),
            body: b"canonical-body\0with-framing".to_vec(),
        }
    }

    fn decode_hex<const SIZE: usize>(encoded: &str) -> [u8; SIZE] {
        assert_eq!(encoded.len(), 2 * SIZE);
        std::array::from_fn(|index| {
            u8::from_str_radix(&encoded[2 * index..2 * index + 2], 16).expect("hex byte")
        })
    }

    fn tagged_sha256(tag: &[u8], payload: &[u8]) -> [u8; 32] {
        let tag_hash = Sha256::digest(tag);
        let mut digest = Sha256::new();
        digest.update(tag_hash);
        digest.update(tag_hash);
        digest.update(payload);
        digest.finalize().into()
    }

    fn native_context_payload(fixture: &Fixture) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&fixture.signing_key);
        payload.extend_from_slice(&fixture.host_commitment);
        payload.extend_from_slice(&fixture.coalition_core_digest);
        payload.extend_from_slice(&(fixture.slot.len() as u64).to_be_bytes());
        payload.extend_from_slice(&fixture.slot);
        payload
    }

    fn native_hashes(fixture: &Fixture) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let context = native_context_payload(fixture);
        let nonce = tagged_sha256(NONCE_TAG, &context);
        let mut challenge_payload = context;
        challenge_payload.extend_from_slice(&(fixture.body.len() as u64).to_be_bytes());
        challenge_payload.extend_from_slice(&fixture.body);
        let challenge_digest = tagged_sha256(CHALLENGE_TAG, &challenge_payload);
        let order = BigInt::from_bytes_be(Sign::Plus, &SECP256K1_SCALAR_ORDER_BE);
        let scalar = BigInt::from_bytes_be(Sign::Plus, &challenge_digest) % order;
        assert_ne!(scalar, BigInt::from(0u8));
        let (_, scalar_bytes) = scalar.to_bytes_be();
        let mut encoded = [0; 32];
        encoded[32 - scalar_bytes.len()..].copy_from_slice(&scalar_bytes);
        assert_eq!(
            nonce,
            decode_hex("89ff0f4751450924b1f2c80e2459addf7f6589327d82d555777ae8e9433a1201")
        );
        assert_eq!(
            challenge_digest,
            decode_hex("e43d7fe34fefb7c872bda3ee00511583932abb6bd33f9da7266d93471e62a7bd")
        );
        assert_eq!(
            encoded,
            decode_hex("e43d7fe34fefb7c872bda3ee00511583932abb6bd33f9da7266d93471e62a7bd")
        );
        (nonce, challenge_digest, encoded)
    }

    fn allocate_bytes<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        label: &'static str,
        bytes: &[u8],
    ) -> Vec<NovaByte> {
        bytes
            .iter()
            .copied()
            .enumerate()
            .map(|(index, byte)| {
                NovaByte::allocate(cs.namespace(|| format!("{label} byte {index}")), byte)
                    .expect("byte allocation")
            })
            .collect()
    }

    fn enforce_digest<CS: ConstraintSystem<Scalar>>(
        mut cs: CS,
        actual: &[NovaByte; 32],
        expected: [u8; 32],
    ) {
        for (byte_index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
            for (bit_index, bit) in actual.bits_le().iter().enumerate() {
                Boolean::enforce_equal(
                    cs.namespace(|| format!("digest {byte_index} bit {bit_index}")),
                    bit,
                    &Boolean::constant((expected >> bit_index) & 1 == 1),
                )
                .expect("digest binding");
            }
        }
    }

    fn synthesize_bound_fixture(
        fixture: &Fixture,
        expected_nonce: [u8; 32],
        expected_challenge_digest: [u8; 32],
        expected_challenge: [u8; 32],
    ) -> TestConstraintSystem<Scalar> {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let signing_key: [NovaByte; 32] = allocate_bytes(
            cs.namespace(|| "signing key"),
            "signing key",
            &fixture.signing_key,
        )
        .try_into()
        .expect("signing key bytes");
        let host_commitment: [NovaByte; 32] = allocate_bytes(
            cs.namespace(|| "host commitment"),
            "host commitment",
            &fixture.host_commitment,
        )
        .try_into()
        .expect("host commitment bytes");
        let coalition_core_digest: [NovaByte; 32] = allocate_bytes(
            cs.namespace(|| "coalition core"),
            "coalition core",
            &fixture.coalition_core_digest,
        )
        .try_into()
        .expect("coalition core bytes");
        let slot = allocate_bytes(cs.namespace(|| "slot"), "slot", &fixture.slot);
        let body = allocate_bytes(cs.namespace(|| "body"), "body", &fixture.body);
        let context = DirectAccountableContext::new(
            &signing_key,
            &host_commitment,
            &coalition_core_digest,
            &slot,
        )
        .expect("accountable context");
        let nonce = constrain_accountable_nonce_input(cs.namespace(|| "nonce input"), &context)
            .expect("nonce input");
        let challenge =
            constrain_accountable_challenge(cs.namespace(|| "challenge"), &context, &body)
                .expect("challenge");
        enforce_digest(cs.namespace(|| "nonce binding"), &nonce, expected_nonce);
        enforce_digest(
            cs.namespace(|| "challenge digest binding"),
            challenge.digest(),
            expected_challenge_digest,
        );
        let expected = constant_scalar::<TestConstraintSystem<Scalar>>(
            SecpScalarWitness::from_bytes_be(expected_challenge),
        )
        .expect("expected challenge scalar");
        cs.enforce(
            || "challenge scalar binding",
            |_| challenge.scalar().embedded(),
            |linear| linear + TestConstraintSystem::<Scalar>::one(),
            |_| expected.embedded(),
        );
        cs
    }

    #[test]
    fn accountable_hashes_match_native_framing_and_reduction() {
        let fixture = fixture();
        let (nonce, challenge_digest, challenge) = native_hashes(&fixture);
        let cs = synthesize_bound_fixture(&fixture, nonce, challenge_digest, challenge);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn accountable_hash_constraints_bind_every_input_class() {
        let fixture = fixture();
        let (nonce, challenge_digest, challenge) = native_hashes(&fixture);
        let mut mutations = Vec::new();
        let mut signing_key = fixture.clone();
        signing_key.signing_key[31] ^= 1;
        mutations.push(signing_key);
        let mut host = fixture.clone();
        host.host_commitment[0] ^= 1;
        mutations.push(host);
        let mut core = fixture.clone();
        core.coalition_core_digest[0] ^= 1;
        mutations.push(core);
        let mut slot = fixture.clone();
        slot.slot[0] ^= 1;
        mutations.push(slot);
        let mut body = fixture.clone();
        body.body[0] ^= 1;
        mutations.push(body);

        for mutation in mutations {
            let cs = synthesize_bound_fixture(&mutation, nonce, challenge_digest, challenge);
            assert!(cs.which_is_unsatisfied().is_some());
        }
    }

    #[test]
    fn accountable_context_rejects_an_empty_slot() {
        let bytes = std::array::from_fn(|_| NovaByte::constant(0));
        assert!(DirectAccountableContext::new(&bytes, &bytes, &bytes, &[]).is_err());
    }
}
