//! The V4 circuit-proof transcript: its inputs and its one schedule.
//!
//! [`replay_v4`] is the only place that orders the transcript's typed items
//! and challenges. It runs over a [`TranscriptBackend`]: natively over bytes
//! ([`replay_circuit_transcript_v4`]), and inside the relation over
//! constrained bytes while allocating the witness. Both therefore absorb the
//! same items in the same order by construction.

use crate::native::secp::{SecpEncodedPointWitness, SecpScalarWitness};
use statement::transcript::NativeTranscript;
use statement::{scalar_to_canonical, RelationError};

pub(crate) const CIRCUIT_NORM_PRECOMMIT_DOMAIN_V4: &[u8] =
    b"Purify/BPPP/CircuitNormArg/v4/precommit";
pub(crate) const CIRCUIT_NORM_PROOF_DOMAIN_V4: &[u8] = b"Purify/BPPP/CircuitNormArg/v4/proof";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitCommitmentModeV4 {
    Hidden,
    Public,
}

impl CircuitCommitmentModeV4 {
    pub(crate) const fn as_u64(self) -> u64 {
        match self {
            Self::Hidden => 0,
            Self::Public => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitTranscriptShapeV4 {
    pub mode: CircuitCommitmentModeV4,
    pub gate_count: usize,
    pub commitment_count: usize,
    pub n_vec_len: usize,
    pub l_vec_len: usize,
}

impl CircuitTranscriptShapeV4 {
    pub(crate) fn validate(self) -> Result<(), RelationError> {
        let expected_n = self
            .gate_count
            .checked_mul(2)
            .ok_or(RelationError::Malformed("V4 gate count"))?;
        if !self.gate_count.is_power_of_two()
            || (self.mode == CircuitCommitmentModeV4::Hidden
                && self.commitment_count >= self.gate_count)
            || self.n_vec_len != expected_n
            || self.l_vec_len != self.n_vec_len
            || (self.mode == CircuitCommitmentModeV4::Public && self.commitment_count == 0)
        {
            return Err(RelationError::Malformed("V4 circuit shape"));
        }
        for value in [
            self.gate_count,
            self.commitment_count,
            self.n_vec_len,
            self.l_vec_len,
        ] {
            u64::try_from(value).map_err(|_| RelationError::Malformed("V4 circuit size"))?;
        }
        Ok(())
    }

    pub(crate) const fn public_commitment_count(self) -> usize {
        match self.mode {
            CircuitCommitmentModeV4::Hidden => 0,
            CircuitCommitmentModeV4::Public => self.commitment_count,
        }
    }

    pub fn round_count(self) -> usize {
        self.n_vec_len.trailing_zeros() as usize
    }

    /// The six words both V4 transcripts absorb for this shape.
    ///
    /// Callers validate the shape first, which establishes that every size
    /// fits the transcript's 64-bit words.
    fn transcript_words(self) -> [u64; 6] {
        let word = |value| u64::try_from(value).expect("a validated V4 shape size fits u64");
        [
            self.mode.as_u64(),
            word(self.gate_count),
            word(self.commitment_count),
            word(self.n_vec_len),
            word(self.l_vec_len),
            word(self.public_commitment_count()),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitPointPairWitnessV4 {
    pub encoded: [u8; 65],
    pub first_y: [u8; 32],
    pub second_y: [u8; 32],
}

impl CircuitPointPairWitnessV4 {
    /// Opens one half of the signed pair as its own encoded point.
    ///
    /// The pair's sign byte carries one parity bit per point. An identity
    /// point has an all-zero x and must leave its parity bit clear.
    pub(crate) fn point(&self, index: usize) -> Result<SecpEncodedPointWitness, RelationError> {
        if self.encoded[0] > 3 || index > 1 {
            return Err(RelationError::Malformed("V4 point pair"));
        }
        let offset = 1 + 32 * index;
        let x = &self.encoded[offset..offset + 32];
        let odd = self.encoded[0] & (2u8 >> index) != 0;
        let y = if index == 0 {
            self.first_y
        } else {
            self.second_y
        };
        if x.iter().all(|byte| *byte == 0) {
            if odd {
                return Err(RelationError::Malformed("V4 signed pair identity"));
            }
            return Ok(SecpEncodedPointWitness {
                encoded: [0; 33],
                y,
            });
        }
        let mut encoded = [0; 33];
        encoded[0] = 2 + u8::from(odd);
        encoded[1..].copy_from_slice(x);
        Ok(SecpEncodedPointWitness { encoded, y })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitProofTranscriptWitnessV4 {
    pub public_commitments: Vec<SecpEncodedPointWitness>,
    pub raw_commitment: SecpEncodedPointWitness,
    pub coefficient_commitment: SecpEncodedPointWitness,
    pub anchored_offset: SecpEncodedPointWitness,
    pub anchored_commitment: SecpEncodedPointWitness,
    pub batched_public_commitment: SecpEncodedPointWitness,
    pub dlog_nonce: SecpEncodedPointWitness,
    pub dlog_response: SecpScalarWitness,
    pub mask_commitment: SecpEncodedPointWitness,
    pub t2: SecpScalarWitness,
    pub combined_commitment: SecpEncodedPointWitness,
    pub rounds: Vec<CircuitPointPairWitnessV4>,
    pub terminal_n: SecpScalarWitness,
    pub terminal_l: SecpScalarWitness,
}

/// Two points absorbed as one signed pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitPointPair<P> {
    pub first: P,
    pub second: P,
}

/// Everything one replay of the V4 transcript binds: the witness values in a
/// backend's own representation, and the challenges derived from them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitTranscriptV4<P, S> {
    pub public_commitments: Vec<P>,
    pub raw_commitment: P,
    pub coefficient_commitment: P,
    pub anchored_offset: P,
    pub anchored_commitment: P,
    pub batched_public_commitment: P,
    pub dlog_nonce: P,
    pub dlog_response: S,
    pub mask_commitment: P,
    pub t2: S,
    pub combined_commitment: P,
    pub rounds: Vec<CircuitPointPair<P>>,
    pub terminal_n: S,
    pub terminal_l: S,
    pub precommitment: S,
    pub rho: S,
    pub mul_scale: S,
    pub mul_ratio: S,
    pub row_ratio: S,
    pub eta: S,
    pub dlog_challenge: S,
    pub alpha: S,
    pub gammas: Vec<S>,
    pub prepared_binding: S,
}

/// One way to run a typed-transcript schedule.
///
/// The native backend hashes bytes. The constrained backend allocates each
/// witness value where the schedule first names it and hashes constrained
/// bytes. Appends are associated functions because they never touch a
/// constraint system: only lifting a witness, drawing a challenge, and a
/// mode rule do.
pub(crate) trait TranscriptBackend {
    type Transcript;
    type Digest;
    type Point;
    type Scalar;
    type Error;

    fn malformed(error: RelationError) -> Self::Error;
    fn new_transcript() -> Self::Transcript;

    /// Brings one witness point into this backend.
    fn point(&mut self, witness: SecpEncodedPointWitness) -> Result<Self::Point, Self::Error>;
    /// Brings one witness scalar into this backend.
    fn scalar(&mut self, witness: SecpScalarWitness) -> Result<Self::Scalar, Self::Error>;
    /// Hashes the pending items and the round marker into one challenge.
    fn challenge(
        &mut self,
        transcript: &mut Self::Transcript,
        round: u64,
    ) -> Result<Self::Scalar, Self::Error>;

    fn append_constant(transcript: &mut Self::Transcript, bytes: &[u8]) -> Result<(), Self::Error>;
    fn append_digest(
        transcript: &mut Self::Transcript,
        digest: &Self::Digest,
    ) -> Result<(), Self::Error>;
    fn append_u64(transcript: &mut Self::Transcript, value: u64);
    fn append_scalar(
        transcript: &mut Self::Transcript,
        scalar: &Self::Scalar,
    ) -> Result<(), Self::Error>;
    fn append_point(
        transcript: &mut Self::Transcript,
        point: &Self::Point,
    ) -> Result<(), Self::Error>;
    /// Appends only the x coordinate, as untyped bytes.
    fn append_point_x(
        transcript: &mut Self::Transcript,
        point: &Self::Point,
    ) -> Result<(), Self::Error>;
    fn append_point_pair(
        transcript: &mut Self::Transcript,
        pair: &CircuitPointPair<Self::Point>,
    ) -> Result<(), Self::Error>;

    // The hidden/public commitment-mode rules are constraints of the
    // relation. The native backend replays the transcript without judging
    // the witness, so it accepts all three.
    fn require_identity(&mut self, point: &Self::Point) -> Result<(), Self::Error>;
    fn require_finite_even(&mut self, point: &Self::Point) -> Result<(), Self::Error>;
    fn require_zero(&mut self, scalar: &Self::Scalar) -> Result<(), Self::Error>;
}

/// The V4 circuit-proof transcript schedule.
///
/// The caller has validated `shape` and checked the witness against it.
pub(crate) fn replay_v4<B: TranscriptBackend>(
    backend: &mut B,
    shape: CircuitTranscriptShapeV4,
    circuit_binding_digest: &B::Digest,
    raw_generator_digest: [u8; 32],
    witness: &CircuitProofTranscriptWitnessV4,
) -> Result<CircuitTranscriptV4<B::Point, B::Scalar>, B::Error> {
    let hidden = shape.mode == CircuitCommitmentModeV4::Hidden;
    let shape_words = shape.transcript_words();

    // The precommitment binds the statement, the shape and the commitments.
    let mut precommit = B::new_transcript();
    B::append_constant(&mut precommit, CIRCUIT_NORM_PRECOMMIT_DOMAIN_V4)?;
    B::append_digest(&mut precommit, circuit_binding_digest)?;
    for word in shape_words {
        B::append_u64(&mut precommit, word);
    }
    let mut public_commitments = Vec::with_capacity(witness.public_commitments.len());
    for point in witness.public_commitments.iter().copied() {
        let point = backend.point(point)?;
        B::append_point(&mut precommit, &point)?;
        public_commitments.push(point);
    }
    let raw_commitment = backend.point(witness.raw_commitment)?;
    B::append_point(&mut precommit, &raw_commitment)?;
    let precommitment = backend.challenge(&mut precommit, 0)?;

    // The proof transcript starts from the precommitment and the generators.
    let mut proof = B::new_transcript();
    B::append_constant(&mut proof, CIRCUIT_NORM_PROOF_DOMAIN_V4)?;
    B::append_scalar(&mut proof, &precommitment)?;
    B::append_constant(&mut proof, &raw_generator_digest)?;
    for word in shape_words {
        B::append_u64(&mut proof, word);
    }
    let rho = backend.challenge(&mut proof, 0)?;
    let mul_scale = backend.challenge(&mut proof, 1)?;
    let mul_ratio = backend.challenge(&mut proof, 2)?;
    let row_ratio = backend.challenge(&mut proof, 3)?;

    let coefficient_commitment = backend.point(witness.coefficient_commitment)?;
    B::append_point(&mut proof, &coefficient_commitment)?;
    let anchored_offset = backend.point(witness.anchored_offset)?;
    B::append_point(&mut proof, &anchored_offset)?;
    let anchored_commitment = backend.point(witness.anchored_commitment)?;
    B::append_point(&mut proof, &anchored_commitment)?;
    let eta = backend.challenge(&mut proof, 4)?;

    // Public-commitment discrete log. Hidden mode has none: its batch and
    // nonce are the identity and its response is zero.
    let batched_public_commitment = backend.point(witness.batched_public_commitment)?;
    B::append_point(&mut proof, &batched_public_commitment)?;
    let dlog_nonce = backend.point(witness.dlog_nonce)?;
    if hidden {
        backend.require_identity(&batched_public_commitment)?;
        backend.require_identity(&dlog_nonce)?;
    } else {
        backend.require_finite_even(&dlog_nonce)?;
    }
    B::append_point_x(&mut proof, &dlog_nonce)?;
    let dlog_challenge = backend.challenge(&mut proof, 5)?;
    let dlog_response = backend.scalar(witness.dlog_response)?;
    if hidden {
        backend.require_zero(&dlog_response)?;
    }
    B::append_scalar(&mut proof, &dlog_response)?;

    let mask_commitment = backend.point(witness.mask_commitment)?;
    B::append_point(&mut proof, &mask_commitment)?;
    let t2 = backend.scalar(witness.t2)?;
    B::append_scalar(&mut proof, &t2)?;
    let alpha = backend.challenge(&mut proof, 6)?;
    let combined_commitment = backend.point(witness.combined_commitment)?;
    B::append_point(&mut proof, &combined_commitment)?;

    // One signed pair and one challenge per norm-argument round.
    let mut round = 7;
    let mut rounds = Vec::with_capacity(witness.rounds.len());
    let mut gammas = Vec::with_capacity(witness.rounds.len());
    for pair in &witness.rounds {
        let first = backend.point(pair.point(0).map_err(B::malformed)?)?;
        let second = backend.point(pair.point(1).map_err(B::malformed)?)?;
        let pair = CircuitPointPair { first, second };
        B::append_point_pair(&mut proof, &pair)?;
        rounds.push(pair);
        gammas.push(backend.challenge(&mut proof, round)?);
        round += 1;
    }
    let terminal_n = backend.scalar(witness.terminal_n)?;
    let terminal_l = backend.scalar(witness.terminal_l)?;
    B::append_scalar(&mut proof, &terminal_n)?;
    B::append_scalar(&mut proof, &terminal_l)?;
    let prepared_binding = backend.challenge(&mut proof, round)?;

    Ok(CircuitTranscriptV4 {
        public_commitments,
        raw_commitment,
        coefficient_commitment,
        anchored_offset,
        anchored_commitment,
        batched_public_commitment,
        dlog_nonce,
        dlog_response,
        mask_commitment,
        t2,
        combined_commitment,
        rounds,
        terminal_n,
        terminal_l,
        precommitment,
        rho,
        mul_scale,
        mul_ratio,
        row_ratio,
        eta,
        dlog_challenge,
        alpha,
        gammas,
        prepared_binding,
    })
}

/// The native backend: canonical bytes in, canonical bytes out.
struct Native;

fn point_x(point: &SecpEncodedPointWitness) -> [u8; 32] {
    point.encoded[1..]
        .try_into()
        .expect("an encoded point x is 32 bytes")
}

impl TranscriptBackend for Native {
    type Transcript = NativeTranscript;
    type Digest = [u8; 32];
    type Point = SecpEncodedPointWitness;
    type Scalar = SecpScalarWitness;
    type Error = RelationError;

    fn malformed(error: RelationError) -> RelationError {
        error
    }

    fn new_transcript() -> NativeTranscript {
        NativeTranscript::new()
    }

    fn point(
        &mut self,
        witness: SecpEncodedPointWitness,
    ) -> Result<SecpEncodedPointWitness, RelationError> {
        Ok(witness)
    }

    fn scalar(&mut self, witness: SecpScalarWitness) -> Result<SecpScalarWitness, RelationError> {
        Ok(witness)
    }

    fn challenge(
        &mut self,
        transcript: &mut NativeTranscript,
        round: u64,
    ) -> Result<SecpScalarWitness, RelationError> {
        let mut encoded = scalar_to_canonical(&transcript.challenge(round)?.scalar);
        encoded.reverse();
        Ok(SecpScalarWitness::from_bytes_be(encoded))
    }

    fn append_constant(
        transcript: &mut NativeTranscript,
        bytes: &[u8],
    ) -> Result<(), RelationError> {
        transcript.append_bytes(bytes)
    }

    fn append_digest(
        transcript: &mut NativeTranscript,
        digest: &[u8; 32],
    ) -> Result<(), RelationError> {
        transcript.append_bytes(digest)
    }

    fn append_u64(transcript: &mut NativeTranscript, value: u64) {
        transcript.append_u64(value);
    }

    fn append_scalar(
        transcript: &mut NativeTranscript,
        scalar: &SecpScalarWitness,
    ) -> Result<(), RelationError> {
        transcript.append_scalar(scalar.bytes);
        Ok(())
    }

    fn append_point(
        transcript: &mut NativeTranscript,
        point: &SecpEncodedPointWitness,
    ) -> Result<(), RelationError> {
        transcript.append_point(point.encoded[0], point_x(point))
    }

    fn append_point_x(
        transcript: &mut NativeTranscript,
        point: &SecpEncodedPointWitness,
    ) -> Result<(), RelationError> {
        transcript.append_bytes(&point.encoded[1..])
    }

    fn append_point_pair(
        transcript: &mut NativeTranscript,
        pair: &CircuitPointPair<SecpEncodedPointWitness>,
    ) -> Result<(), RelationError> {
        let odd = |point: &SecpEncodedPointWitness| u8::from(point.encoded[0] == 3);
        transcript.append_point_pair(
            2 * odd(&pair.first) + odd(&pair.second),
            point_x(&pair.first),
            point_x(&pair.second),
        )
    }

    fn require_identity(&mut self, _point: &SecpEncodedPointWitness) -> Result<(), RelationError> {
        Ok(())
    }

    fn require_finite_even(
        &mut self,
        _point: &SecpEncodedPointWitness,
    ) -> Result<(), RelationError> {
        Ok(())
    }

    fn require_zero(&mut self, _scalar: &SecpScalarWitness) -> Result<(), RelationError> {
        Ok(())
    }
}

/// The V4 transcript as native values.
pub type NativeCircuitTranscriptV4 =
    CircuitTranscriptV4<SecpEncodedPointWitness, SecpScalarWitness>;

/// Replay the exact V4 typed transcript without building a constraint system.
pub fn replay_circuit_transcript_v4(
    shape: CircuitTranscriptShapeV4,
    circuit_binding_digest: [u8; 32],
    raw_generator_digest: [u8; 32],
    witness: &CircuitProofTranscriptWitnessV4,
) -> Result<NativeCircuitTranscriptV4, RelationError> {
    shape.validate()?;
    if witness.public_commitments.len() != shape.public_commitment_count()
        || witness.rounds.len() != shape.round_count()
    {
        return Err(RelationError::Malformed("V4 transcript witness shape"));
    }
    replay_v4(
        &mut Native,
        shape,
        &circuit_binding_digest,
        raw_generator_digest,
        witness,
    )
}
