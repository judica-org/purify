//! Equation-level access to the scalar and point gadgets.
//!
//! The gadgets take one namespaced constraint system per call. Relation code
//! that spells those namespaces out spends more lines on naming than on the
//! equations it checks. [`Ops`] owns one constraint system and names each
//! operation itself, so a relation reads as the equations it constrains.
//!
//! Every method performs exactly the gadget calls its body shows, in that
//! order, and nothing else. Namespace names never reach the constraint stream:
//! they only label constraints for a debugging constraint system. Each name
//! is the operation, a per-context sequence number, and the source line of
//! the call, which keeps names unique within a parent and points an
//! unsatisfied constraint back at the line that created it.

use std::panic::Location;

use nova_snark::frontend::{
    gadgets::boolean::Boolean, ConstraintSystem, Namespace, SynthesisError,
};

use crate::gadgets::point::{
    add_points, allocate_constant_point, allocate_encoded_point, encode_computed_point,
    scale_point, EncodedPoint, Point,
};
use crate::gadgets::scalar::{
    add_scalars, allocate_canonical_scalar, constant_scalar, constant_u64, invert_scalar,
    multiply_scalars, subtract_scalars, CanonicalScalar,
};
use crate::gadgets::sha256::{Byte, Transcript};
use crate::gadgets::transcript::challenge;
use crate::native::secp::{PointValue, SecpEncodedPointWitness, SecpScalarWitness};
use statement::Scalar;

type Result<T> = std::result::Result<T, SynthesisError>;

/// One constraint system and the arithmetic a relation performs on it.
pub(crate) struct Ops<CS> {
    cs: CS,
    sequence: usize,
}

impl<CS: ConstraintSystem<Scalar>> Ops<CS> {
    pub(crate) fn new(cs: CS) -> Self {
        Self { cs, sequence: 0 }
    }

    /// Opens the uniquely named namespace for one operation.
    #[track_caller]
    fn at(&mut self, operation: &'static str) -> Namespace<'_, Scalar, CS::Root> {
        let line = Location::caller().line();
        let sequence = self.sequence;
        self.sequence += 1;
        self.cs
            .namespace(move || format!("{operation} #{sequence} (line {line})"))
    }

    /// Opens a labelled child constraint system for one sub-relation.
    #[track_caller]
    pub(crate) fn scope(&mut self, label: &'static str) -> Namespace<'_, Scalar, CS::Root> {
        self.at(label)
    }

    // Scalars modulo the secp256k1 group order.

    /// A relation constant. It is part of the circuit shape, not a witness.
    pub(crate) fn constant(&self, value: u64) -> Result<CanonicalScalar> {
        constant_u64::<CS::Root>(value)
    }

    /// A relation constant. It is part of the circuit shape, not a witness.
    pub(crate) fn constant_scalar(&self, value: SecpScalarWitness) -> Result<CanonicalScalar> {
        constant_scalar::<CS::Root>(value)
    }

    /// Allocates one witness scalar with its `< n` proof.
    #[track_caller]
    pub(crate) fn scalar(&mut self, witness: SecpScalarWitness) -> Result<CanonicalScalar> {
        allocate_canonical_scalar(self.at("scalar"), witness)
    }

    /// Constrains `value` to be zero.
    #[track_caller]
    pub(crate) fn require_zero(&mut self, value: &CanonicalScalar) {
        let embedded = value.embedded();
        self.at("zero")
            .enforce(|| "zero scalar", |_| embedded, |lc| lc + CS::one(), |lc| lc);
    }

    #[track_caller]
    pub(crate) fn add(
        &mut self,
        left: &CanonicalScalar,
        right: &CanonicalScalar,
    ) -> Result<CanonicalScalar> {
        add_scalars(self.at("add"), left, right)
    }

    #[track_caller]
    pub(crate) fn sub(
        &mut self,
        left: &CanonicalScalar,
        right: &CanonicalScalar,
    ) -> Result<CanonicalScalar> {
        subtract_scalars(self.at("sub"), left, right)
    }

    #[track_caller]
    pub(crate) fn mul(
        &mut self,
        left: &CanonicalScalar,
        right: &CanonicalScalar,
    ) -> Result<CanonicalScalar> {
        multiply_scalars(self.at("mul"), left, right)
    }

    #[track_caller]
    pub(crate) fn square(&mut self, value: &CanonicalScalar) -> Result<CanonicalScalar> {
        multiply_scalars(self.at("square"), value, value)
    }

    /// Allocates the inverse, which also proves `value` is nonzero.
    #[track_caller]
    pub(crate) fn invert(&mut self, value: &CanonicalScalar) -> Result<CanonicalScalar> {
        invert_scalar(self.at("invert"), value)
    }

    /// Proves `value` is nonzero by exhibiting its inverse.
    #[track_caller]
    pub(crate) fn require_nonzero(&mut self, value: &CanonicalScalar) -> Result<()> {
        invert_scalar(self.at("nonzero"), value).map(drop)
    }

    // secp256k1 points.

    /// Allocates one witness point with its curve, identity and encoding
    /// constraints.
    #[track_caller]
    pub(crate) fn point(&mut self, witness: SecpEncodedPointWitness) -> Result<EncodedPoint> {
        allocate_encoded_point(self.at("point"), witness)
    }

    /// A relation constant. It is part of the circuit shape, not a witness.
    #[track_caller]
    pub(crate) fn constant_point(&mut self, value: PointValue) -> Result<Point> {
        allocate_constant_point(self.at("constant point"), value)
    }

    /// Constrains the canonical encoding of a computed point.
    #[track_caller]
    pub(crate) fn encode(&mut self, point: Point) -> Result<EncodedPoint> {
        encode_computed_point(self.at("encode"), point)
    }

    #[track_caller]
    pub(crate) fn add_points(&mut self, left: &Point, right: &Point) -> Result<Point> {
        add_points(self.at("point add"), left, right)
    }

    /// Scalar multiplication over the scalar's own canonical bits.
    #[track_caller]
    pub(crate) fn scale(&mut self, point: &Point, scalar: &CanonicalScalar) -> Result<Point> {
        let mut cs = self.at("scale");
        let bits = scalar.allocated_bits_le(cs.namespace(|| "scalar bits"))?;
        scale_point(cs.namespace(|| "scalar multiplication"), point, &bits)
    }

    /// `sum + scalar * point`.
    #[track_caller]
    pub(crate) fn add_scaled(
        &mut self,
        sum: &Point,
        point: &Point,
        scalar: &CanonicalScalar,
    ) -> Result<Point> {
        let term = self.scale(point, scalar)?;
        self.add_points(sum, &term)
    }

    #[track_caller]
    pub(crate) fn require_finite(&mut self, point: &Point) -> Result<()> {
        Boolean::enforce_equal(
            self.at("finite"),
            &point.is_identity(),
            &Boolean::constant(false),
        )
    }

    #[track_caller]
    pub(crate) fn require_identity(&mut self, point: &Point) -> Result<()> {
        Boolean::enforce_equal(
            self.at("identity"),
            &point.is_identity(),
            &Boolean::constant(true),
        )
    }

    #[track_caller]
    pub(crate) fn require_even(&mut self, point: &EncodedPoint) -> Result<()> {
        Boolean::enforce_equal(self.at("even"), point.odd(), &Boolean::constant(false))
    }

    #[track_caller]
    pub(crate) fn require_equal_points(&mut self, left: &Point, right: &Point) -> Result<()> {
        left.enforce_equal(self.at("point equality"), right)
    }

    // Typed transcript.

    /// Allocates witness bytes, in order.
    #[track_caller]
    pub(crate) fn bytes<const N: usize>(&mut self, value: [u8; N]) -> Result<[Byte; N]> {
        let mut cs = self.at("bytes");
        let mut bytes = Vec::with_capacity(N);
        for (index, byte) in value.into_iter().enumerate() {
            bytes.push(Byte::allocate(
                cs.namespace(|| format!("byte {index}")),
                byte,
            )?);
        }
        Ok(bytes
            .try_into()
            .expect("one constrained byte per input byte"))
    }

    /// Hashes the pending transcript items into one nonzero challenge.
    #[track_caller]
    pub(crate) fn challenge(
        &mut self,
        transcript: &mut Transcript,
        round: u64,
    ) -> Result<CanonicalScalar> {
        challenge(self.at("challenge"), transcript, round)
    }
}
