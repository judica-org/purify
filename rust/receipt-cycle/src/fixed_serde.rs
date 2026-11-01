//! Restricted fixed-shape Serde transport for recursive proof objects.
//!
//! Dynamic sequence lengths are supplied by the locally selected proof suite,
//! never by untrusted bytes. The transport deliberately supports only the
//! Serde forms used by fixed-shape Nova proofs.
//!
//! These broad limits are defense-in-depth bounds for the codec itself. They
//! do not define an accepted receipt shape. Each production proof suite must
//! select one exact encoded length and sequence schedule locally. Empty
//! sequences are excluded because Nova's polynomial code assumes nonempty
//! inputs in paths that are reachable after deserialization.

use std::{cmp::max, fmt, iter};

use serde::{
    de::{self, DeserializeOwned, DeserializeSeed, SeqAccess, Visitor},
    ser::{self, Impossible, SerializeSeq, SerializeStruct, SerializeTuple, SerializeTupleStruct},
    Serialize,
};
use thiserror::Error;

const MAX_CANONICAL_BYTES: usize = 1 << 20;
const MAX_SEQUENCE_COUNT: usize = 1 << 10;
const MAX_SEQUENCE_LENGTH: usize = 1 << 12;
const MAX_TOTAL_SEQUENCE_ELEMENTS: usize = 1 << 14;

const NOVA_PUBLIC_IO_ARITY: usize = 2;
const NOVA_IPA_MAX_ROUNDS: usize = 32;
// Twelve top-level commitments and forty fixed scalars, including both
// Spartan proofs. Round-dependent bytes are accounted for separately.
const NOVA_COMPRESSED_FIXED_BYTES: usize = 1_676;
const NOVA_STATE_SCALAR_BYTES: usize = 32;
const NOVA_OUTER_ROUND_BYTES: usize = 96;
const NOVA_INNER_ROUND_BYTES: usize = 64;
const NOVA_BATCH_AND_IPA_ROUND_BYTES: usize = 130;
// Five R1CS instance X vectors and the final-state vector.
const NOVA_COMPRESSED_WRAPPER_SEQUENCE_COUNT: usize = 6;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum FixedSerdeError {
    #[error("fixed Serde shape exceeds its resource bound")]
    InvalidShape,
    #[error("fixed Serde encoded length mismatch")]
    EncodedLength,
    #[error("fixed Serde sequence schedule is exhausted")]
    ScheduleExhausted,
    #[error("fixed Serde sequence schedule was not fully consumed")]
    ScheduleRemaining,
    #[error("fixed Serde sequence length mismatch")]
    SequenceLength,
    #[error("fixed Serde compound length mismatch")]
    CompoundLength,
    #[error("fixed Serde input ended early")]
    UnexpectedEnd,
    #[error("fixed Serde input has trailing bytes")]
    TrailingBytes,
    #[error("fixed Serde encoding is noncanonical")]
    NonCanonical,
    #[error("unsupported fixed Serde form: {0}")]
    Unsupported(&'static str),
    #[error("fixed Serde value rejected: {0}")]
    Value(String),
}

impl ser::Error for FixedSerdeError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Value(message.to_string())
    }
}

impl de::Error for FixedSerdeError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Value(message.to_string())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FixedSerdeShape<'a> {
    encoded_len: usize,
    sequence_lengths: &'a [usize],
}

impl<'a> FixedSerdeShape<'a> {
    pub(crate) fn new(
        encoded_len: usize,
        sequence_lengths: &'a [usize],
    ) -> Result<Self, FixedSerdeError> {
        if encoded_len > MAX_CANONICAL_BYTES || sequence_lengths.len() > MAX_SEQUENCE_COUNT {
            return Err(FixedSerdeError::InvalidShape);
        }
        let mut total = 0usize;
        for &length in sequence_lengths {
            if length == 0 || length > MAX_SEQUENCE_LENGTH {
                return Err(FixedSerdeError::InvalidShape);
            }
            total = total
                .checked_add(length)
                .ok_or(FixedSerdeError::InvalidShape)?;
        }
        if total > MAX_TOTAL_SEQUENCE_ELEMENTS {
            return Err(FixedSerdeError::InvalidShape);
        }
        Ok(Self {
            encoded_len,
            sequence_lengths,
        })
    }

    pub(crate) fn encode<T: Serialize>(&self, value: &T) -> Result<Vec<u8>, FixedSerdeError> {
        let mut encoder = Encoder {
            output: Vec::with_capacity(self.encoded_len),
            output_limit: self.encoded_len,
            schedule: self.sequence_lengths,
            schedule_index: 0,
        };
        value.serialize(&mut encoder)?;
        if encoder.schedule_index != encoder.schedule.len() {
            return Err(FixedSerdeError::ScheduleRemaining);
        }
        if encoder.output.len() != self.encoded_len {
            return Err(FixedSerdeError::EncodedLength);
        }
        Ok(encoder.output)
    }

    pub(crate) fn decode_canonical<T>(&self, encoded: &[u8]) -> Result<T, FixedSerdeError>
    where
        T: DeserializeOwned + Serialize,
    {
        if encoded.len() != self.encoded_len {
            return Err(FixedSerdeError::EncodedLength);
        }
        let mut decoder = Decoder {
            input: encoded,
            position: 0,
            schedule: self.sequence_lengths,
            schedule_index: 0,
        };
        let value = T::deserialize(&mut decoder)?;
        if decoder.schedule_index != decoder.schedule.len() {
            return Err(FixedSerdeError::ScheduleRemaining);
        }
        if decoder.position != decoder.input.len() {
            return Err(FixedSerdeError::TrailingBytes);
        }
        if self.encode(&value)? != encoded {
            return Err(FixedSerdeError::NonCanonical);
        }
        Ok(value)
    }
}

/// Raw dimensions of one immutable Nova suite R1CS shape.
///
/// These values must come from locally selected `PublicParams`, never from a
/// proof, receipt, or peer-selected descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NovaR1csDimensions {
    num_constraints: usize,
    num_variables: usize,
}

impl NovaR1csDimensions {
    pub(crate) const fn new(num_constraints: usize, num_variables: usize) -> Self {
        Self {
            num_constraints,
            num_variables,
        }
    }

    fn spartan_rounds(self) -> Result<NovaSpartanRounds, FixedSerdeError> {
        if self.num_constraints == 0 || self.num_variables == 0 {
            return Err(FixedSerdeError::InvalidShape);
        }

        // This is Nova 0.76 R1CSShape::pad. In particular, an already regular
        // shape is not made square when its two dimensions are unequal powers
        // of two. All other shapes are padded to one common power of two.
        let already_regular = self.num_constraints.is_power_of_two()
            && self.num_variables.is_power_of_two()
            && NOVA_PUBLIC_IO_ARITY < self.num_variables;
        let (padded_constraints, padded_variables) = if already_regular {
            (self.num_constraints, self.num_variables)
        } else {
            let padded = max(
                max(self.num_constraints, self.num_variables),
                NOVA_PUBLIC_IO_ARITY,
            )
            .checked_next_power_of_two()
            .ok_or(FixedSerdeError::InvalidShape)?;
            (padded, padded)
        };

        if padded_constraints == 0
            || padded_variables == 0
            || !padded_constraints.is_power_of_two()
            || !padded_variables.is_power_of_two()
            || NOVA_PUBLIC_IO_ARITY >= padded_variables
        {
            return Err(FixedSerdeError::InvalidShape);
        }

        let constraint_rounds = padded_constraints.ilog2() as usize;
        let variable_rounds = padded_variables.ilog2() as usize;
        let batch_rounds = max(constraint_rounds, variable_rounds);
        if constraint_rounds == 0 || variable_rounds == 0 || batch_rounds >= NOVA_IPA_MAX_ROUNDS {
            return Err(FixedSerdeError::InvalidShape);
        }

        Ok(NovaSpartanRounds {
            constraint_rounds,
            variable_rounds,
            batch_rounds,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NovaSpartanRounds {
    constraint_rounds: usize,
    variable_rounds: usize,
    batch_rounds: usize,
}

impl NovaSpartanRounds {
    fn encoded_round_bytes(self) -> Result<usize, FixedSerdeError> {
        self.constraint_rounds
            .checked_mul(NOVA_OUTER_ROUND_BYTES)
            .and_then(|bytes| {
                self.variable_rounds
                    .checked_mul(NOVA_INNER_ROUND_BYTES)
                    .and_then(|inner| bytes.checked_add(inner))
            })
            .and_then(|bytes| {
                self.batch_rounds
                    .checked_mul(NOVA_BATCH_AND_IPA_ROUND_BYTES)
                    .and_then(|batch| bytes.checked_add(batch))
            })
            .ok_or(FixedSerdeError::InvalidShape)
    }

    fn sequence_count(self) -> Result<usize, FixedSerdeError> {
        self.constraint_rounds
            .checked_add(self.variable_rounds)
            .and_then(|count| count.checked_add(self.batch_rounds))
            .and_then(|count| count.checked_add(7))
            .ok_or(FixedSerdeError::InvalidShape)
    }

    fn append_schedule(self, schedule: &mut Vec<usize>) {
        schedule.push(self.constraint_rounds);
        schedule.extend(iter::repeat_n(3, self.constraint_rounds));

        schedule.push(self.variable_rounds + 1);
        schedule.extend(iter::repeat_n(2, self.variable_rounds + 1));

        schedule.push(self.batch_rounds);
        schedule.extend(iter::repeat_n(2, self.batch_rounds));

        schedule.push(2);
        schedule.push(self.batch_rounds);
        schedule.push(self.batch_rounds);
    }
}

/// Fixed transport shape for non-EVM Nova 0.76 compressed Spartan IPA proofs.
///
/// The owned schedule is derived only from immutable local suite dimensions
/// and the suite's fixed final-state arity. It is not an acceptance API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NovaCompressedProofShape {
    encoded_len: usize,
    sequence_lengths: Vec<usize>,
}

impl NovaCompressedProofShape {
    pub(crate) fn from_suite_dimensions(
        primary: NovaR1csDimensions,
        secondary: NovaR1csDimensions,
        final_state_arity: usize,
    ) -> Result<Self, FixedSerdeError> {
        if final_state_arity == 0 {
            return Err(FixedSerdeError::InvalidShape);
        }

        let primary = primary.spartan_rounds()?;
        let secondary = secondary.spartan_rounds()?;
        let state_bytes = final_state_arity
            .checked_mul(NOVA_STATE_SCALAR_BYTES)
            .ok_or(FixedSerdeError::InvalidShape)?;
        let primary_round_bytes = primary.encoded_round_bytes()?;
        let secondary_round_bytes = secondary.encoded_round_bytes()?;
        let encoded_len = NOVA_COMPRESSED_FIXED_BYTES
            .checked_add(state_bytes)
            .and_then(|bytes| bytes.checked_add(primary_round_bytes))
            .and_then(|bytes| bytes.checked_add(secondary_round_bytes))
            .ok_or(FixedSerdeError::InvalidShape)?;

        let primary_sequence_count = primary.sequence_count()?;
        let secondary_sequence_count = secondary.sequence_count()?;
        let sequence_count = NOVA_COMPRESSED_WRAPPER_SEQUENCE_COUNT
            .checked_add(primary_sequence_count)
            .and_then(|count| count.checked_add(secondary_sequence_count))
            .ok_or(FixedSerdeError::InvalidShape)?;
        let mut sequence_lengths = Vec::with_capacity(sequence_count);
        sequence_lengths.extend_from_slice(&[2; 5]);
        primary.append_schedule(&mut sequence_lengths);
        secondary.append_schedule(&mut sequence_lengths);
        sequence_lengths.push(final_state_arity);
        if sequence_lengths.len() != sequence_count {
            return Err(FixedSerdeError::InvalidShape);
        }

        FixedSerdeShape::new(encoded_len, &sequence_lengths)?;
        Ok(Self {
            encoded_len,
            sequence_lengths,
        })
    }

    pub(crate) fn as_fixed_serde_shape(&self) -> FixedSerdeShape<'_> {
        // Construction validated both fields together and neither is mutable.
        FixedSerdeShape {
            encoded_len: self.encoded_len,
            sequence_lengths: &self.sequence_lengths,
        }
    }
}

struct Encoder<'a> {
    output: Vec<u8>,
    output_limit: usize,
    schedule: &'a [usize],
    schedule_index: usize,
}

impl<'shape> Encoder<'shape> {
    fn next_sequence_length(&mut self) -> Result<usize, FixedSerdeError> {
        let length = self
            .schedule
            .get(self.schedule_index)
            .copied()
            .ok_or(FixedSerdeError::ScheduleExhausted)?;
        self.schedule_index += 1;
        Ok(length)
    }

    fn compound(&mut self, length: usize) -> Result<Compound<'_, 'shape>, FixedSerdeError> {
        if length > MAX_SEQUENCE_LENGTH {
            return Err(FixedSerdeError::InvalidShape);
        }
        Ok(Compound {
            encoder: self,
            remaining: length,
        })
    }
}

struct Compound<'encoder, 'shape> {
    encoder: &'encoder mut Encoder<'shape>,
    remaining: usize,
}

impl Compound<'_, '_> {
    fn element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), FixedSerdeError> {
        if self.remaining == 0 {
            return Err(FixedSerdeError::CompoundLength);
        }
        value.serialize(&mut *self.encoder)?;
        self.remaining -= 1;
        Ok(())
    }

    fn finish(self) -> Result<(), FixedSerdeError> {
        if self.remaining != 0 {
            return Err(FixedSerdeError::CompoundLength);
        }
        Ok(())
    }
}

impl SerializeSeq for Compound<'_, '_> {
    type Ok = ();
    type Error = FixedSerdeError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.element(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

impl SerializeTuple for Compound<'_, '_> {
    type Ok = ();
    type Error = FixedSerdeError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.element(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

impl SerializeTupleStruct for Compound<'_, '_> {
    type Ok = ();
    type Error = FixedSerdeError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.element(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

impl SerializeStruct for Compound<'_, '_> {
    type Ok = ();
    type Error = FixedSerdeError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.element(value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.finish()
    }
}

impl<'encoder, 'shape> ser::Serializer for &'encoder mut Encoder<'shape> {
    type Ok = ();
    type Error = FixedSerdeError;
    type SerializeSeq = Compound<'encoder, 'shape>;
    type SerializeTuple = Compound<'encoder, 'shape>;
    type SerializeTupleStruct = Compound<'encoder, 'shape>;
    type SerializeTupleVariant = Impossible<(), FixedSerdeError>;
    type SerializeMap = Impossible<(), FixedSerdeError>;
    type SerializeStruct = Compound<'encoder, 'shape>;
    type SerializeStructVariant = Impossible<(), FixedSerdeError>;

    fn serialize_u8(self, value: u8) -> Result<Self::Ok, Self::Error> {
        if self.output.len() == self.output_limit {
            return Err(FixedSerdeError::EncodedLength);
        }
        self.output.push(value);
        Ok(())
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        let actual = len.ok_or(FixedSerdeError::SequenceLength)?;
        let expected = self.next_sequence_length()?;
        if actual != expected {
            return Err(FixedSerdeError::SequenceLength);
        }
        self.compound(expected)
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.compound(len)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.compound(len)
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.compound(len)
    }

    fn serialize_bool(self, _value: bool) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("bool"))
    }

    fn serialize_i8(self, _value: i8) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("i8"))
    }

    fn serialize_i16(self, _value: i16) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("i16"))
    }

    fn serialize_i32(self, _value: i32) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("i32"))
    }

    fn serialize_i64(self, _value: i64) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("i64"))
    }

    fn serialize_i128(self, _value: i128) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("i128"))
    }

    fn serialize_u16(self, _value: u16) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("u16"))
    }

    fn serialize_u32(self, _value: u32) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("u32"))
    }

    fn serialize_u64(self, _value: u64) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("u64"))
    }

    fn serialize_u128(self, _value: u128) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("u128"))
    }

    fn serialize_f32(self, _value: f32) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("f32"))
    }

    fn serialize_f64(self, _value: f64) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("f64"))
    }

    fn serialize_char(self, _value: char) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("char"))
    }

    fn serialize_str(self, _value: &str) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("str"))
    }

    fn serialize_bytes(self, _value: &[u8]) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("bytes"))
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("option"))
    }

    fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("option"))
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("enum"))
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("enum"))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(FixedSerdeError::Unsupported("enum"))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(FixedSerdeError::Unsupported("map"))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(FixedSerdeError::Unsupported("enum"))
    }

    fn collect_str<T: ?Sized + fmt::Display>(self, _value: &T) -> Result<Self::Ok, Self::Error> {
        Err(FixedSerdeError::Unsupported("display"))
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

struct Decoder<'input, 'shape> {
    input: &'input [u8],
    position: usize,
    schedule: &'shape [usize],
    schedule_index: usize,
}

impl<'input, 'shape> Decoder<'input, 'shape> {
    fn next_sequence_length(&mut self) -> Result<usize, FixedSerdeError> {
        let length = self
            .schedule
            .get(self.schedule_index)
            .copied()
            .ok_or(FixedSerdeError::ScheduleExhausted)?;
        self.schedule_index += 1;
        Ok(length)
    }

    fn read_u8(&mut self) -> Result<u8, FixedSerdeError> {
        let value = self
            .input
            .get(self.position)
            .copied()
            .ok_or(FixedSerdeError::UnexpectedEnd)?;
        self.position += 1;
        Ok(value)
    }

    fn visit_sequence<V>(&mut self, length: usize, visitor: V) -> Result<V::Value, FixedSerdeError>
    where
        V: Visitor<'input>,
    {
        if length > MAX_SEQUENCE_LENGTH {
            return Err(FixedSerdeError::InvalidShape);
        }
        let mut access = FixedSeqAccess {
            decoder: self,
            remaining: length,
        };
        let value = visitor.visit_seq(&mut access)?;
        if access.remaining != 0 {
            return Err(FixedSerdeError::CompoundLength);
        }
        Ok(value)
    }
}

struct FixedSeqAccess<'decoder, 'input, 'shape> {
    decoder: &'decoder mut Decoder<'input, 'shape>,
    remaining: usize,
}

impl<'de> SeqAccess<'de> for &mut FixedSeqAccess<'_, 'de, '_> {
    type Error = FixedSerdeError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        if self.remaining == 0 {
            return Ok(None);
        }
        let value = seed.deserialize(&mut *self.decoder)?;
        self.remaining -= 1;
        Ok(Some(value))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

impl<'de> de::Deserializer<'de> for &mut Decoder<'de, '_> {
    type Error = FixedSerdeError;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(FixedSerdeError::Unsupported("dynamic value"))
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(self.read_u8()?)
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let length = self.next_sequence_length()?;
        self.visit_sequence(length, visitor)
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.visit_sequence(len, visitor)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.visit_sequence(len, visitor)
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.visit_sequence(fields.len(), visitor)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u16 u32 u64 u128 f32 f64 char str
        string bytes byte_buf option map enum identifier ignored_any
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt, marker::PhantomData};

    use ff::Field;
    use nova_snark::provider::{
        secp_secq::{secp256k1, secq256k1},
        traits::DlogGroup,
    };
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct NestedFixture {
        prefix: [u8; 2],
        values: Vec<Vec<u8>>,
        marker: PhantomData<u8>,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct SecpLeaves {
        scalar: secp256k1::Scalar,
        point: secp256k1::Point,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct SecqLeaves {
        scalar: secq256k1::Scalar,
        point: secq256k1::Point,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Normalized(u8);

    #[derive(Debug)]
    struct UnknownLengthSequence;

    impl Serialize for UnknownLengthSequence {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_seq(None)?.end()
        }
    }

    #[derive(Debug)]
    struct ShortTuple;

    impl Serialize for ShortTuple {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_tuple(1)?.end()
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct OversizedTuple;

    impl Serialize for OversizedTuple {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_tuple(MAX_SEQUENCE_LENGTH + 1)?.end()
        }
    }

    impl<'de> Deserialize<'de> for OversizedTuple {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct OversizedVisitor;

            impl<'de> Visitor<'de> for OversizedVisitor {
                type Value = OversizedTuple;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("an oversized tuple")
                }

                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    _sequence: A,
                ) -> Result<Self::Value, A::Error> {
                    Ok(OversizedTuple)
                }
            }

            deserializer.deserialize_tuple(MAX_SEQUENCE_LENGTH + 1, OversizedVisitor)
        }
    }

    impl Serialize for Normalized {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_u8(self.0)
        }
    }

    impl<'de> Deserialize<'de> for Normalized {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Ok(Self(u8::deserialize(deserializer)? & 1))
        }
    }

    #[test]
    fn nested_sequences_omit_lengths_and_round_trip() {
        let shape = FixedSerdeShape::new(7, &[2, 3, 2]).expect("shape");
        let fixture = NestedFixture {
            prefix: [0xa1, 0xa2],
            values: vec![vec![1, 2, 3], vec![4, 5]],
            marker: PhantomData,
        };
        let encoded = shape.encode(&fixture).expect("encode");
        assert_eq!(encoded, [0xa1, 0xa2, 1, 2, 3, 4, 5]);
        assert_eq!(
            shape
                .decode_canonical::<NestedFixture>(&encoded)
                .expect("decode"),
            fixture
        );
    }

    #[test]
    fn exact_schedule_is_mandatory() {
        let fixture = vec![vec![1u8, 2]];
        let wrong_outer = FixedSerdeShape::new(2, &[2, 2]).expect("shape");
        assert_eq!(
            wrong_outer.encode(&fixture),
            Err(FixedSerdeError::SequenceLength)
        );

        let exhausted = FixedSerdeShape::new(2, &[1]).expect("shape");
        assert_eq!(
            exhausted.encode(&fixture),
            Err(FixedSerdeError::ScheduleExhausted)
        );

        let remaining = FixedSerdeShape::new(2, &[1, 2, 1]).expect("shape");
        assert_eq!(
            remaining.encode(&fixture),
            Err(FixedSerdeError::ScheduleRemaining)
        );
    }

    #[test]
    fn wire_bytes_cannot_select_allocation_lengths() {
        let shape = FixedSerdeShape::new(8, &[1]).expect("shape");
        assert_eq!(
            shape.decode_canonical::<Vec<u8>>(&[0xff; 8]),
            Err(FixedSerdeError::TrailingBytes)
        );
    }

    #[test]
    fn malformed_compounds_and_output_overflow_reject_early() {
        let empty = FixedSerdeShape::new(0, &[]).expect("shape");
        assert_eq!(
            empty.encode(&ShortTuple),
            Err(FixedSerdeError::CompoundLength)
        );
        assert_eq!(
            empty.encode(&OversizedTuple),
            Err(FixedSerdeError::InvalidShape)
        );
        assert_eq!(
            empty.decode_canonical::<OversizedTuple>(&[]),
            Err(FixedSerdeError::InvalidShape)
        );

        let one_byte = FixedSerdeShape::new(1, &[2]).expect("shape");
        assert_eq!(
            one_byte.encode(&vec![1u8, 2]),
            Err(FixedSerdeError::EncodedLength)
        );
        let truncated_tuple = FixedSerdeShape::new(1, &[]).expect("shape");
        assert_eq!(
            truncated_tuple.decode_canonical::<[u8; 2]>(&[1]),
            Err(FixedSerdeError::UnexpectedEnd)
        );
    }

    #[test]
    fn encoded_length_and_schedule_bounds_reject_early() {
        assert!(FixedSerdeShape::new(MAX_CANONICAL_BYTES, &[]).is_ok());
        assert_eq!(
            FixedSerdeShape::new(MAX_CANONICAL_BYTES + 1, &[]),
            Err(FixedSerdeError::InvalidShape)
        );
        assert_eq!(
            FixedSerdeShape::new(1, &[0]),
            Err(FixedSerdeError::InvalidShape)
        );
        assert_eq!(
            FixedSerdeShape::new(1, &[MAX_SEQUENCE_LENGTH + 1]),
            Err(FixedSerdeError::InvalidShape)
        );
        assert!(FixedSerdeShape::new(1, &[MAX_SEQUENCE_LENGTH]).is_ok());
        let maximum_count = vec![1; MAX_SEQUENCE_COUNT];
        assert!(FixedSerdeShape::new(1, &maximum_count).is_ok());
        let too_many = vec![1; MAX_SEQUENCE_COUNT + 1];
        assert_eq!(
            FixedSerdeShape::new(1, &too_many),
            Err(FixedSerdeError::InvalidShape)
        );
        let too_many_elements =
            vec![MAX_SEQUENCE_LENGTH; MAX_TOTAL_SEQUENCE_ELEMENTS / MAX_SEQUENCE_LENGTH + 1];
        assert!(FixedSerdeShape::new(1, &too_many_elements[..too_many_elements.len() - 1]).is_ok());
        assert_eq!(
            FixedSerdeShape::new(1, &too_many_elements),
            Err(FixedSerdeError::InvalidShape)
        );

        let shape = FixedSerdeShape::new(1, &[]).expect("shape");
        assert_eq!(
            shape.decode_canonical::<u8>(&[]),
            Err(FixedSerdeError::EncodedLength)
        );
        assert_eq!(
            shape.decode_canonical::<u8>(&[1, 2]),
            Err(FixedSerdeError::EncodedLength)
        );
    }

    #[test]
    fn unsupported_forms_reject() {
        let shape = FixedSerdeShape::new(1, &[]).expect("shape");
        assert_eq!(
            shape.encode(&true),
            Err(FixedSerdeError::Unsupported("bool"))
        );
        assert_eq!(
            shape.decode_canonical::<bool>(&[1]),
            Err(FixedSerdeError::Unsupported("dynamic value"))
        );

        let sequence_shape = FixedSerdeShape::new(0, &[1]).expect("shape");
        assert_eq!(
            sequence_shape.encode(&UnknownLengthSequence),
            Err(FixedSerdeError::SequenceLength)
        );
    }

    #[test]
    fn decode_requires_canonical_reencoding() {
        let shape = FixedSerdeShape::new(1, &[]).expect("shape");
        assert_eq!(
            shape.decode_canonical::<Normalized>(&[2]),
            Err(FixedSerdeError::NonCanonical)
        );
        assert_eq!(
            shape.decode_canonical::<Normalized>(&[1]),
            Ok(Normalized(1))
        );
    }

    #[test]
    fn secp_and_secq_leaves_use_canonical_fixed_bytes() {
        let shape = FixedSerdeShape::new(65, &[]).expect("shape");
        let secp = SecpLeaves {
            scalar: secp256k1::Scalar::ONE,
            point: secp256k1::Point::zero(),
        };
        let secp_encoded = shape.encode(&secp).expect("secp encode");
        assert_eq!(secp_encoded[0], 1);
        assert!(secp_encoded[1..32].iter().all(|byte| *byte == 0));
        assert_eq!(secp_encoded[32], 0x40);
        assert!(secp_encoded[33..].iter().all(|byte| *byte == 0));
        assert_eq!(
            shape
                .decode_canonical::<SecpLeaves>(&secp_encoded)
                .expect("secp decode"),
            secp
        );

        let secq = SecqLeaves {
            scalar: secq256k1::Scalar::ONE,
            point: secq256k1::Point::zero(),
        };
        let secq_encoded = shape.encode(&secq).expect("secq encode");
        assert_eq!(secq_encoded[0], 1);
        assert!(secq_encoded[1..32].iter().all(|byte| *byte == 0));
        assert_eq!(secq_encoded[32], 0x40);
        assert!(secq_encoded[33..].iter().all(|byte| *byte == 0));
        assert_eq!(
            shape
                .decode_canonical::<SecqLeaves>(&secq_encoded)
                .expect("secq decode"),
            secq
        );
    }

    #[test]
    fn noncanonical_curve_leaves_reject_before_verification() {
        let shape = FixedSerdeShape::new(65, &[]).expect("shape");
        let fixture = SecpLeaves {
            scalar: secp256k1::Scalar::ONE,
            point: secp256k1::Point::zero(),
        };
        let mut noncanonical_scalar = shape.encode(&fixture).expect("encode");
        noncanonical_scalar[..32].fill(0xff);
        assert!(matches!(
            shape.decode_canonical::<SecpLeaves>(&noncanonical_scalar),
            Err(FixedSerdeError::Value(_))
        ));

        let mut malformed_point = shape.encode(&fixture).expect("encode");
        malformed_point[32] = 0x01;
        assert!(matches!(
            shape.decode_canonical::<SecpLeaves>(&malformed_point),
            Err(FixedSerdeError::Value(_))
        ));

        let secq = SecqLeaves {
            scalar: secq256k1::Scalar::ONE,
            point: secq256k1::Point::zero(),
        };
        let mut noncanonical_secq = shape.encode(&secq).expect("encode");
        noncanonical_secq[..32].fill(0xff);
        assert!(matches!(
            shape.decode_canonical::<SecqLeaves>(&noncanonical_secq),
            Err(FixedSerdeError::Value(_))
        ));
    }

    #[test]
    fn nova_shape_preserves_unequal_rounds_and_exact_schedule_order() {
        let shape = NovaCompressedProofShape::from_suite_dimensions(
            NovaR1csDimensions::new(4, 16),
            NovaR1csDimensions::new(5, 9),
            7,
        )
        .expect("Nova shape");
        let mut expected = vec![2; 5];
        // Primary: qc=2, qv=4, qb=4.
        expected.extend_from_slice(&[2, 3, 3, 5, 2, 2, 2, 2, 2, 4, 2, 2, 2, 2, 2, 4, 4]);
        // Secondary is square-padded to qc=qv=qb=4.
        expected.extend_from_slice(&[4, 3, 3, 3, 3, 5, 2, 2, 2, 2, 2, 4, 2, 2, 2, 2, 2, 4, 4]);
        expected.push(7);

        assert_eq!(shape.encoded_len, 4_028);
        assert_eq!(shape.sequence_lengths, expected);
        assert_eq!(shape.sequence_lengths.len(), 42);
        assert_eq!(shape.sequence_lengths.iter().sum::<usize>(), 115);
        assert_eq!(
            shape.as_fixed_serde_shape(),
            FixedSerdeShape::new(4_028, &expected).expect("fixed shape")
        );
    }

    #[test]
    fn nova_shape_matches_known_square_probe_formula() {
        let primary = NovaR1csDimensions::new(10_442, 10_434);
        let secondary = NovaR1csDimensions::new(10_787, 10_769);
        let one_field = NovaCompressedProofShape::from_suite_dimensions(primary, secondary, 1)
            .expect("one-field shape");
        assert_eq!(one_field.encoded_len, 9_828);
        assert_eq!(one_field.sequence_lengths.len(), 104);
        assert_eq!(one_field.sequence_lengths.iter().sum::<usize>(), 357);

        let production = NovaCompressedProofShape::from_suite_dimensions(primary, secondary, 20)
            .expect("production shape");
        assert_eq!(production.encoded_len, 10_436);
        assert_eq!(production.sequence_lengths.len(), 104);
        assert_eq!(production.sequence_lengths.last(), Some(&20));
    }

    #[test]
    fn nova_padding_preserves_only_already_regular_dimensions() {
        assert_eq!(
            NovaR1csDimensions::new(4, 16).spartan_rounds(),
            Ok(NovaSpartanRounds {
                constraint_rounds: 2,
                variable_rounds: 4,
                batch_rounds: 4,
            })
        );
        assert_eq!(
            NovaR1csDimensions::new(5, 16).spartan_rounds(),
            Ok(NovaSpartanRounds {
                constraint_rounds: 4,
                variable_rounds: 4,
                batch_rounds: 4,
            })
        );
        assert_eq!(
            NovaR1csDimensions::new(16, 4).spartan_rounds(),
            Ok(NovaSpartanRounds {
                constraint_rounds: 4,
                variable_rounds: 2,
                batch_rounds: 4,
            })
        );
    }

    #[test]
    fn nova_shape_rejects_empty_overflowing_and_oversized_dimensions() {
        let small = NovaR1csDimensions::new(4, 4);
        assert_eq!(
            NovaCompressedProofShape::from_suite_dimensions(small, small, 0),
            Err(FixedSerdeError::InvalidShape)
        );
        assert_eq!(
            NovaR1csDimensions::new(0, 4).spartan_rounds(),
            Err(FixedSerdeError::InvalidShape)
        );
        assert_eq!(
            NovaR1csDimensions::new(1, 4).spartan_rounds(),
            Err(FixedSerdeError::InvalidShape)
        );
        assert_eq!(
            NovaR1csDimensions::new(2, 2).spartan_rounds(),
            Err(FixedSerdeError::InvalidShape)
        );
        assert_eq!(
            NovaR1csDimensions::new(usize::MAX, usize::MAX).spartan_rounds(),
            Err(FixedSerdeError::InvalidShape)
        );
        assert!(
            NovaCompressedProofShape::from_suite_dimensions(small, small, MAX_SEQUENCE_LENGTH,)
                .is_ok()
        );
        assert_eq!(
            NovaCompressedProofShape::from_suite_dimensions(small, small, MAX_SEQUENCE_LENGTH + 1,),
            Err(FixedSerdeError::InvalidShape)
        );
        assert_eq!(
            NovaCompressedProofShape::from_suite_dimensions(small, small, usize::MAX),
            Err(FixedSerdeError::InvalidShape)
        );

        let maximum_ipa_dimension = 1usize.checked_shl(31).expect("31-bit dimension");
        let maximum_ipa = NovaR1csDimensions::new(maximum_ipa_dimension, maximum_ipa_dimension);
        assert!(
            NovaCompressedProofShape::from_suite_dimensions(maximum_ipa, maximum_ipa, 1).is_ok()
        );
        if let Some(oversized_ipa_dimension) = 1usize.checked_shl(32) {
            let oversized =
                NovaR1csDimensions::new(oversized_ipa_dimension, oversized_ipa_dimension);
            assert_eq!(
                NovaCompressedProofShape::from_suite_dimensions(oversized, small, 1),
                Err(FixedSerdeError::InvalidShape)
            );
        }
    }
}
