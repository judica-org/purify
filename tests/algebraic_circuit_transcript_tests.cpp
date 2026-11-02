// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>

#include "../src/protocol/algebraic_circuit_transcript.hpp"
#include "test_harness.hpp"

namespace {

namespace candidate = purify::bppp::candidate;
using candidate::CircuitCommitmentModeV4;
using candidate::CircuitProofTranscriptInputV4;
using candidate::CircuitTranscriptShapeV4;
using candidate::CoordinateFieldElement;
using candidate::PackedPointPairV4;
using purify::FieldElement;
using purify::UInt256;
using purify::bppp::PointBytes;
using purify_test::expect_error;
using purify_test::expect_ok;
using purify_test::TestContext;

template <std::size_t Size>
std::array<unsigned char, Size> bytes(std::string_view hex) {
  assert(hex.size() == 2 * Size);
  std::array<unsigned char, Size> out{};
  for (std::size_t index = 0; index < Size; ++index) {
    out[index] = static_cast<unsigned char>(
        std::stoul(std::string(hex.substr(2 * index, 2)), nullptr, 16));
  }
  return out;
}

FieldElement scalar(std::string_view hex) {
  auto parsed = FieldElement::try_from_bytes32(bytes<32>(hex));
  assert(parsed.has_value());
  return *parsed;
}

CoordinateFieldElement coordinate(std::string_view hex) {
  auto parsed = CoordinateFieldElement::from_bytes_be(bytes<32>(hex));
  assert(parsed.has_value());
  return *parsed;
}

CoordinateFieldElement point_x(const PointBytes &point) {
  CoordinateFieldElement::Encoding encoded{};
  std::copy(point.begin() + 1, point.end(), encoded.begin());
  auto parsed = CoordinateFieldElement::from_bytes_be(encoded);
  assert(parsed.has_value());
  return *parsed;
}

struct Fixture {
  candidate::TranscriptDigest binding =
      bytes<32>("101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f");
  std::array<PointBytes, 2> public_commitments{
      bytes<33>("0279be667ef9dcbbac55a06295ce870b0"
                "7029bfcdb2dce28d959f2815b16f81798"),
      bytes<33>("02c6047f9441ed7d6d3045406e95c07c"
                "d85c778e4b8cef3ca7abac09b95c709ee5")};
  PointBytes raw_commitment = bytes<33>("02f9308a019258c31049344f85f89d52"
                                        "29b531c845836f99b08601f113bce036f9");
  CircuitProofTranscriptInputV4 proof;

  Fixture() {
    proof.raw_generator_digest = bytes<32>("808182838485868788898a8b8c8d8e8f"
                                           "909192939495969798999a9b9c9d9e9f");
    proof.coefficient_commitment =
        bytes<33>("02e493dbf1c10d80f3581e4904930b14"
                  "04cc6c13900ee0758474fa94abe8c4cd13");
    proof.anchored_offset = bytes<33>("022f8bde4d1a07209355b4a7250a5c51"
                                      "28e88b84bddc619ab7cba8d569b240efe4");
    proof.anchored_commitment = bytes<33>("022f01e5e15cca351daff3843fb70f3c"
                                          "2f0a1bdd05e5af888a67784ef3e10a2a01");
    proof.batched_public_commitment =
        bytes<33>("02f1d29aa67de7035b22059166064240"
                  "b96d70c222e30d0945143d8213b45607f4");
    proof.dlog_nonce = bytes<32>("5cbdf0646e5db4eaa398f365f2ea7a0e"
                                 "3d419b7e0330e39ce92bddedcac4f9bc");
    proof.dlog_response = bytes<32>("00000000000000000000000000000000"
                                    "0000000000000000000000000000000b");
    proof.mask_commitment = bytes<33>("03acd484e2f0c7f65309ad178a9f559a"
                                      "bde09796974c57e714c35f110dfc27ccbe");
    proof.t2 = bytes<32>("00000000000000000000000000000000"
                         "0000000000000000000000000000000d");
    proof.combined_commitment =
        bytes<33>("02bfacb05bbed0375df3c3e4a39357b"
                  "2ee6a781214ca2ed168ac7581e8162bc376");
    proof.rounds = {
        bytes<65>(
            "010000000000000000000000000000000000000000000000000000000000000000"
            "774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb"),
        bytes<65>(
            "02d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a"
            "0000000000000000000000000000000000000000000000000000000000000000"),
        bytes<65>(
            "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8"
            "499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4"),
        bytes<65>(
            "01d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e"
            "e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0"
            "a")};
    proof.terminal_n = bytes<32>("00000000000000000000000000000000"
                                 "00000000000000000000000000000011");
    proof.terminal_l = bytes<32>("00000000000000000000000000000000"
                                 "00000000000000000000000000000013");
  }
};

auto public_shape() {
  return CircuitTranscriptShapeV4::create(CircuitCommitmentModeV4::Public, 8, 2,
                                          16, 16);
}

void check_shared_vector(TestContext &ctx, purify_secp_context *secp) {
  Fixture fixture;
  auto shape = public_shape();
  expect_ok(ctx, shape, "V4 public shape creates");
  if (!shape)
    return;
  auto precommit = candidate::derive_circuit_precommitment_v4(
      *shape, fixture.binding, fixture.public_commitments,
      fixture.raw_commitment, secp);
  expect_ok(ctx, precommit, "V4 precommitment derives");
  if (!precommit)
    return;
  ctx.expect(precommit->lanes ==
                 std::array{coordinate("78732ddaf31c0d8af29b7b778d99540e"
                                       "a1ad10879d1e5a888e2277fdf659cb89"),
                            coordinate("dde7375a1e232b01fc5a3ef2fa8483a1"
                                       "5870df4ba1ba154ad912d37c473f860b")},
             "V4 precommitment lanes match Python");
  ctx.expect(precommit->digest.scalar() ==
                 scalar("78732ddaf31c0d8af29b7b778d99540e"
                        "a1ad10879d1e5a888e2277fdf659cb89"),
             "V4 precommitment digest matches Python");

  auto proof = candidate::derive_circuit_proof_transcript_v4(
      *shape, precommit->digest, fixture.proof, secp);
  expect_ok(ctx, proof, "V4 proof transcript derives");
  if (!proof)
    return;
  const std::array expected{scalar("308428a2dafb211682a3a43ede3fe663"
                                   "3a902bb92bce45ab6717fd45b541b8f6"),
                            scalar("283798065967a1ffdbd08c5b4eba60d3"
                                   "a993f375fa72967901e8c7b103f35a71"),
                            scalar("d741d9247cf66f1fcd5fa6d85144a2b5"
                                   "dcd1edbabcd8a152a9bb9f37385a7e8e"),
                            scalar("155dc3cf87335661393846b5c7bc5e96"
                                   "7fc229dc63d3d6fce0b8200d1e0a9c6f"),
                            scalar("4280602137d49c641fe9b92f8d0c8dd4"
                                   "695a8fee6476a4f41db7a4275703afac"),
                            scalar("ebf1821badaf1e3ab5088a6ce84794a8"
                                   "08b0bc1f4054a2e32e1a0e05df6f05dd"),
                            scalar("df6957cb502f479599b0596b36736147"
                                   "9dcd137741edf69ba17a3dd0367e1a90")};
  const std::array actual{proof->rho.scalar,       proof->mul_scale.scalar,
                          proof->mul_ratio.scalar, proof->row_ratio.scalar,
                          proof->eta.scalar,       proof->dlog_challenge.scalar,
                          proof->alpha.scalar};
  ctx.expect(actual == expected, "V4 outer challenges match Python");
  const std::array expected_gammas{scalar("05ae7f9e9decde1b3a11fc1ef8ee6f1f"
                                          "c542749fa3aaa71a220f742a26426976"),
                                   scalar("0b415d8d9ee0e54e6d31cf2d346437a0"
                                          "03a4441eec318b493aa28f76690b71d1"),
                                   scalar("6c49de8636bdc1837df921477c437f11"
                                          "89b8251c1d8f626270bf52b7789ce601"),
                                   scalar("1eb1ab7ba7a71ba95a59471441725585"
                                          "b2446f1ffafe420094fdc2bb1fbb8cec")};
  ctx.expect(proof->gammas.size() == expected_gammas.size(),
             "V4 gamma count matches Python");
  if (proof->gammas.size() == expected_gammas.size()) {
    for (std::size_t index = 0; index < expected_gammas.size(); ++index) {
      ctx.expect(proof->gammas[index].scalar == expected_gammas[index],
                 "V4 gamma matches Python");
    }
  }
  ctx.expect(proof->prepared_binding.scalar ==
                 scalar("9f5f54875acb2d863f4eb1e1c2e34de7"
                        "050b53581f3f6a531259f6dc2fdc2dad"),
             "V4 prepared binding matches Python");

  auto staged = candidate::CircuitProofTranscriptV4::create(
      *shape, precommit->digest, fixture.proof.raw_generator_digest);
  expect_ok(ctx, staged, "V4 staged proof transcript creates");
  if (!staged)
    return;
  ctx.expect(staged->rho().scalar == proof->rho.scalar &&
                 staged->mul_scale().scalar == proof->mul_scale.scalar &&
                 staged->mul_ratio().scalar == proof->mul_ratio.scalar &&
                 staged->row_ratio().scalar == proof->row_ratio.scalar,
             "V4 staged prefix matches one-shot replay");
  auto eta = staged->append_anchored_commitments(
      fixture.proof.coefficient_commitment, fixture.proof.anchored_offset,
      fixture.proof.anchored_commitment, secp);
  auto dlog = staged->append_public_opening(
      fixture.proof.batched_public_commitment, fixture.proof.dlog_nonce, secp);
  auto response =
      FieldElement::try_from_bytes32(fixture.proof.dlog_response);
  auto t2 = FieldElement::try_from_bytes32(fixture.proof.t2);
  auto terminal_n = FieldElement::try_from_bytes32(fixture.proof.terminal_n);
  auto terminal_l = FieldElement::try_from_bytes32(fixture.proof.terminal_l);
  ctx.expect(eta && dlog && response && t2 && terminal_n && terminal_l,
             "V4 staged public values parse");
  if (!eta || !dlog || !response || !t2 || !terminal_n || !terminal_l)
    return;
  ctx.expect(eta->scalar == proof->eta.scalar &&
                 dlog->scalar == proof->dlog_challenge.scalar,
             "V4 staged public challenges match one-shot replay");
  ctx.expect(staged->append_dlog_response(*response).has_value(),
             "V4 staged DLog response appends");
  auto alpha =
      staged->append_mask(fixture.proof.mask_commitment, *t2, secp);
  ctx.expect(alpha && alpha->scalar == proof->alpha.scalar,
             "V4 staged masking challenge matches one-shot replay");
  if (!alpha)
    return;
  ctx.expect(staged->append_combined_commitment(
                 fixture.proof.combined_commitment, secp)
                 .has_value(),
             "V4 staged combined commitment appends");
  for (std::size_t index = 0; index < fixture.proof.rounds.size(); ++index) {
    auto gamma = staged->append_round(fixture.proof.rounds[index], secp);
    ctx.expect(gamma && gamma->scalar == proof->gammas[index].scalar,
               "V4 staged norm challenge matches one-shot replay");
    if (!gamma)
      return;
  }
  auto prepared = staged->finish(*terminal_n, *terminal_l);
  ctx.expect(prepared &&
                 prepared->scalar == proof->prepared_binding.scalar,
             "V4 staged terminal binding matches one-shot replay");
  ctx.expect(!staged->finish(*terminal_n, *terminal_l),
             "V4 staged transcript rejects a repeated terminal stage");
}

void check_binding_mutations(TestContext &ctx, purify_secp_context *secp) {
  Fixture fixture;
  auto shape = public_shape();
  if (!shape)
    return;
  auto base_precommit = candidate::derive_circuit_precommitment_v4(
      *shape, fixture.binding, fixture.public_commitments,
      fixture.raw_commitment, secp);
  if (!base_precommit)
    return;
  auto base = candidate::derive_circuit_proof_transcript_v4(
      *shape, base_precommit->digest, fixture.proof, secp);
  if (!base)
    return;

  auto binding = fixture.binding;
  binding[0] ^= 1;
  auto changed_binding = candidate::derive_circuit_precommitment_v4(
      *shape, binding, fixture.public_commitments, fixture.raw_commitment,
      secp);
  ctx.expect(changed_binding && changed_binding->digest.bytes() !=
                                    base_precommit->digest.bytes(),
             "V4 precommitment binds circuit digest");
  if (changed_binding) {
    auto changed_digest = candidate::derive_circuit_proof_transcript_v4(
        *shape, changed_binding->digest, fixture.proof, secp);
    ctx.expect(changed_digest && changed_digest->prepared_binding.scalar !=
                                     base->prepared_binding.scalar,
               "V4 proof binds the precommitment digest");
  }

  auto public_points = fixture.public_commitments;
  std::swap(public_points[0], public_points[1]);
  auto changed_points = candidate::derive_circuit_precommitment_v4(
      *shape, fixture.binding, public_points, fixture.raw_commitment, secp);
  ctx.expect(changed_points && changed_points->digest.bytes() !=
                                   base_precommit->digest.bytes(),
             "V4 precommitment binds ordered public points");

  auto changed_raw = candidate::derive_circuit_precommitment_v4(
      *shape, fixture.binding, fixture.public_commitments,
      fixture.proof.coefficient_commitment, secp);
  ctx.expect(changed_raw &&
                 changed_raw->digest.bytes() != base_precommit->digest.bytes(),
             "V4 precommitment binds raw commitment");

  auto changed_shape = CircuitTranscriptShapeV4::create(
      CircuitCommitmentModeV4::Public, 16, 2, 32, 32);
  expect_ok(ctx, changed_shape, "V4 changed shape creates");
  if (changed_shape) {
    auto changed_dimensions = candidate::derive_circuit_precommitment_v4(
        *changed_shape, fixture.binding, fixture.public_commitments,
        fixture.raw_commitment, secp);
    ctx.expect(changed_dimensions && changed_dimensions->digest.bytes() !=
                                         base_precommit->digest.bytes(),
               "V4 precommitment binds exact dimensions");
  }
  auto changed_proof_shape = CircuitTranscriptShapeV4::create(
      CircuitCommitmentModeV4::Public, 8, 3, 16, 16);
  expect_ok(ctx, changed_proof_shape, "V4 changed proof shape creates");
  if (changed_proof_shape) {
    auto changed_dimensions = candidate::derive_circuit_proof_transcript_v4(
        *changed_proof_shape, base_precommit->digest, fixture.proof, secp);
    ctx.expect(changed_dimensions &&
                   changed_dimensions->prepared_binding.scalar !=
                       base->prepared_binding.scalar,
               "V4 proof repeats and binds the exact dimensions");
  }

  const auto expect_changed = [&](CircuitProofTranscriptInputV4 changed,
                                  std::string_view label) {
    auto result = candidate::derive_circuit_proof_transcript_v4(
        *shape, base_precommit->digest, changed, secp);
    ctx.expect(result && result->prepared_binding.scalar !=
                             base->prepared_binding.scalar,
               label);
  };
  auto changed = fixture.proof;
  changed.raw_generator_digest[0] ^= 1;
  expect_changed(changed, "V4 proof binds generator digest");
  changed = fixture.proof;
  changed.coefficient_commitment = fixture.public_commitments[0];
  expect_changed(changed, "V4 proof binds coefficient commitment");
  changed = fixture.proof;
  changed.anchored_offset = fixture.public_commitments[0];
  expect_changed(changed, "V4 proof binds anchored offset");
  changed = fixture.proof;
  changed.anchored_commitment = fixture.public_commitments[0];
  expect_changed(changed, "V4 proof binds anchored commitment");
  changed = fixture.proof;
  changed.batched_public_commitment = fixture.public_commitments[0];
  expect_changed(changed, "V4 proof binds batched commitment");
  changed = fixture.proof;
  std::copy(fixture.public_commitments[0].begin() + 1,
            fixture.public_commitments[0].end(), changed.dlog_nonce.begin());
  expect_changed(changed, "V4 proof binds DLog nonce");
  changed = fixture.proof;
  changed.dlog_response = FieldElement::from_u64(12).to_bytes_be();
  expect_changed(changed, "V4 proof binds DLog response");
  changed = fixture.proof;
  changed.mask_commitment = fixture.public_commitments[0];
  expect_changed(changed, "V4 proof binds mask commitment");
  changed = fixture.proof;
  changed.t2 = FieldElement::from_u64(14).to_bytes_be();
  expect_changed(changed, "V4 proof binds t2");
  changed = fixture.proof;
  changed.combined_commitment = fixture.public_commitments[0];
  expect_changed(changed, "V4 proof binds combined commitment");
  changed = fixture.proof;
  changed.rounds[2][0] ^= 1;
  expect_changed(changed, "V4 proof binds point-pair parity");
  changed = fixture.proof;
  changed.rounds[2] = changed.rounds[3];
  expect_changed(changed, "V4 proof binds point-pair coordinates");
  changed = fixture.proof;
  changed.terminal_n = FieldElement::from_u64(18).to_bytes_be();
  expect_changed(changed, "V4 proof binds terminal n");
  changed = fixture.proof;
  changed.terminal_l = FieldElement::from_u64(20).to_bytes_be();
  expect_changed(changed, "V4 proof binds terminal l");
}

void check_domain_separation(TestContext &ctx) {
  Fixture fixture;
  candidate::AlgebraicTranscript wrong_suite;
  constexpr std::string_view domain = "Purify/BPPP/CircuitNormArg/v3/precommit";
  expect_ok(ctx,
            wrong_suite.append_bytes(std::span(
                reinterpret_cast<const unsigned char *>(domain.data()),
                domain.size())),
            "V4 cross-suite probe absorbs domain");
  expect_ok(ctx, wrong_suite.append_bytes(fixture.binding),
            "V4 cross-suite probe absorbs binding");
  wrong_suite.append_u64(1);
  wrong_suite.append_u64(8);
  wrong_suite.append_u64(2);
  wrong_suite.append_u64(16);
  wrong_suite.append_u64(16);
  wrong_suite.append_u64(2);
  for (const auto &point : fixture.public_commitments) {
    expect_ok(ctx, wrong_suite.append_point(point[0], point_x(point)),
              "V4 cross-suite probe absorbs public point");
  }
  expect_ok(ctx,
            wrong_suite.append_point(fixture.raw_commitment[0],
                                     point_x(fixture.raw_commitment)),
            "V4 cross-suite probe absorbs raw point");
  auto selected = candidate::select_nonzero_scalar(wrong_suite.challenge(0));
  expect_ok(ctx, selected, "V4 cross-suite probe selects challenge");
  if (selected) {
    ctx.expect(*selected != scalar("78732ddaf31c0d8af29b7b778d99540e"
                                   "a1ad10879d1e5a888e2277fdf659cb89"),
               "V4 domain cannot replay a V3-suite transcript");
  }
}

void check_hidden_branch_and_rejections(TestContext &ctx,
                                        purify_secp_context *secp) {
  Fixture fixture;
  auto public_shape_result = public_shape();
  if (!public_shape_result)
    return;
  auto precommit = candidate::derive_circuit_precommitment_v4(
      *public_shape_result, fixture.binding, fixture.public_commitments,
      fixture.raw_commitment, secp);
  if (!precommit)
    return;
  expect_error(
      ctx,
      candidate::derive_circuit_precommitment_v4(
          *public_shape_result, fixture.binding,
          std::span<const PointBytes>(fixture.public_commitments).first(1),
          fixture.raw_commitment, secp),
      purify::ErrorCode::SizeMismatch,
      "V4 precommitment rejects a mismatched public count");

  auto hidden_shape = CircuitTranscriptShapeV4::create(
      CircuitCommitmentModeV4::Hidden, 8, 2, 16, 16);
  expect_ok(ctx, hidden_shape, "V4 hidden shape creates");
  if (!hidden_shape)
    return;
  auto hidden_precommit = candidate::derive_circuit_precommitment_v4(
      *hidden_shape, fixture.binding, {}, fixture.raw_commitment, secp);
  expect_ok(ctx, hidden_precommit, "V4 hidden precommitment derives");
  ctx.expect(hidden_precommit &&
                 hidden_precommit->digest.bytes() != precommit->digest.bytes(),
             "V4 precommitment binds the commitment mode");
  expect_error(ctx,
               candidate::derive_circuit_precommitment_v4(
                   *hidden_shape, fixture.binding, fixture.public_commitments,
                   fixture.raw_commitment, secp),
               purify::ErrorCode::SizeMismatch,
               "V4 hidden mode rejects public points");
  if (!hidden_precommit)
    return;
  auto hidden_proof = fixture.proof;
  hidden_proof.batched_public_commitment.fill(0);
  hidden_proof.dlog_nonce.fill(0);
  hidden_proof.dlog_response.fill(0);
  auto hidden_result = candidate::derive_circuit_proof_transcript_v4(
      *hidden_shape, hidden_precommit->digest, hidden_proof, secp);
  expect_ok(ctx, hidden_result,
            "V4 hidden branch derives fixed DLog challenges");
  if (hidden_result) {
    ctx.expect(!hidden_result->eta.scalar.is_zero() &&
                   !hidden_result->dlog_challenge.scalar.is_zero(),
               "V4 hidden branch selects eta and the DLog challenge");
  }

  auto malformed = fixture.proof;
  malformed.dlog_nonce.fill(0);
  expect_error(ctx,
               candidate::derive_circuit_proof_transcript_v4(
                   *public_shape_result, precommit->digest, malformed, secp),
               purify::ErrorCode::BackendRejectedInput,
               "V4 public branch rejects zero nonce");
  hidden_proof.dlog_response = FieldElement::one().to_bytes_be();
  expect_error(ctx,
               candidate::derive_circuit_proof_transcript_v4(
                   *hidden_shape, hidden_precommit->digest, hidden_proof, secp),
               purify::ErrorCode::BindingMismatch,
               "V4 hidden branch requires a zero DLog response");
  hidden_proof.dlog_response.fill(0);
  hidden_proof.batched_public_commitment = fixture.public_commitments[0];
  expect_error(ctx,
               candidate::derive_circuit_proof_transcript_v4(
                   *hidden_shape, hidden_precommit->digest, hidden_proof, secp),
               purify::ErrorCode::BindingMismatch,
               "V4 hidden branch requires the batch identity");
  hidden_proof.batched_public_commitment.fill(0);
  hidden_proof.dlog_nonce = fixture.proof.dlog_nonce;
  expect_error(ctx,
               candidate::derive_circuit_proof_transcript_v4(
                   *hidden_shape, hidden_precommit->digest, hidden_proof, secp),
               purify::ErrorCode::BindingMismatch,
               "V4 hidden branch requires the zero nonce encoding");

  malformed = fixture.proof;
  malformed.coefficient_commitment[0] = 4;
  expect_error(ctx,
               candidate::derive_circuit_proof_transcript_v4(
                   *public_shape_result, precommit->digest, malformed, secp),
               purify::ErrorCode::BackendRejectedInput,
               "V4 rejects noncanonical point prefix");
  const auto field_modulus = bytes<32>("ffffffffffffffffffffffffffffffff"
                                       "fffffffffffffffffffffffefffffc2f");
  malformed = fixture.proof;
  std::copy(field_modulus.begin(), field_modulus.end(),
            malformed.coefficient_commitment.begin() + 1);
  expect_error(ctx,
               candidate::derive_circuit_proof_transcript_v4(
                   *public_shape_result, precommit->digest, malformed, secp),
               purify::ErrorCode::BackendRejectedInput,
               "V4 rejects noncanonical point coordinate");
  malformed = fixture.proof;
  malformed.rounds[0][0] = 4;
  expect_error(ctx,
               candidate::derive_circuit_proof_transcript_v4(
                   *public_shape_result, precommit->digest, malformed, secp),
               purify::ErrorCode::RangeViolation,
               "V4 rejects point-pair parity overflow");
  malformed = fixture.proof;
  malformed.rounds[0][0] |= 2;
  expect_error(ctx,
               candidate::derive_circuit_proof_transcript_v4(
                   *public_shape_result, precommit->digest, malformed, secp),
               purify::ErrorCode::BindingMismatch,
               "V4 rejects signed identity in point pair");
  malformed = fixture.proof;
  std::copy(field_modulus.begin(), field_modulus.end(),
            malformed.rounds[0].begin() + 1);
  expect_error(ctx,
               candidate::derive_circuit_proof_transcript_v4(
                   *public_shape_result, precommit->digest, malformed, secp),
               purify::ErrorCode::BackendRejectedInput,
               "V4 rejects noncanonical point-pair coordinate");
  malformed = fixture.proof;
  malformed.t2 =
      UInt256::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03b"
                        "bfd25e8cd0364141")
          .to_bytes_be();
  ctx.expect(!candidate::derive_circuit_proof_transcript_v4(
                 *public_shape_result, precommit->digest, malformed, secp),
             "V4 rejects noncanonical scalar");

  ctx.expect(!CircuitTranscriptShapeV4::create(
                 static_cast<CircuitCommitmentModeV4>(2), 8, 2, 16, 16),
             "V4 rejects unknown transcript mode");
  ctx.expect(!CircuitTranscriptShapeV4::create(CircuitCommitmentModeV4::Public,
                                               8, 0, 16, 16),
             "V4 rejects empty public mode");
  ctx.expect(!CircuitTranscriptShapeV4::create(CircuitCommitmentModeV4::Hidden,
                                               7, 2, 14, 14),
             "V4 rejects non-power-of-two gate shape");
  ctx.expect(CircuitTranscriptShapeV4::create(
                 CircuitCommitmentModeV4::Hidden, 8, 7, 16, 16)
                 .has_value(),
             "V4 hidden shape retains its last hiding coordinate");
  ctx.expect(!CircuitTranscriptShapeV4::create(
                 CircuitCommitmentModeV4::Hidden, 8, 8, 16, 16),
             "V4 rejects a hidden shape without a hiding coordinate");
  ctx.expect(!CircuitTranscriptShapeV4::create(
                 CircuitCommitmentModeV4::Hidden, 8, 9, 16, 16),
             "V4 rejects hidden commitments beyond the padded gates");
}

} // namespace

void run_algebraic_circuit_transcript_tests(TestContext &ctx) {
  auto secp = purify::make_secp_context();
  ctx.expect(secp != nullptr, "V4 transcript secp context creates");
  if (!secp)
    return;
  check_shared_vector(ctx, secp.get());
  check_binding_mutations(ctx, secp.get());
  check_domain_separation(ctx);
  check_hidden_branch_and_rejections(ctx, secp.get());
}
