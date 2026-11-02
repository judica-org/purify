// Copyright (c) 2026 Judica, Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include "poseidon.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <limits>
#include <utility>

namespace purify::bppp::candidate {
namespace {

constexpr std::size_t kFieldBits = 256;

class Grain {
public:
    Grain() {
        state_.fill(1);
        std::size_t offset = 0;
        write_bits(offset, 1, 2); // prime field
        write_bits(offset, 0, 4); // x^alpha S-box
        write_bits(offset, kFieldBits, 12);
        write_bits(offset, kPoseidonWidth, 12);
        write_bits(offset, kPoseidonFullRounds, 10);
        write_bits(offset, kPoseidonPartialRounds, 10);
        assert(offset == 50);
        for (std::size_t i = 0; i < 160; ++i) shift();
    }

    CoordinateFieldElement::Encoding next_bytes_be() {
        CoordinateFieldElement::Encoding bytes{};
        for (std::size_t bit = 0; bit < kFieldBits; ++bit) {
            bytes[bit / 8] |= static_cast<unsigned char>(next_bit() << (7 - bit % 8));
        }
        return bytes;
    }

    Result<CoordinateFieldElement> next_canonical() {
        return CoordinateFieldElement::from_bytes_be(next_bytes_be());
    }

    CoordinateFieldElement next_reduced() {
        return CoordinateFieldElement::from_reduced_bytes_be(next_bytes_be());
    }

private:
    void write_bits(std::size_t& offset, std::size_t value, std::size_t width) {
        assert(width <= std::numeric_limits<std::size_t>::digits);
        assert(value < (std::size_t{1} << width));
        for (std::size_t bit = width; bit != 0; --bit) {
            state_[offset++] = static_cast<unsigned char>((value >> (bit - 1)) & 1U);
        }
    }

    unsigned char shift() {
        const unsigned char next =
            state_[62] ^ state_[51] ^ state_[38] ^ state_[23] ^ state_[13] ^ state_[0];
        std::rotate(state_.begin(), state_.begin() + 1, state_.end());
        state_.back() = next;
        return next;
    }

    unsigned char next_bit() {
        unsigned char control = shift();
        while (control == 0) {
            shift();
            control = shift();
        }
        return shift();
    }

    std::array<unsigned char, 80> state_{};
};

PoseidonState mix(const PoseidonMatrix& matrix, const PoseidonState& vector) {
    PoseidonState out{};
    for (std::size_t row = 0; row < kPoseidonWidth; ++row) {
        for (std::size_t column = 0; column < kPoseidonWidth; ++column) {
            out[row] = out[row] + matrix[row][column] * vector[column];
        }
    }
    return out;
}

PoseidonMatrix identity_matrix() {
    PoseidonMatrix out{};
    for (std::size_t index = 0; index < kPoseidonWidth; ++index) {
        out[index][index] = CoordinateFieldElement::one();
    }
    return out;
}

PoseidonMatrix matrix_multiply(const PoseidonMatrix& left, const PoseidonMatrix& right) {
    PoseidonMatrix out{};
    for (std::size_t row = 0; row < kPoseidonWidth; ++row) {
        for (std::size_t column = 0; column < kPoseidonWidth; ++column) {
            for (std::size_t index = 0; index < kPoseidonWidth; ++index) {
                out[row][column] = out[row][column] + left[row][index] * right[index][column];
            }
        }
    }
    return out;
}

PoseidonMatrix matrix_power(PoseidonMatrix base, std::size_t exponent) {
    PoseidonMatrix result = identity_matrix();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            result = matrix_multiply(result, base);
        }
        base = matrix_multiply(base, base);
        exponent >>= 1;
    }
    return result;
}

CoordinateFieldElement determinant(const PoseidonMatrix& matrix) {
    return matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]) -
           matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]) +
           matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]);
}

bool proportional(const PoseidonState& left, const PoseidonState& right) {
    for (std::size_t first = 0; first < kPoseidonWidth; ++first) {
        for (std::size_t second = first + 1; second < kPoseidonWidth; ++second) {
            if (left[first] * right[second] != left[second] * right[first]) {
                return false;
            }
        }
    }
    return true;
}

bool krylov_secure(const PoseidonMatrix& matrix) {
    const PoseidonState basis{CoordinateFieldElement::one(), CoordinateFieldElement::zero(),
                              CoordinateFieldElement::zero()};
    const PoseidonState first = mix(matrix, basis);
    const PoseidonState second = mix(matrix, first);
    PoseidonMatrix columns{};
    for (std::size_t row = 0; row < kPoseidonWidth; ++row) {
        columns[row] = {basis[row], first[row], second[row]};
    }
    return !determinant(columns).is_zero();
}

bool algorithm_one_secure(const PoseidonMatrix& matrix) {
    const std::array<PoseidonMatrix, 3> powers{identity_matrix(), matrix, matrix_power(matrix, 2)};
    for (std::size_t exponent = 1; exponent <= 2; ++exponent) {
        const PoseidonMatrix& current = powers[exponent];
        PoseidonMatrix diagonal{};
        for (std::size_t index = 0; index < kPoseidonWidth; ++index) {
            diagonal[index][index] = current[0][0];
        }
        if (current == diagonal) return false;

        const PoseidonMatrix& source = exponent == 1 ? current : matrix;
        const PoseidonState vector{CoordinateFieldElement::zero(), source[0][2],
                                   CoordinateFieldElement::zero() - source[0][1]};
        if (vector == PoseidonState{} || proportional(vector, mix(current, vector))) {
            return false;
        }

        for (std::size_t index = 1; index <= exponent; ++index) {
            if (exponent == 1) {
                if (powers[index][0][1].is_zero() && powers[index][0][2].is_zero()) {
                    return false;
                }
            } else if (proportional(vector, mix(powers[index], vector))) {
                return false;
            }
        }
    }
    return true;
}

bool secure_mds(const PoseidonMatrix& matrix) {
    if (!algorithm_one_secure(matrix) || !krylov_secure(matrix)) {
        return false;
    }
    for (std::size_t power = 2; power <= 4 * kPoseidonWidth; ++power) {
        if (!krylov_secure(matrix_power(matrix, power))) return false;
    }
    return true;
}

PoseidonParameters generate_parameters() {
    Grain grain;
    PoseidonParameters out{};
    std::size_t constants = 0;
    while (constants < out.round_constants.size()) {
        auto candidate = grain.next_canonical();
        if (candidate) {
            out.round_constants[constants++] = std::move(*candidate);
        }
    }

    for (;;) {
        std::array<CoordinateFieldElement, 2 * kPoseidonWidth> values{};
        for (auto& value : values) value = grain.next_reduced();
        bool duplicate = false;
        for (std::size_t i = 0; i < values.size(); ++i) {
            for (std::size_t prior = 0; prior < i; ++prior) {
                duplicate |= values[i] == values[prior];
            }
        }
        if (duplicate) continue;

        bool valid = true;
        for (std::size_t row = 0; row < kPoseidonWidth; ++row) {
            for (std::size_t column = 0; column < kPoseidonWidth; ++column) {
                auto inverse = (values[row] + values[kPoseidonWidth + column]).inverse();
                if (!inverse) {
                    valid = false;
                    break;
                }
                out.mds[row][column] = std::move(*inverse);
            }
            if (!valid) break;
        }
        if (valid && secure_mds(out.mds)) return out;
    }
}

CoordinateFieldElement pow5(const CoordinateFieldElement& value) {
    const CoordinateFieldElement squared = value * value;
    return squared * squared * value;
}

} // namespace

const PoseidonParameters& poseidon_parameters() {
    static const PoseidonParameters parameters = generate_parameters();
    return parameters;
}

PoseidonState poseidon_permute(PoseidonState state) {
    const PoseidonParameters& parameters = poseidon_parameters();
    for (std::size_t round = 0; round < kPoseidonFullRounds + kPoseidonPartialRounds; ++round) {
        for (std::size_t lane = 0; lane < kPoseidonWidth; ++lane) {
            state[lane] = state[lane] + parameters.round_constants[round * kPoseidonWidth + lane];
        }
        const bool full = round < kPoseidonFullRounds / 2 ||
                          round >= kPoseidonFullRounds / 2 + kPoseidonPartialRounds;
        if (full) {
            for (auto& value : state) value = pow5(value);
        } else {
            state[0] = pow5(state[0]);
        }
        state = mix(parameters.mds, state);
    }
    return state;
}

} // namespace purify::bppp::candidate
