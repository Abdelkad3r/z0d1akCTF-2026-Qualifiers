#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kStepMultiplier = 0x85ebca6bU;
constexpr uint32_t kLengthMultiplier = 0xc2b2ae35U;
constexpr int kHalfLength = 4;
constexpr int kCollisionLength = 8;

uint32_t rol32(uint32_t value, unsigned amount) {
    return (value << amount) | (value >> (32 - amount));
}

uint32_t ror32(uint32_t value, unsigned amount) {
    return (value >> amount) | (value << (32 - amount));
}

uint32_t inverse_odd32(uint32_t value) {
    uint32_t inverse = 1;
    for (int round = 0; round < 5; ++round) {
        inverse *= 2U - value * inverse;
    }
    return inverse;
}

uint32_t undo_xor_shift_right(uint32_t value, unsigned amount) {
    uint32_t result = value;
    for (unsigned shift = amount; shift < 32; shift <<= 1) {
        result ^= result >> shift;
    }
    return result;
}

uint32_t undo_final_mix(uint32_t value) {
    static const uint32_t inverse_second = inverse_odd32(0x846ca68bU);
    static const uint32_t inverse_first = inverse_odd32(0x7feb352dU);

    value = undo_xor_shift_right(value, 16);
    value *= inverse_second;
    value = undo_xor_shift_right(value, 15);
    value *= inverse_first;
    value = undo_xor_shift_right(value, 16);
    return value;
}

uint32_t hash_step(uint32_t state, uint8_t byte) {
    return rol32((uint32_t(byte) ^ state) * kStepMultiplier, 13);
}

std::string decode_word(uint32_t code, const std::string &alphabet) {
    std::string word;
    word.reserve(kHalfLength);
    for (int index = 0; index < kHalfLength; ++index) {
        word.push_back(alphabet[code % alphabet.size()]);
        code /= static_cast<uint32_t>(alphabet.size());
    }
    return word;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "usage: collision_finder IDENTITY_SALT TARGET_HASH [TARGET_HASH ...]\n";
        return 2;
    }

    const uint32_t salt = static_cast<uint32_t>(std::strtoul(argv[1], nullptr, 0));
    const std::string alphabet =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    const uint32_t initial_state = salt ^ 0x9e3779b9U;

    size_t half_space = 1;
    for (int index = 0; index < kHalfLength; ++index) {
        half_space *= alphabet.size();
    }

    // Store state in the high dword and the compact prefix code in the low dword.
    std::vector<uint64_t> forward;
    forward.reserve(half_space);
    for (size_t code = 0; code < half_space; ++code) {
        uint32_t state = initial_state;
        const std::string prefix = decode_word(static_cast<uint32_t>(code), alphabet);
        for (const unsigned char byte : prefix) {
            state = hash_step(state, byte);
        }
        forward.push_back((uint64_t(state) << 32) | uint32_t(code));
    }
    std::sort(forward.begin(), forward.end());

    const uint32_t inverse_step_multiplier = inverse_odd32(kStepMultiplier);
    for (int argument = 2; argument < argc; ++argument) {
        const uint32_t target_hash =
            static_cast<uint32_t>(std::strtoul(argv[argument], nullptr, 16));
        const uint32_t target_state =
            undo_final_mix(target_hash) ^ (kCollisionLength * kLengthMultiplier);
        bool found = false;

        for (size_t code = 0; code < half_space && !found; ++code) {
            const std::string suffix = decode_word(static_cast<uint32_t>(code), alphabet);
            uint32_t state = target_state;
            for (int index = kHalfLength - 1; index >= 0; --index) {
                state = (ror32(state, 13) * inverse_step_multiplier) ^
                        uint32_t(static_cast<unsigned char>(suffix[index]));
            }

            const uint64_t key = uint64_t(state) << 32;
            const auto match = std::lower_bound(forward.begin(), forward.end(), key);
            if (match != forward.end() && uint32_t(*match >> 32) == state) {
                const std::string prefix = decode_word(uint32_t(*match), alphabet);
                std::cout << std::hex << std::setfill('0') << std::setw(8) << target_hash
                          << " " << prefix << suffix << "\n";
                found = true;
            }
        }

        if (!found) {
            std::cerr << "no eight-byte collision for " << argv[argument] << "\n";
            return 1;
        }
    }

    return 0;
}
