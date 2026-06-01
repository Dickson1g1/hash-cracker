#include "detector.hpp"
#include "hash.hpp"
#include <stdexcept>
#include <algorithm>

// Detect algorithm purely from the hex string length.
// MD5=32, SHA1=40, SHA256=64, SHA512=128 characters.
// This is unambiguous — no two supported algorithms produce the same length.
HashAlgo detect_algorithm(const std::string& hash) {
    // Validate: must be all hex characters
    for (char c : hash) {
        if (!std::isxdigit(static_cast<unsigned char>(c)))
            throw std::invalid_argument("Not a valid hex hash: " + hash);
    }

    switch (hash.size()) {
        case 32:  return HashAlgo::MD5;
        case 40:  return HashAlgo::SHA1;
        case 64:  return HashAlgo::SHA256;
        case 128: return HashAlgo::SHA512;
        default:
            throw std::invalid_argument(
                "Cannot detect algorithm: unsupported hash length " +
                std::to_string(hash.size()));
    }
}
