#pragma once
#include <string>
#include <string_view>

// Supported hash algorithms
enum class HashAlgo { MD5, SHA1, SHA256, SHA512 };

// Returns the hex-encoded digest of input using the given algorithm.
// Salt is prepended or appended depending on salt_append flag.
std::string compute_hash(std::string_view input,
                         HashAlgo algo,
                         std::string_view salt = "",
                         bool salt_append = false);

// Returns the expected hex string length for each algorithm
// (MD5=32, SHA1=40, SHA256=64, SHA512=128)
size_t hex_length(HashAlgo algo);

// Human-readable algorithm name
const char* algo_name(HashAlgo algo);
