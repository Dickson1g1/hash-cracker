#include "hash.hpp"
#include <openssl/evp.h>
#include <stdexcept>
#include <array>
#include <cstdio>

// ---------------------------------------------------------------------------
// OpenSSL EVP (Envelope) API
// ---------------------------------------------------------------------------
// The EVP interface is OpenSSL's high-level, algorithm-agnostic digest API.
// Rather than calling MD5() or SHA256() directly (which are deprecated
// in OpenSSL 3.0), we use EVP_DigestInit/Update/Final which works
// identically for all algorithms — only the EVP_MD* type differs.
//
// EVP_MD_CTX is the digest context: allocated on the stack (via
// EVP_MD_CTX_new) and freed when done (EVP_MD_CTX_free).
// ---------------------------------------------------------------------------

// Map our enum to OpenSSL's EVP_MD type
static const EVP_MD* get_evp_md(HashAlgo algo) {
    switch (algo) {
        case HashAlgo::MD5:    return EVP_md5();
        case HashAlgo::SHA1:   return EVP_sha1();
        case HashAlgo::SHA256: return EVP_sha256();
        case HashAlgo::SHA512: return EVP_sha512();
    }
    return nullptr;
}

std::string compute_hash(std::string_view input, HashAlgo algo,
                         std::string_view salt, bool salt_append) {
    const EVP_MD* md = get_evp_md(algo);
    if (!md) throw std::invalid_argument("Unknown hash algorithm");

    // Allocate a new digest context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    // EVP_DigestInit_ex initialises the context for the chosen algorithm.
    // The second argument is an ENGINE* for hardware acceleration — nullptr
    // means use the default software implementation.
    EVP_DigestInit_ex(ctx, md, nullptr);

    // Feed data in the correct order (salt position)
    if (!salt.empty() && !salt_append) {
        // Prepend: hash(salt + input)
        EVP_DigestUpdate(ctx, salt.data(), salt.size());
    }
    EVP_DigestUpdate(ctx, input.data(), input.size());
    if (!salt.empty() && salt_append) {
        // Append: hash(input + salt)
        EVP_DigestUpdate(ctx, salt.data(), salt.size());
    }

    // Finalise — copies the digest bytes into 'raw'
    // EVP_MAX_MD_SIZE = 64 bytes (large enough for any algorithm)
    std::array<unsigned char, EVP_MAX_MD_SIZE> raw{};
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, raw.data(), &len);
    EVP_MD_CTX_free(ctx);

    // Convert raw bytes to lowercase hex string
    // Each byte becomes 2 hex characters (e.g. 0xAB → "ab")
    std::string hex;
    hex.reserve(len * 2);
    char buf[3];
    for (unsigned i = 0; i < len; ++i) {
        snprintf(buf, sizeof(buf), "%02x", raw[i]);
        hex += buf;
    }
    return hex;
}

size_t hex_length(HashAlgo algo) {
    switch (algo) {
        case HashAlgo::MD5:    return 32;
        case HashAlgo::SHA1:   return 40;
        case HashAlgo::SHA256: return 64;
        case HashAlgo::SHA512: return 128;
    }
    return 0;
}

const char* algo_name(HashAlgo algo) {
    switch (algo) {
        case HashAlgo::MD5:    return "MD5";
        case HashAlgo::SHA1:   return "SHA1";
        case HashAlgo::SHA256: return "SHA256";
        case HashAlgo::SHA512: return "SHA512";
    }
    return "UNKNOWN";
}
