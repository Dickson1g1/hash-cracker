#include "bruteforce.hpp"
#include "hash.hpp"
#include <cmath>
#include <atomic>
#include <thread>
#include <vector>

// ---------------------------------------------------------------------------
// Keyspace partitioning for zero-contention brute force
// ---------------------------------------------------------------------------
// For a charset of size C and password length L, the keyspace has C^L entries.
// We number every candidate 0 … C^L-1 (mixed-radix representation in base C).
//
// To partition across N threads:
//   Thread 0 handles candidates [0,        K/N)
//   Thread 1 handles candidates [K/N,    2*K/N)
//   ...
//   Thread N handles candidates [(N-1)*K/N, K)
//
// Each thread converts its integer range back to strings using index_to_string().
// No shared queue, no mutex, no work stealing needed — just math.
// ---------------------------------------------------------------------------

// Convert an integer index to the corresponding password string
// using mixed-radix (base = charset.size()) representation.
static std::string index_to_string(uint64_t idx,
                                    const std::string& charset,
                                    int length) {
    std::string result(length, charset[0]);
    size_t base = charset.size();
    for (int i = length - 1; i >= 0; --i) {
        result[i] = charset[idx % base];
        idx /= base;
    }
    return result;
}

CrackResult brute_force_attack(
    const std::string& target_hash,
    HashAlgo           algo,
    const std::string& charset,
    int                min_len,
    int                max_len,
    std::string_view   salt,
    bool               salt_append,
    unsigned           num_threads,
    std::atomic<uint64_t>& attempts,
    std::atomic<bool>&  found_flag)
{
    std::atomic<bool> local_found{false};
    std::string result_pw;
    std::mutex  result_mutex;

    size_t base = charset.size();

    // Iterate over each password length
    for (int len = min_len; len <= max_len && !found_flag.load(); ++len) {
        // Total candidates for this length = base^len
        // Use __uint128_t to avoid overflow for large keyspaces
        __uint128_t keyspace = 1;
        for (int i = 0; i < len; ++i) keyspace *= base;

        // Cap at UINT64_MAX to fit in a uint64_t loop variable
        uint64_t total = (keyspace > UINT64_MAX)
                         ? UINT64_MAX
                         : static_cast<uint64_t>(keyspace);

        // Partition the keyspace evenly across threads
        uint64_t chunk = total / num_threads;

        auto worker = [&](uint64_t start, uint64_t end_idx) {
            for (uint64_t idx = start;
                 idx < end_idx && !found_flag.load(std::memory_order_relaxed);
                 ++idx)
            {
                ++attempts;
                std::string candidate = index_to_string(idx, charset, len);
                std::string h = compute_hash(candidate, algo, salt, salt_append);
                if (h == target_hash) {
                    found_flag.store(true, std::memory_order_relaxed);
                    std::lock_guard<std::mutex> lk(result_mutex);
                    result_pw = candidate;
                    return;
                }
            }
        };

        std::vector<std::thread> threads;
        for (unsigned t = 0; t < num_threads; ++t) {
            uint64_t start = t * chunk;
            uint64_t end   = (t == num_threads - 1) ? total : start + chunk;
            threads.emplace_back(worker, start, end);
        }
        for (auto& th : threads) th.join();

        if (found_flag.load()) return {true, result_pw};
    }
    return {false, ""};
}

// Pre-defined character sets for common attack modes
const std::string CHARSET_LOWER  = "abcdefghijklmnopqrstuvwxyz";
const std::string CHARSET_UPPER  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::string CHARSET_DIGITS = "0123456789";
const std::string CHARSET_ALPHA  = CHARSET_LOWER + CHARSET_UPPER;
const std::string CHARSET_ALNUM  = CHARSET_ALPHA + CHARSET_DIGITS;
const std::string CHARSET_FULL   = CHARSET_ALNUM + "!@#$%^&*()-_=+[]{}|;:,.<>?";
