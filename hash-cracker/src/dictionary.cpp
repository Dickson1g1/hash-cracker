#include "dictionary.hpp"
#include "hash.hpp"
#include "rules.hpp"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <atomic>
#include <thread>
#include <vector>
#include <stdexcept>
#include <cstring>

// ---------------------------------------------------------------------------
// Memory-mapped wordlist
// ---------------------------------------------------------------------------
// mmap() maps the wordlist file into virtual memory without reading it.
// The OS loads pages from disk only when they are accessed (demand paging).
// Benefits:
//   1. Zero-copy: no heap allocation, no memcpy — the kernel handles paging
//   2. OS caching: the page cache keeps hot pages in RAM automatically
//   3. Huge file support: a 14GB rockyou.txt fits with 64-bit address space
//
// We then scan the mapped memory for newlines to partition lines across threads.
// ---------------------------------------------------------------------------

// Scans the mmap region for the line starting at offset, returns the line
// as a string_view (zero copy — points into the mapped memory).
static std::string_view get_line(const char* base, size_t offset, size_t file_size) {
    const char* start = base + offset;
    const char* end   = start;
    while (end < base + file_size && *end != '\n') ++end;
    // Strip Windows-style \r\n
    size_t len = end - start;
    if (len > 0 && start[len-1] == '\r') --len;
    return {start, len};
}

CrackResult dictionary_attack(
    const std::string& target_hash,
    HashAlgo           algo,
    const std::string& wordlist_path,
    const std::vector<Rule>& rules,
    std::string_view   salt,
    bool               salt_append,
    unsigned           num_threads,
    std::atomic<uint64_t>& attempts,
    std::atomic<bool>&  found_flag)
{
    // Open the wordlist file
    int fd = open(wordlist_path.c_str(), O_RDONLY);
    if (fd < 0) throw std::runtime_error("Cannot open wordlist: " + wordlist_path);

    struct stat st{};
    if (fstat(fd, &st) < 0) { close(fd); throw std::runtime_error("fstat failed"); }
    size_t file_size = static_cast<size_t>(st.st_size);

    // Map the entire file into virtual address space (read-only, shared)
    // MAP_POPULATE hints the kernel to prefault pages — faster sequential reads
    void* mapped = mmap(nullptr, file_size, PROT_READ,
                        MAP_PRIVATE | MAP_POPULATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED)
        throw std::runtime_error("mmap failed for: " + wordlist_path);

    // Advise the kernel that we'll read sequentially — enables readahead
    madvise(mapped, file_size, MADV_SEQUENTIAL);

    const char* base = static_cast<const char*>(mapped);

    // Partition the file into N chunks — one per thread.
    // Each thread gets a contiguous byte range and processes lines within it.
    // We snap chunk boundaries to the nearest newline to avoid splitting words.
    std::vector<size_t> chunk_starts(num_threads + 1);
    chunk_starts[0] = 0;
    for (unsigned i = 1; i < num_threads; ++i) {
        size_t approx = (file_size / num_threads) * i;
        // Advance to the next newline so we don't cut a word in half
        while (approx < file_size && base[approx] != '\n') ++approx;
        chunk_starts[i] = approx + 1;
    }
    chunk_starts[num_threads] = file_size;

    // Shared result — written once when a thread finds the password
    std::atomic<bool> local_found{false};
    std::string        result_password;
    std::mutex         result_mutex;

    // Launch worker threads — each processes its chunk independently
    // (zero contention on the wordlist; contention only on found_flag)
    auto worker = [&](unsigned tid) {
        size_t pos = chunk_starts[tid];
        size_t end = chunk_starts[tid + 1];

        while (pos < end && !found_flag.load(std::memory_order_relaxed)) {
            // Get the next line (zero-copy string_view into mapped memory)
            auto line = get_line(base, pos, file_size);

            // Advance position past this line + newline character
            pos += line.size() + 1;
            if (pos < file_size && base[pos-1] == '\r') ++pos; // skip \r

            if (line.empty()) continue;

            std::string word(line);   // one allocation per word — unavoidable for rules

            // Apply mutation rules to generate candidate list
            auto candidates = apply_rules(word, rules);

            for (const auto& candidate : candidates) {
                ++attempts;
                std::string h = compute_hash(candidate, algo, salt, salt_append);
                if (h == target_hash) {
                    found_flag.store(true, std::memory_order_relaxed);
                    std::lock_guard<std::mutex> lk(result_mutex);
                    result_password = candidate;
                    return;
                }
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(num_threads);
    for (unsigned i = 0; i < num_threads; ++i)
        threads.emplace_back(worker, i);
    for (auto& t : threads) t.join();

    munmap(mapped, file_size);

    if (found_flag.load()) return {true, result_password};
    return {false, ""};
}
