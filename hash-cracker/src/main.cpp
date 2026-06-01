#include "hash.hpp"
#include "detector.hpp"
#include "dictionary.hpp"
#include "bruteforce.hpp"
#include "progress.hpp"
#include <iostream>
#include <string>
#include <atomic>
#include <thread>

static void print_usage(const char* prog) {
    fprintf(stderr,
R"(Usage: %s [options] <hash>

Options:
  -m <algo>       Hash algorithm: md5 sha1 sha256 sha512 (auto-detect if omitted)
  -w <wordlist>   Dictionary attack — path to wordlist file
  -b              Brute force attack
  --min <n>       Brute force minimum length (default 1)
  --max <n>       Brute force maximum length (default 6)
  --charset <s>   Character set: lower upper digits alpha alnum full or custom string
  --rules         Apply mutation rules (capitalize, leet, digits, reverse...)
  --salt <s>      Salt value
  --salt-append   Append salt instead of prepending (default: prepend)
  -t <n>          Threads (default: hardware concurrency)

Examples:
  crack -w rockyou.txt 5f4dcc3b5aa765d61d8327deb882cf99
  crack -w rockyou.txt --rules 5f4dcc3b5aa765d61d8327deb882cf99
  crack -b --charset lower --max 6 5f4dcc3b5aa765d61d8327deb882cf99
  crack -b --charset full --min 4 --max 8 -m sha256 <hash>
)", prog);
}

int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    std::string  target_hash;
    std::string  wordlist;
    std::string  algo_str;
    std::string  salt;
    std::string  charset_arg = "alnum";
    bool         brute  = false;
    bool         rules  = false;
    bool         salt_append = false;
    int          min_len = 1, max_len = 6;
    unsigned     threads = std::thread::hardware_concurrency();

    // Simple argument parsing
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "-m"  && i+1 < argc) algo_str    = argv[++i];
        else if (a == "-w"  && i+1 < argc) wordlist     = argv[++i];
        else if (a == "-b")                 brute        = true;
        else if (a == "--rules")            rules        = true;
        else if (a == "--min" && i+1 < argc) min_len   = std::stoi(argv[++i]);
        else if (a == "--max" && i+1 < argc) max_len   = std::stoi(argv[++i]);
        else if (a == "--charset" && i+1 < argc) charset_arg = argv[++i];
        else if (a == "--salt" && i+1 < argc) salt      = argv[++i];
        else if (a == "--salt-append")      salt_append  = true;
        else if (a == "-t"  && i+1 < argc) threads      = std::stoul(argv[++i]);
        else if (a[0] != '-')               target_hash  = a;
    }

    if (target_hash.empty()) { print_usage(argv[0]); return 1; }

    // Auto-detect algorithm from hash length
    HashAlgo algo;
    try {
        algo = algo_str.empty()
            ? detect_algorithm(target_hash)
            : [&]() -> HashAlgo {
                if (algo_str == "md5")    return HashAlgo::MD5;
                if (algo_str == "sha1")   return HashAlgo::SHA1;
                if (algo_str == "sha256") return HashAlgo::SHA256;
                if (algo_str == "sha512") return HashAlgo::SHA512;
                throw std::invalid_argument("Unknown algorithm: " + algo_str);
              }();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    std::cout << "Target : " << target_hash << "\n";
    std::cout << "Algo   : " << algo_name(algo) << "\n";
    std::cout << "Threads: " << threads << "\n";
    if (!salt.empty()) std::cout << "Salt   : " << salt
                                  << (salt_append ? " (append)\n" : " (prepend)\n");

    std::atomic<uint64_t> attempts{0};
    std::atomic<bool>     found_flag{false};
    std::atomic<bool>     progress_done{false};

    // Resolve charset
    std::string charset;
    if      (charset_arg == "lower")  charset = CHARSET_LOWER;
    else if (charset_arg == "upper")  charset = CHARSET_UPPER;
    else if (charset_arg == "digits") charset = CHARSET_DIGITS;
    else if (charset_arg == "alpha")  charset = CHARSET_ALPHA;
    else if (charset_arg == "alnum")  charset = CHARSET_ALNUM;
    else if (charset_arg == "full")   charset = CHARSET_FULL;
    else                              charset = charset_arg; // custom

    CrackResult result{false, ""};

    // Run progress bar on a separate thread so it never blocks hashing
    std::thread progress_thread([&] {
        run_progress(attempts, progress_done, 0, brute ? "BRUTE" : "DICT");
    });

    try {
        if (!wordlist.empty()) {
            auto rule_set = rules ? default_rules() : std::vector<Rule>{Rule::NONE};
            result = dictionary_attack(
                target_hash, algo, wordlist, rule_set,
                salt, salt_append, threads, attempts, found_flag);
        } else if (brute) {
            result = brute_force_attack(
                target_hash, algo, charset, min_len, max_len,
                salt, salt_append, threads, attempts, found_flag);
        } else {
            std::cerr << "Error: specify -w <wordlist> or -b\n";
            progress_done = true;
            progress_thread.join();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << "\n";
        progress_done = true;
        progress_thread.join();
        return 2;
    }

    progress_done = true;
    progress_thread.join();

    if (result.found) {
        std::cout << "\n\033[1;32m[CRACKED]\033[0m " << result.password
                  << "  (" << attempts.load() << " attempts)\n";
        return 0;
    } else {
        std::cout << "\n\033[1;31m[NOT FOUND]\033[0m after "
                  << attempts.load() << " attempts\n";
        return 1;
    }
}
