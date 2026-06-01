```
 ██╗  ██╗ █████╗ ███████╗██╗  ██╗
 ██║  ██║██╔══██╗██╔════╝██║  ██║
 ███████║███████║███████╗███████║
 ██╔══██║██╔══██║╚════██║██╔══██║
 ██║  ██║██║  ██║███████║██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

  ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ 
 ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
 ██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
 ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

   md5 · sha1 · sha256 · sha512 · dictionary · brute force · c++
```

# hash-cracker

> Dictionary and brute-force hash cracking in C++20.
> Auto-detects MD5, SHA1, SHA256, and SHA512 from hash length.
> Memory-mapped wordlists, zero-contention keyspace partitioning,
> rule-based mutations, salt support, and a live Rich progress display.

---

## What it does

`hash-cracker` takes a hash string, auto-detects the algorithm from its
length, and attempts to recover the original password using either a
dictionary attack (with optional mutation rules) or a configurable
brute-force attack. All CPU cores are used by default with
mathematically partitioned work — no shared queues, no locks between
threads during hashing.

```
$ ./build/crack -w wordlists/rockyou.txt 5f4dcc3b5aa765d61d8327deb882cf99

Target : 5f4dcc3b5aa765d61d8327deb882cf99
Algo   : MD5
Threads: 16

DICT [=========>            ] 4.2 MH/s | 3s elapsed | ETA: 12s | 12,845,231 attempts

[CRACKED] password  (3,211,234 attempts)
```

---

## Features

- **Auto-detection** — identifies MD5 (32), SHA1 (40), SHA256 (64), and
  SHA512 (128) purely from the hex string length; no guessing required
- **Dictionary attack** — reads wordlists using `mmap()` for zero-copy
  large file handling; a 14GB wordlist never fully loads into RAM
- **Brute-force attack** — generates all strings of configurable length
  from a charset; keyspace partitioned mathematically across threads
  with zero contention (each thread owns a disjoint integer range)
- **Rule-based mutations** — capitalize, uppercase, leet speak, digit
  append (0–9, 12, 123, 1234), reverse, toggle case, prepend year,
  append `!`, and double — applied to every wordlist entry
- **Multi-threaded** — uses all CPU cores by default; `-t` flag to limit;
  no shared work queue between threads during hashing
- **Salt support** — `--salt` with configurable prepend (default) or
  append (`--salt-append`) position
- **Live progress display** — ANSI progress bar, hashes-per-second rate
  (H/s / KH/s / MH/s / GH/s), elapsed time, and ETA
- **OpenSSL EVP backend** — unified API for all four algorithms; `-O3
  -march=native` enables AVX2 SHA hardware acceleration on modern CPUs
- **Exit codes** — `0` cracked · `1` not found · `2` error

---

## Requirements

- C++20 (GCC 10+ or Clang 12+)
- CMake 3.16+
- OpenSSL 1.1+ (`libssl-dev`)
- Linux (uses `mmap` and POSIX threads)

```bash
# Ubuntu / Debian
sudo apt install build-essential cmake libssl-dev

# Arch
sudo pacman -S base-devel cmake openssl

# Fedora
sudo dnf install gcc-c++ cmake openssl-devel
```

---

## Installation

```bash
git clone https://github.com/Dickson1g1/hash-cracker.git
cd hash-cracker
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

---

## Usage

```bash
# Dictionary attack (MD5 auto-detected from hash length)
./build/crack -w wordlists/rockyou.txt 5f4dcc3b5aa765d61d8327deb882cf99

# Dictionary + all mutation rules
./build/crack -w wordlists/rockyou.txt --rules 5f4dcc3b5aa765d61d8327deb882cf99

# Brute force — lowercase letters, lengths 1–6
./build/crack -b --charset lower --min 1 --max 6 5f4dcc3b5aa765d61d8327deb882cf99

# Brute force — full charset (letters + digits + symbols), max length 8
./build/crack -b --charset full --min 4 --max 8 

# SHA256 with a prepended salt
./build/crack -w wordlists/rockyou.txt -m sha256 --salt mysalt 

# SHA512 with an appended salt
./build/crack -w wordlists/rockyou.txt -m sha512 --salt mysalt --salt-append 

# Limit to 4 threads
./build/crack -b --charset alnum --max 5 -t 4 

# Custom character set
./build/crack -b --charset "abc123!@#" --max 6 
```

---

## Options

| Flag | Description |
|------|-------------|
| `-m ` | Algorithm: `md5` `sha1` `sha256` `sha512` (auto-detected if omitted) |
| `-w ` | Dictionary attack using a wordlist file |
| `-b` | Brute-force attack |
| `--min ` | Brute-force minimum password length (default 1) |
| `--max ` | Brute-force maximum password length (default 6) |
| `--charset ` | `lower` `upper` `digits` `alpha` `alnum` `full` or custom string |
| `--rules` | Apply all mutation rules to each dictionary word |
| `--salt ` | Salt value to include in the hash |
| `--salt-append` | Append salt instead of prepending (default: prepend) |
| `-t ` | Number of threads (default: all CPU cores) |

---

## Character sets

| Name | Characters |
|------|-----------|
| `lower` | `a-z` (26) |
| `upper` | `A-Z` (26) |
| `digits` | `0-9` (10) |
| `alpha` | `a-zA-Z` (52) |
| `alnum` | `a-zA-Z0-9` (62) |
| `full` | `alnum` + `!@#$%^&*()-_=+[]{}|;:,.<>?` (95) |

---

## Mutation rules

| Rule | Example |
|------|---------|
| `CAPITALIZE` | `password` → `Password` |
| `UPPERCASE` | `password` → `PASSWORD` |
| `LEET` | `password` → `p@55w0rd` |
| `APPEND_DIGITS` | `password` → `password1`, `password123`... |
| `REVERSE` | `password` → `drowssap` |
| `TOGGLE_CASE` | `password` → `pAsSwOrD` |
| `PREPEND_YEAR` | `password` → `2024password` |
| `APPEND_BANG` | `password` → `password!` |
| `DOUBLE` | `password` → `passwordpassword` |

---

## Getting wordlists

```bash
# rockyou.txt — 14 million passwords (133 MB)
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
mv rockyou.txt wordlists/

# Generate test hashes
echo -n "password"  | md5sum
echo -n "password"  | sha1sum
echo -n "password"  | sha256sum
echo -n "password"  | sha512sum
```

---

## Project structure

```
hash-cracker/
├── CMakeLists.txt
├── src/
│   ├── main.cpp           # CLI entry point and argument parsing
│   ├── hash.hpp/cpp       # OpenSSL EVP hash wrappers (MD5/SHA1/SHA256/SHA512)
│   ├── detector.hpp/cpp   # Auto-detect algorithm from hash hex length
│   ├── rules.hpp/cpp      # Mutation rule engine (capitalize, leet, etc.)
│   ├── dictionary.hpp/cpp # mmap() wordlist + threaded dictionary attack
│   ├── bruteforce.hpp/cpp # Keyspace generator + partitioned brute force
│   └── progress.hpp/cpp   # ANSI progress bar + speed/ETA display
└── wordlists/
    └── (place rockyou.txt and other wordlists here)
```

---

## Concepts covered

- OpenSSL EVP unified digest API (`EVP_DigestInit/Update/Final`)
- `mmap()` + `madvise(MADV_SEQUENTIAL)` for zero-copy file reading
- Mixed-radix keyspace indexing for brute-force (base-N counting)
- Zero-contention work partitioning (mathematical ranges, no shared queue)
- `std::atomic` for lock-free attempt counting and found-flag signalling
- `std::lock_guard` RAII mutex for result write protection
- ANSI escape codes for live-updating terminal progress display
- CMake `find_package(OpenSSL)` and target linking

---

## Legal notice

Only crack hashes you own or have explicit written permission to test.
Unauthorised password cracking is illegal under computer fraud laws in
most jurisdictions. This tool is provided for educational and
authorised security research purposes only.

---

## License

MIT — do whatever you want, attribution appreciated.
