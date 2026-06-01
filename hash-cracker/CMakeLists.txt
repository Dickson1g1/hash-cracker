cmake_minimum_required(VERSION 3.16)
project(hash_cracker VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Aggressive optimisation in Release — hash throughput is CPU-bound
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -Wall -Wextra -fsanitize=address,undefined")

# OpenSSL is required for MD5, SHA1, SHA256, SHA512
find_package(OpenSSL REQUIRED)

add_executable(crack
  src/main.cpp
  src/hash.cpp
  src/detector.cpp
  src/rules.cpp
  src/dictionary.cpp
  src/bruteforce.cpp
  src/progress.cpp
)

target_include_directories(crack PRIVATE src)
target_link_libraries(crack PRIVATE
  OpenSSL::Crypto   # libcrypto — hash functions
  pthread           # POSIX threads
)
