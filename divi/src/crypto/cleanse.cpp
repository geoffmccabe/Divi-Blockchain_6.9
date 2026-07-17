// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2024 The Divi Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/cleanse.h"

#include <cstring>

// Zero a buffer and prevent the compiler from optimizing the write away.
// The empty inline-asm barrier tells the optimizer the memory may be read
// through `ptr`, so the preceding memset must be kept (same technique used
// by Bitcoin Core's memory_cleanse on GCC/Clang).
void memory_cleanse(void* ptr, size_t len)
{
    std::memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}
