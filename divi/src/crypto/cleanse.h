// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2024 The Divi Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_CLEANSE_H
#define BITCOIN_CRYPTO_CLEANSE_H

#include <stdlib.h>

// Secure overwrite of a memory buffer that will not be optimized away by the
// compiler. In-tree replacement for OpenSSL's OPENSSL_cleanse().
void memory_cleanse(void* ptr, size_t len);

#endif // BITCOIN_CRYPTO_CLEANSE_H
