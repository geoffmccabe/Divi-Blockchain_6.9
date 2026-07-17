/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

// Source:
// https://github.com/trezor/trezor-crypto

#include "bip39.h"
#include "bip39_english.h"
#include "crypto/sha256.h"
#include "random.h"

#include "crypto/hmac_sha512.h"
#include "crypto/cleanse.h"

#include <cstring>

SecureString CMnemonic::Generate(int strength)
{
    if (strength % 32 || strength < 128 || strength > 256) {
        return SecureString();
    }
    SecureVector data(32);
    GetStrongRandBytes(&data[0], 32);
    SecureString mnemonic = FromData(data, strength / 8);
    return mnemonic;
}

// SecureString CMnemonic::FromData(const uint8_t *data, int len)
SecureString CMnemonic::FromData(const SecureVector& data, int len)
{
    if (len % 4 || len < 16 || len > 32) {
        return SecureString();
    }

    SecureVector checksum(32);
    CSHA256().Write(&data[0], len).Finalize(&checksum[0]);

    // data
    SecureVector bits(len);
    memcpy(&bits[0], &data[0], len);
    // checksum
    bits.push_back(checksum[0]);

    int mlen = len * 3 / 4;
    SecureString mnemonic;

    int i, j, idx;
    for (i = 0; i < mlen; i++) {
        idx = 0;
        for (j = 0; j < 11; j++) {
            idx <<= 1;
            idx += (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
        }
        mnemonic.append(wordlist[idx]);
        if (i < mlen - 1) {
            mnemonic += ' ';
        }
    }

    return mnemonic;
}

bool CMnemonic::Check(SecureString mnemonic)
{
    if (mnemonic.empty()) {
        return false;
    }

    uint32_t nWordCount{};

    for (size_t i = 0; i < mnemonic.size(); ++i) {
        if (mnemonic[i] == ' ') {
            nWordCount++;
        }
    }
    nWordCount++;
    // check number of words
    if (nWordCount != 12 && nWordCount != 18 && nWordCount != 24) {
        return false;
    }

    SecureString ssCurrentWord;
    SecureVector bits(32 + 1);

    uint32_t nWordIndex, ki, nBitsCount{};

    for (size_t i = 0; i < mnemonic.size(); ++i)
    {
        ssCurrentWord = "";
        while (i + ssCurrentWord.size() < mnemonic.size() && mnemonic[i + ssCurrentWord.size()] != ' ') {
            if (ssCurrentWord.size() >= 9) {
                return false;
            }
            ssCurrentWord += mnemonic[i + ssCurrentWord.size()];
        }
        i += ssCurrentWord.size();
        nWordIndex = 0;
        for (;;) {
            if (!wordlist[nWordIndex]) { // word not found
                return false;
            }
            if (ssCurrentWord == wordlist[nWordIndex]) { // word found on index nWordIndex
                for (ki = 0; ki < 11; ki++) {
                    if (nWordIndex & (1 << (10 - ki))) {
                        bits[nBitsCount / 8] |= 1 << (7 - (nBitsCount % 8));
                    }
                    nBitsCount++;
                }
                break;
            }
            nWordIndex++;
        }
    }
    if (nBitsCount != nWordCount * 11) {
        return false;
    }
    bits[32] = bits[nWordCount * 4 / 3];
    CSHA256().Write(&bits[0], nWordCount * 4 / 3).Finalize(&bits[0]);

    bool fResult = 0;
    if (nWordCount == 12) {
        fResult = (bits[0] & 0xF0) == (bits[32] & 0xF0); // compare first 4 bits
    } else
    if (nWordCount == 18) {
        fResult = (bits[0] & 0xFC) == (bits[32] & 0xFC); // compare first 6 bits
    } else
    if (nWordCount == 24) {
        fResult = bits[0] == bits[32]; // compare 8 bits
    }

    return fResult;
}

// PBKDF2-HMAC-SHA512 using the in-tree HMAC (crypto/hmac_sha512). This matches
// OpenSSL's PKCS5_PBKDF2_HMAC(..., EVP_sha512()) byte-for-byte -- verified against
// the official BIP39 seed test vectors -- so existing seed phrases derive exactly
// the same keys as before.
static void PBKDF2_HMAC_SHA512(const unsigned char* pass, size_t pass_len,
                               const unsigned char* salt, size_t salt_len,
                               unsigned int iterations,
                               unsigned char* out, size_t dkLen)
{
    const size_t H = CHMAC_SHA512::OUTPUT_SIZE;
    unsigned char U[CHMAC_SHA512::OUTPUT_SIZE];
    unsigned char T[CHMAC_SHA512::OUTPUT_SIZE];
    unsigned int blocks = (unsigned int)((dkLen + H - 1) / H);
    for (unsigned int i = 1; i <= blocks; i++) {
        unsigned char ibe[4] = { (unsigned char)(i >> 24), (unsigned char)(i >> 16),
                                 (unsigned char)(i >> 8),  (unsigned char)i };
        CHMAC_SHA512(pass, pass_len).Write(salt, salt_len).Write(ibe, 4).Finalize(U);
        memcpy(T, U, H);
        for (unsigned int j = 1; j < iterations; j++) {
            CHMAC_SHA512(pass, pass_len).Write(U, H).Finalize(U);
            for (size_t k = 0; k < H; k++)
                T[k] ^= U[k];
        }
        size_t offset = (size_t)(i - 1) * H;
        size_t clen = dkLen - offset;
        if (clen > H)
            clen = H;
        memcpy(out + offset, T, clen);
    }
    memory_cleanse(U, sizeof(U));
    memory_cleanse(T, sizeof(T));
}

// passphrase must be at most 256 characters or code may crash
void CMnemonic::ToSeed(SecureString mnemonic, SecureString passphrase, SecureVector& seedRet)
{
    SecureString ssSalt = SecureString("mnemonic") + passphrase;
    SecureVector vchSalt(ssSalt.begin(), ssSalt.end());
    seedRet.resize(64);
    PBKDF2_HMAC_SHA512((const unsigned char*)mnemonic.c_str(), mnemonic.size(),
                       &vchSalt[0], vchSalt.size(), 2048, &seedRet[0], 64);
}
