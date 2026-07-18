// Copyright (c) 2026 The Divi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Regression tests for the wallet's AES-256-CBC encryption (CCrypter). This is
// the code path that was moved off OpenSSL onto the in-tree AES / key
// derivation. These tests lock in two things:
//   1. byte-for-byte compatibility with the previous OpenSSL output, so wallets
//      encrypted by older builds still decrypt (the KAT below was generated with
//      `openssl enc -aes-256-cbc`), and
//   2. round-trip correctness across the passphrase-derivation path.

// script/standard.h first: crypter.h -> keystore.h instantiates maps of
// CScript / CScriptID, which must be complete types at that point.
#include "script/script.h"
#include "script/standard.h"
#include "crypter.h"
#include "utilstrencodings.h"

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(crypter_tests)

static CKeyingMaterial ToKeying(const std::string& s)
{
    return CKeyingMaterial(s.begin(), s.end());
}

// Byte-exact known-answer test: a fixed key + IV + plaintext must produce
// exactly the ciphertext OpenSSL's aes-256-cbc (PKCS7 padding) produced for the
// same inputs. If the in-tree AES ever diverged from OpenSSL, this fails --
// which would mean existing encrypted wallets could no longer be opened.
BOOST_AUTO_TEST_CASE(crypter_openssl_byte_compat_kat)
{
    std::vector<unsigned char> key = ParseHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    std::vector<unsigned char> iv = ParseHex("000102030405060708090a0b0c0d0e0f");

    CCrypter crypt;
    CKeyingMaterial keyMat(key.begin(), key.end());
    BOOST_CHECK(crypt.SetKey(keyMat, iv));

    CKeyingMaterial plain = ToKeying("Divi wallet crypter KAT");
    std::vector<unsigned char> cipher;
    BOOST_CHECK(crypt.Encrypt(plain, cipher));
    BOOST_CHECK_EQUAL(
        HexStr(cipher),
        "e28528f6071123c2abd84276f3da36231d33c40fc48ff6870a9ed9cd744684fa");

    CKeyingMaterial recovered;
    BOOST_CHECK(crypt.Decrypt(cipher, recovered));
    BOOST_CHECK(recovered == plain);
}

// The passphrase path (BytesToKeySHA512AES, formerly OpenSSL's EVP_BytesToKey)
// must round-trip at every plaintext length, including the block boundaries.
BOOST_AUTO_TEST_CASE(crypter_passphrase_roundtrip)
{
    std::vector<unsigned char> salt = ParseHex("0102030405060708");
    // Start at 1: CCrypter::Decrypt reports a zero-length result as failure, so
    // an empty plaintext is a degenerate case that never occurs for key material.
    for (size_t len = 1; len <= 64; ++len) {
        CCrypter crypt;
        BOOST_CHECK(crypt.SetKeyFromPassphrase(
            "correct horse battery staple", salt, 1000, 0));

        CKeyingMaterial plain(len, static_cast<unsigned char>(len & 0xff));
        std::vector<unsigned char> cipher;
        BOOST_CHECK(crypt.Encrypt(plain, cipher));

        CKeyingMaterial recovered;
        BOOST_CHECK(crypt.Decrypt(cipher, recovered));
        BOOST_CHECK(recovered == plain);
    }
}

// Same passphrase/salt/rounds must derive the same key (deterministic), and a
// different passphrase must not recover the plaintext.
BOOST_AUTO_TEST_CASE(crypter_determinism_and_wrong_key)
{
    std::vector<unsigned char> salt = ParseHex("a1a2a3a4a5a6a7a8");
    CKeyingMaterial plain = ToKeying("master key material");

    CCrypter a, b, wrong;
    BOOST_CHECK(a.SetKeyFromPassphrase("passphrase-one", salt, 2048, 0));
    BOOST_CHECK(b.SetKeyFromPassphrase("passphrase-one", salt, 2048, 0));
    BOOST_CHECK(wrong.SetKeyFromPassphrase("passphrase-two", salt, 2048, 0));

    std::vector<unsigned char> ca, cb;
    BOOST_CHECK(a.Encrypt(plain, ca));
    BOOST_CHECK(b.Encrypt(plain, cb));
    BOOST_CHECK(ca == cb); // deterministic derivation

    CKeyingMaterial recovered;
    if (wrong.Decrypt(ca, recovered)) // may fail padding, or give garbage
        BOOST_CHECK(recovered != plain);
}

BOOST_AUTO_TEST_SUITE_END()
