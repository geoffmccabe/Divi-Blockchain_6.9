// Known-answer vector checks for the in-tree crypto that replaced OpenSSL.
//
// These pin the crypto-critical replacements to official test vectors so their
// correctness is permanent and re-runnable, not resting on a code comment.
// Covered:
//   - CSHA256                 (powers hash.h Hash() and scrypt's HMAC)      -> FIPS/NIST "abc"
//   - PBKDF2-HMAC-SHA256      (crypto/scrypt.cpp, exported PBKDF2_SHA256)   -> RFC-style vectors
//   - PBKDF2-HMAC-SHA512      (the algorithm bip39.cpp uses for seeds)      -> official BIP39 vector
//   - AES-256 single block    (crypto/aes.h, used by bip38.cpp/crypter)     -> FIPS-197 C.3
//
// This file is intentionally standalone (not wired into the automake test
// target) so it needs no Boost/GMock. Build + run from divi/src/ with:
//
//   c++ -std=c++11 -I. \
//       crypto/sha256.cpp crypto/sha512.cpp crypto/hmac_sha512.cpp \
//       crypto/scrypt.cpp crypto/aes.cpp crypto/ctaes/ctaes.c \
//       test/openssl_removal_vectors.cpp -o /tmp/divi_vectors && /tmp/divi_vectors
//
// Exit code 0 = all vectors pass. TODO(follow-up): fold into the Boost.Test suite.

#include "crypto/sha256.h"
#include "crypto/hmac_sha512.h"
#include "crypto/aes.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

extern void PBKDF2_SHA256(const uint8_t* passwd, size_t passwdlen, const uint8_t* salt,
                          size_t saltlen, uint64_t c, uint8_t* buf, size_t dkLen);

// PBKDF2-HMAC-SHA512 exactly as bip39.cpp implements it (over the in-tree HMAC).
static void PBKDF2_HMAC_SHA512(const unsigned char* pass, size_t pass_len,
                               const unsigned char* salt, size_t salt_len,
                               unsigned int iterations, unsigned char* out, size_t dkLen)
{
    const size_t H = CHMAC_SHA512::OUTPUT_SIZE;
    unsigned char U[CHMAC_SHA512::OUTPUT_SIZE], T[CHMAC_SHA512::OUTPUT_SIZE];
    unsigned int blocks = (unsigned int)((dkLen + H - 1) / H);
    for (unsigned int i = 1; i <= blocks; i++) {
        unsigned char ibe[4] = {(unsigned char)(i >> 24), (unsigned char)(i >> 16),
                                (unsigned char)(i >> 8), (unsigned char)i};
        CHMAC_SHA512(pass, pass_len).Write(salt, salt_len).Write(ibe, 4).Finalize(U);
        memcpy(T, U, H);
        for (unsigned int j = 1; j < iterations; j++) {
            CHMAC_SHA512(pass, pass_len).Write(U, H).Finalize(U);
            for (size_t k = 0; k < H; k++) T[k] ^= U[k];
        }
        size_t off = (size_t)(i - 1) * H, clen = dkLen - off;
        if (clen > H) clen = H;
        memcpy(out + off, T, clen);
    }
}

static int check(const char* name, const unsigned char* got, int n, const char* expectHex)
{
    char hex[257];
    for (int i = 0; i < n; i++) sprintf(hex + 2 * i, "%02x", got[i]);
    int ok = strcmp(hex, expectHex) == 0;
    printf("%-34s %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) printf("   got %s\n   exp %s\n", hex, expectHex);
    return ok ? 0 : 1;
}

int main()
{
    int fails = 0;
    unsigned char b[64];

    // SHA-256("abc")
    CSHA256().Write((const unsigned char*)"abc", 3).Finalize(b);
    fails += check("SHA256(abc)", b, 32,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // PBKDF2-HMAC-SHA256 (scrypt's rewritten HMAC), c=1 and c=2
    PBKDF2_SHA256((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 1, b, 32);
    fails += check("PBKDF2-HMAC-SHA256 c=1", b, 32,
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    PBKDF2_SHA256((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 2, b, 32);
    fails += check("PBKDF2-HMAC-SHA256 c=2", b, 32,
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");

    // BIP39 seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048, 64)
    const char* mn = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    PBKDF2_HMAC_SHA512((const unsigned char*)mn, strlen(mn),
                       (const unsigned char*)"mnemonicTREZOR", 14, 2048, b, 64);
    fails += check("BIP39 seed (abandon.../TREZOR)", b, 64,
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a698"
        "7599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");

    // AES-256 single block, FIPS-197 Appendix C.3
    unsigned char key[32], pt[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                                     0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff}, ct[16];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
    AES256Encrypt(key).Encrypt(ct, pt);
    fails += check("AES-256 encrypt (FIPS-197)", ct, 16, "8ea2b7ca516745bfeafc49904b496089");
    unsigned char rt[16];
    AES256Decrypt(key).Decrypt(rt, ct);
    fails += check("AES-256 decrypt round-trip", rt, 16, "00112233445566778899aabbccddeeff");

    printf("\n%s\n", fails ? ">>> SOME VECTORS FAILED" : ">>> ALL VECTORS PASS");
    return fails;
}
