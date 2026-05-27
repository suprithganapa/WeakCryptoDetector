/*
 * ============================================================
 *  test_target.cpp  –  Target application
 *  Course  : Cryptography and Network Security
 *
 *  Intentionally uses weak cryptographic algorithms via the
 *  Windows CryptoAPI (advapi32) and BCrypt API (bcrypt) so
 *  the Pin tool can detect and report them.
 *
 *  Algorithms exercised (weak):
 *    MD5, SHA-1, MD4, DES, RC4, RC2
 *  Algorithms exercised (strong – for contrast):
 *    SHA-256, AES-256
 *
 *  Compile (VS Developer Command Prompt – x64):
 *    cl /EHsc /W3 test_target.cpp /link advapi32.lib bcrypt.lib
 * ============================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

/* ── helpers ── */
static void PrintHex(const char* label, const BYTE* data, DWORD len)
{
    printf("  %-10s : ", label);
    for (DWORD i = 0; i < len; ++i)
        printf("%02X", data[i]);
    printf("\n");
}

static const char* PLAINTEXT = "Hello, Cryptography and Network Security!";

/* ================================================================
 *  Section A  –  Windows Legacy CryptoAPI  (advapi32.dll)
 *                Uses CryptCreateHash which our Pin tool hooks.
 * ================================================================ */
static void RunLegacyCryptoAPI(void)
{
    printf("\n[A] Windows Legacy CryptoAPI (advapi32)\n");
    printf("    Plaintext: \"%s\"\n\n", PLAINTEXT);

    /* algorithms to test:  { ALG_ID, display-name, expected-flag } */
    struct Entry { ALG_ID id; const char* name; const char* flag; };
    static const Entry ALGOS[] = {
        { CALG_MD2,      "MD2",       "BROKEN"  },
        { CALG_MD4,      "MD4",       "BROKEN"  },
        { CALG_MD5,      "MD5",       "BROKEN"  },
        { CALG_SHA1,     "SHA-1",     "WEAK"    },
        { CALG_SHA_256,  "SHA-256",   "STRONG"  },
        { 0, NULL, NULL }
    };

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL,
                               PROV_RSA_AES,
                               CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "  CryptAcquireContext failed: 0x%08X\n",
                GetLastError());
        return;
    }

    for (int i = 0; ALGOS[i].name; ++i) {
        HCRYPTHASH hHash = 0;
        /* ← Pin tool intercepts this call */
        if (!CryptCreateHash(hProv, ALGOS[i].id, 0, 0, &hHash)) {
            fprintf(stderr,
                    "  CryptCreateHash(%s) failed: 0x%08X\n",
                    ALGOS[i].name, GetLastError());
            continue;
        }

        CryptHashData(hHash,
                      (const BYTE*)PLAINTEXT,
                      (DWORD)strlen(PLAINTEXT), 0);

        BYTE   digest[64] = {0};
        DWORD  digestLen  = sizeof(digest);
        CryptGetHashParam(hHash, HP_HASHVAL, digest, &digestLen, 0);

        printf("  [%s] %s  -> ", ALGOS[i].flag, ALGOS[i].name);
        for (DWORD b = 0; b < digestLen; ++b)
            printf("%02X", digest[b]);
        printf("\n");

        CryptDestroyHash(hHash);
    }

    CryptReleaseContext(hProv, 0);
}

/* ================================================================
 *  Section B  –  Windows BCrypt API  (bcrypt.dll)
 *                Uses BCryptOpenAlgorithmProvider which our
 *                Pin tool also hooks.
 * ================================================================ */
static void HashWithBCrypt(LPCWSTR algId, const char* label)
{
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD hashLen = 0, tmp = 0;
    PBYTE  hashObj  = NULL;
    PBYTE  hashVal  = NULL;
    DWORD  objLen   = 0;
    NTSTATUS st;

    /* ← Pin tool intercepts this call */
    st = BCryptOpenAlgorithmProvider(&hAlg, algId,
                                     MS_PRIMITIVE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(st)) {
        fprintf(stderr, "  BCryptOpenAlgorithmProvider(%ls) failed: 0x%X\n",
                algId, (unsigned)st);
        return;
    }

    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                      (PBYTE)&objLen, sizeof(DWORD), &tmp, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                      (PBYTE)&hashLen, sizeof(DWORD), &tmp, 0);

    hashObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, objLen);
    hashVal = (PBYTE)HeapAlloc(GetProcessHeap(), 0, hashLen);

    BCryptCreateHash(hAlg, &hHash, hashObj, objLen, NULL, 0, 0);
    BCryptHashData(hHash, (PUCHAR)PLAINTEXT,
                   (ULONG)strlen(PLAINTEXT), 0);
    BCryptFinishHash(hHash, hashVal, hashLen, 0);

    printf("  %s  -> ", label);
    for (DWORD b = 0; b < hashLen; ++b) printf("%02X", hashVal[b]);
    printf("\n");

    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    HeapFree(GetProcessHeap(), 0, hashObj);
    HeapFree(GetProcessHeap(), 0, hashVal);
}

static void RunBCryptAPI(void)
{
    printf("\n[B] Windows BCrypt API (bcrypt.dll)\n");
    printf("    Plaintext: \"%s\"\n\n", PLAINTEXT);

    /* WEAK / BROKEN */
    HashWithBCrypt(BCRYPT_MD5_ALGORITHM,    "[BROKEN]  MD5   ");
    HashWithBCrypt(BCRYPT_SHA1_ALGORITHM,   "[WEAK  ]  SHA-1 ");
    /* STRONG (for contrast) */
    HashWithBCrypt(BCRYPT_SHA256_ALGORITHM, "[STRONG]  SHA-256");
    HashWithBCrypt(BCRYPT_SHA512_ALGORITHM, "[STRONG]  SHA-512");
}

/* ================================================================
 *  Section C  –  Symmetric cipher (RC4 via CryptoAPI)
 *                RC4 is weak; AES-256 shown for comparison.
 * ================================================================ */
static void RunRC4(HCRYPTPROV hProv)
{
    printf("\n[C] Symmetric cipher – RC4 (weak) via CryptoAPI\n");

    /* derive a key from a password using MD5 (doubly weak!) */
    HCRYPTHASH hHash = 0;
    CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    const char* password = "weakpassword123";
    CryptHashData(hHash, (const BYTE*)password,
                  (DWORD)strlen(password), 0);

    HCRYPTKEY hKey = 0;
    if (!CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &hKey)) {
        fprintf(stderr, "  CryptDeriveKey(RC4) failed: 0x%08X\n",
                GetLastError());
        CryptDestroyHash(hHash);
        return;
    }

    char buf[256];
    strncpy_s(buf, PLAINTEXT, _TRUNCATE);
    DWORD bufLen = (DWORD)strlen(buf);

    CryptEncrypt(hKey, 0, TRUE, 0, (BYTE*)buf, &bufLen, sizeof(buf));
    printf("  RC4 cipher-text (hex): ");
    for (DWORD i = 0; i < bufLen; ++i) printf("%02X", (unsigned char)buf[i]);
    printf("\n");

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
}

/* ================================================================
 *  Section D  –  DES  via CryptoAPI  (56-bit key = broken)
 * ================================================================ */
static void RunDES(HCRYPTPROV hProv)
{
    printf("\n[D] Symmetric cipher – DES (broken) via CryptoAPI\n");

    HCRYPTHASH hHash = 0;
    CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
    const char* password = "deskey";
    CryptHashData(hHash, (const BYTE*)password,
                  (DWORD)strlen(password), 0);

    HCRYPTKEY hKey = 0;
    /* CALG_DES  requires PROV_RSA_FULL or PROV_RSA_AES */
    if (!CryptDeriveKey(hProv, CALG_DES, hHash, 0, &hKey)) {
        /* DES may not be available on modern Windows – that is OK */
        DWORD err = GetLastError();
        printf("  DES key derivation skipped (err=0x%08X) "
               "– DES may be disabled on this OS.\n", err);
        CryptDestroyHash(hHash);
        return;
    }

    char buf[64];
    strncpy_s(buf, "DESplaintext", _TRUNCATE);
    DWORD bufLen = (DWORD)strlen(buf);

    CryptEncrypt(hKey, 0, TRUE, 0, (BYTE*)buf, &bufLen, sizeof(buf));
    printf("  DES cipher-text (hex): ");
    for (DWORD i = 0; i < bufLen; ++i) printf("%02X", (unsigned char)buf[i]);
    printf("\n");

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
}

/* ================================================================
 *  main
 * ================================================================ */
int main(void)
{
    printf("============================================================\n");
    printf("  Test Target – Weak Crypto Usage Demo\n");
    printf("  CNS Mini-Project\n");
    printf("============================================================\n");

    RunLegacyCryptoAPI();
    RunBCryptAPI();

    /* acquire a full context for symmetric tests */
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextW(&hProv, NULL, NULL,
                              PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT)) {
        RunRC4(hProv);
        RunDES(hProv);
        CryptReleaseContext(hProv, 0);
    }

    printf("\n============================================================\n");
    printf("  Done. Check weak_crypto_report.txt for Pin tool output.\n");
    printf("============================================================\n");
    return 0;
}
