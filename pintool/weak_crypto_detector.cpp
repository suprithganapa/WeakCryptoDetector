/*
 * ============================================================
 *  WeakCryptoDetector.cpp  –  Intel Pin Tool
 *  Course  : Cryptography and Network Security
 *
 *  Detects usage of weak cryptographic algorithms at runtime:
 *    • Windows CryptoAPI  (advapi32.dll  – CryptCreateHash)
 *    • BCrypt API         (bcrypt.dll    – BCryptOpenAlgorithmProvider)
 *    • OpenSSL symbols    (MD5_Init, SHA1_Init, …)
 *    • Symbol-name scan   (any routine whose name contains a
 *                          weak-algorithm keyword)
 *
 *  Output  : weak_crypto_report.txt  (and stdout)
 * ============================================================
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <set>
#include <algorithm>
#include <cctype>

/* ── output file ── */
static std::ofstream ReportFile;

/* ── knobs (command-line switches) ── */
KNOB<std::string> KnobOutputFile(
    KNOB_MODE_WRITEONCE, "pintool",
    "o", "weak_crypto_report.txt",
    "Output report file name");

KNOB<BOOL> KnobVerbose(
    KNOB_MODE_WRITEONCE, "pintool",
    "v", "0",
    "Enable verbose logging");

/* ── statistics ── */
static std::map<std::string, UINT64> DetectionCount;
static std::set<std::string>         ReportedImages;

/* ================================================================
 *  Windows CryptoAPI  ALG_ID  constants
 * ================================================================ */
struct AlgEntry { UINT32 id; const char* name; const char* strength; };

static const AlgEntry WIN_ALGO_TABLE[] = {
    /* WEAK / BROKEN */
    { 0x00008001, "MD2",       "BROKEN"  },
    { 0x00008002, "MD4",       "BROKEN"  },
    { 0x00008003, "MD5",       "BROKEN"  },
    { 0x00008004, "SHA-1",     "WEAK"    },
    { 0x00006601, "DES",       "BROKEN"  },
    { 0x00006602, "RC2",       "WEAK"    },
    { 0x00006801, "RC4",       "WEAK"    },
    { 0x00006603, "3DES-112",  "WEAK"    },
    { 0x00006609, "3DES",      "WEAK"    },
    /* ACCEPTABLE / STRONG (logged but not flagged as weak) */
    { 0x0000800c, "SHA-256",   "STRONG"  },
    { 0x0000800d, "SHA-384",   "STRONG"  },
    { 0x0000800e, "SHA-512",   "STRONG"  },
    { 0x00006610, "AES-128",   "STRONG"  },
    { 0x00006611, "AES-192",   "STRONG"  },
    { 0x00006612, "AES-256",   "STRONG"  },
    { 0,          nullptr,     nullptr   }
};

/* ── lookup Windows ALG_ID → name + strength ── */
static bool LookupWinAlg(UINT32 algId,
                          std::string& outName,
                          std::string& outStrength)
{
    for (int i = 0; WIN_ALGO_TABLE[i].name; ++i) {
        if (WIN_ALGO_TABLE[i].id == algId) {
            outName     = WIN_ALGO_TABLE[i].name;
            outStrength = WIN_ALGO_TABLE[i].strength;
            return true;
        }
    }
    outName     = "UNKNOWN(0x" + std::to_string(algId) + ")";
    outStrength = "UNKNOWN";
    return false;
}

/* ── is a given ALG_ID considered weak? ── */
static bool IsWeakWinAlg(UINT32 algId)
{
    std::string n, s;
    LookupWinAlg(algId, n, s);
    return (s == "BROKEN" || s == "WEAK");
}

/* ================================================================
 *  BCrypt provider name  →  strength
 * ================================================================ */
static bool IsWeakBCryptAlgo(const std::wstring& name)
{
    /* BCrypt uses wide-char algorithm strings */
    static const wchar_t* WEAK_LIST[] = {
        L"MD2", L"MD4", L"MD5", L"SHA1",
        L"DES", L"RC2", L"RC4", L"3DES",
        nullptr
    };
    std::wstring up = name;
    std::transform(up.begin(), up.end(), up.begin(), ::towupper);
    for (int i = 0; WEAK_LIST[i]; ++i)
        if (up.find(WEAK_LIST[i]) != std::wstring::npos)
            return true;
    return false;
}

/* ================================================================
 *  Emit a detection record
 * ================================================================ */
static void Emit(const std::string& source,
                 const std::string& algo,
                 const std::string& strength,
                 const std::string& detail)
{
    std::string line =
        "[DETECTED] Source=" + source +
        "  Algorithm=" + algo +
        "  Strength=" + strength +
        "  Detail=" + detail;

    std::cout << line << "\n";
    if (ReportFile.is_open())
        ReportFile << line << "\n";

    DetectionCount[algo]++;
}

/* ================================================================
 *  Analysis callback: CryptCreateHash  (advapi32.dll)
 *
 *  BOOL CryptCreateHash(
 *      HCRYPTPROV hProv,
 *      ALG_ID     Algid,    ← arg 2 (index 1)
 *      HCRYPTKEY  hKey,
 *      DWORD      dwFlags,
 *      HCRYPTHASH *phHash);
 * ================================================================ */
static VOID PIN_FAST_ANALYSIS_CALL
AnalyseCryptCreateHash(ADDRINT algId, ADDRINT retAddr)
{
    std::string name, strength;
    LookupWinAlg((UINT32)algId, name, strength);

    std::string detail =
        "ALG_ID=0x" + [&](){
            char buf[12];
            snprintf(buf, sizeof(buf), "%08X", (unsigned)algId);
            return std::string(buf);
        }() +
        " RetAddr=0x" + [&](){
            char buf[20];
            snprintf(buf, sizeof(buf), "%p", (void*)retAddr);
            return std::string(buf);
        }();

    if (strength == "BROKEN" || strength == "WEAK") {
        Emit("CryptCreateHash(advapi32)", name, strength, detail);
    } else if (KnobVerbose) {
        std::cout << "[INFO] CryptCreateHash – strong algo: "
                  << name << "\n";
    }
}

/* ================================================================
 *  Analysis callback: BCryptOpenAlgorithmProvider  (bcrypt.dll)
 *
 *  NTSTATUS BCryptOpenAlgorithmProvider(
 *      BCRYPT_ALG_HANDLE *phAlgorithm,
 *      LPCWSTR            pszAlgId,   ← arg 2 (index 1)
 *      LPCWSTR            pszImplementation,
 *      ULONG              dwFlags);
 * ================================================================ */
static VOID PIN_FAST_ANALYSIS_CALL
AnalyseBCryptOpenAlgo(ADDRINT pszAlgId, ADDRINT retAddr)
{
    if (!pszAlgId) return;

    /* read the wide-char string from the target process */
    const wchar_t* wptr = reinterpret_cast<const wchar_t*>(pszAlgId);
    std::wstring algName;
    try {
        for (int i = 0; i < 64 && wptr[i]; ++i)
            algName += wptr[i];
    } catch (...) { return; }

    std::string narrow(algName.begin(), algName.end());

    if (IsWeakBCryptAlgo(algName)) {
        Emit("BCryptOpenAlgorithmProvider(bcrypt)",
             narrow, "WEAK/BROKEN",
             "AlgString=" + narrow);
    } else if (KnobVerbose) {
        std::cout << "[INFO] BCryptOpenAlgorithmProvider – algo: "
                  << narrow << "\n";
    }
}

/* ================================================================
 *  Analysis callback: generic OpenSSL-style entry point
 *  (called for MD5_Init, SHA1_Init, DES_*, RC4_*, etc.)
 * ================================================================ */
static VOID PIN_FAST_ANALYSIS_CALL
AnalyseOpenSSLWeak(const char* funcName, ADDRINT retAddr)
{
    Emit("OpenSSL/library symbol",
         funcName, "WEAK/BROKEN",
         "DirectCallToWeakRoutine");
}

/* ================================================================
 *  Keyword table used for symbol-name scanning
 * ================================================================ */
struct KeyEntry { const char* keyword; const char* algo; const char* strength; };

static const KeyEntry WEAK_KEYWORDS[] = {
    { "MD5",    "MD5",    "BROKEN" },
    { "SHA1",   "SHA-1",  "WEAK"   },
    { "SHA_1",  "SHA-1",  "WEAK"   },
    { "MD4",    "MD4",    "BROKEN" },
    { "MD2",    "MD2",    "BROKEN" },
    { "_DES_",  "DES",    "BROKEN" },
    { "DES_",   "DES",    "BROKEN" },
    { "_RC4",   "RC4",    "WEAK"   },
    { "RC4_",   "RC4",    "WEAK"   },
    { "_RC2",   "RC2",    "WEAK"   },
    { "RC2_",   "RC2",    "WEAK"   },
    { "3DES",   "3DES",   "WEAK"   },
    { "BLOWFISH","Blowfish","WEAK"  },
    { nullptr,  nullptr,  nullptr  }
};

/* ── upper-case a std::string in-place ── */
static std::string ToUpper(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

/* ── check if routine name contains a weak-crypto keyword ── */
static bool NameContainsWeakKeyword(const std::string& name,
                                    std::string& outAlgo,
                                    std::string& outStrength)
{
    std::string up = ToUpper(name);
    for (int i = 0; WEAK_KEYWORDS[i].keyword; ++i) {
        if (up.find(WEAK_KEYWORDS[i].keyword) != std::string::npos) {
            outAlgo     = WEAK_KEYWORDS[i].algo;
            outStrength = WEAK_KEYWORDS[i].strength;
            return true;
        }
    }
    return false;
}

/* ================================================================
 *  Image-load callback  – instrument every image as it is loaded
 * ================================================================ */
static VOID ImageLoad(IMG img, VOID* /*v*/)
{
    std::string imgName = IMG_Name(img);

    /* ── deduplicate image reports ── */
    if (ReportedImages.find(imgName) == ReportedImages.end()) {
        ReportedImages.insert(imgName);
        std::string msg = "[IMAGE] Loaded: " + imgName;
        if (KnobVerbose) std::cout << msg << "\n";
        if (ReportFile.is_open()) ReportFile << msg << "\n";
    }

    /* ── 1. Hook CryptCreateHash ── */
    RTN rtn = RTN_FindByName(img, "CryptCreateHash");
    if (RTN_Valid(rtn)) {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE,
                       (AFUNPTR)AnalyseCryptCreateHash,
                       IARG_FAST_ANALYSIS_CALL,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,   /* Algid */
                       IARG_RETURN_IP,
                       IARG_END);
        RTN_Close(rtn);
        if (KnobVerbose)
            std::cout << "[HOOK] CryptCreateHash in " << imgName << "\n";
    }

    /* ── 2. Hook BCryptOpenAlgorithmProvider ── */
    rtn = RTN_FindByName(img, "BCryptOpenAlgorithmProvider");
    if (RTN_Valid(rtn)) {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE,
                       (AFUNPTR)AnalyseBCryptOpenAlgo,
                       IARG_FAST_ANALYSIS_CALL,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,   /* pszAlgId */
                       IARG_RETURN_IP,
                       IARG_END);
        RTN_Close(rtn);
        if (KnobVerbose)
            std::cout << "[HOOK] BCryptOpenAlgorithmProvider in "
                      << imgName << "\n";
    }

    /* ── 3. Scan every routine by name for weak keywords ── */
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN r = SEC_RtnHead(sec); RTN_Valid(r); r = RTN_Next(r)) {
            std::string rname = RTN_Name(r);
            std::string algo, strength;

            if (NameContainsWeakKeyword(rname, algo, strength)) {
                /* emit a static detection (found in symbol table) */
                std::string staticMsg =
                    "[STATIC-SYMBOL] Image=" + imgName +
                    "  Routine=" + rname +
                    "  Algorithm=" + algo +
                    "  Strength=" + strength;
                std::cout << staticMsg << "\n";
                if (ReportFile.is_open())
                    ReportFile << staticMsg << "\n";
                DetectionCount[algo]++;

                /* also instrument calls to it at runtime */
                RTN_Open(r);
                RTN_InsertCall(r, IPOINT_BEFORE,
                               (AFUNPTR)AnalyseOpenSSLWeak,
                               IARG_FAST_ANALYSIS_CALL,
                               IARG_PTR, RTN_Name(r).c_str(),
                               IARG_RETURN_IP,
                               IARG_END);
                RTN_Close(r);
            }
        }
    }
}

/* ================================================================
 *  Fini callback  – print summary when the process exits
 * ================================================================ */
static VOID Fini(INT32 /*code*/, VOID* /*v*/)
{
    std::string sep(60, '=');
    std::string summary;
    summary  = "\n" + sep + "\n";
    summary += "  WEAK CRYPTO DETECTION SUMMARY\n";
    summary += sep + "\n";

    if (DetectionCount.empty()) {
        summary += "  No weak cryptographic usage detected.\n";
    } else {
        summary += "  Algorithm        | Invocations\n";
        summary += "  " + std::string(40, '-') + "\n";
        for (auto& kv : DetectionCount) {
            char line[80];
            snprintf(line, sizeof(line),
                     "  %-16s | %llu\n",
                     kv.first.c_str(),
                     (unsigned long long)kv.second);
            summary += line;
        }
    }
    summary += sep + "\n";

    std::cout << summary;
    if (ReportFile.is_open()) {
        ReportFile << summary;
        ReportFile.close();
    }
}

/* ================================================================
 *  Usage  (shown with  pin -t weak_crypto_detector.dll -- -help)
 * ================================================================ */
static INT32 Usage()
{
    std::cerr
        << "WeakCryptoDetector – Intel Pin Tool\n"
        << "  Detects runtime usage of weak crypto algorithms.\n\n"
        << KNOB_BASE::StringKnobSummary() << "\n";
    return -1;
}

/* ================================================================
 *  main
 * ================================================================ */
int main(int argc, char* argv[])
{
    /* initialise symbol table (needed for RTN_FindByName) */
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
        return Usage();

    /* open report file */
    ReportFile.open(KnobOutputFile.Value().c_str());
    if (!ReportFile.is_open())
        std::cerr << "[WARN] Cannot open report file "
                  << KnobOutputFile.Value() << " – using stdout only\n";

    std::string header =
        "========================================\n"
        "  Weak Crypto Detector – Pin Tool\n"
        "  CNS Mini Project\n"
        "========================================\n";
    std::cout << header;
    if (ReportFile.is_open()) ReportFile << header;

    /* register callbacks */
    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);

    /* never returns */
    PIN_StartProgram();
    return 0;
}
