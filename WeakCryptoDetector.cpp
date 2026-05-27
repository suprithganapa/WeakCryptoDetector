/*
 * ============================================================
 *  WeakCryptoDetector.cpp
 *  Course  : Cryptography and Network Security
 *
 *  Dynamic Binary Analysis tool using Windows Debug API.
 *  Monitors a target process and detects weak cryptographic
 *  algorithm usage by setting breakpoints on:
 *    - CryptCreateHash     (advapi32.dll)
 *    - BCryptOpenAlgorithmProvider (bcrypt.dll)
 *
 *  Weak algorithms detected:
 *    MD2, MD4, MD5, SHA-1, DES, RC4, RC2, 3DES
 *
 *  Compile (from VS x64 Build Tools Command Prompt):
 *    cl /nologo /EHsc /W3 WeakCryptoDetector.cpp /link advapi32.lib /OUT:WeakCryptoDetector.exe
 *
 *  Usage:
 *    WeakCryptoDetector.exe <target.exe> [args...]
 * ============================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <string>
#include <vector>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

/* ── report file ── */
static FILE* gReport = NULL;

/* ── detection counter ── */
static std::map<std::string, int> gDetections;

/* ── breakpoint record ── */
struct Breakpoint {
    LPVOID  address;
    BYTE    originalByte;
    std::string name;
    bool    active;
};

static std::vector<Breakpoint> gBreakpoints;
static HANDLE gProcess = NULL;

/* ================================================================
 *  Windows CryptoAPI ALG_ID table
 * ================================================================ */
struct AlgInfo { DWORD id; const char* name; const char* strength; };

static const AlgInfo ALG_TABLE[] = {
    { 0x8001, "MD2",     "BROKEN"  },
    { 0x8002, "MD4",     "BROKEN"  },
    { 0x8003, "MD5",     "BROKEN"  },
    { 0x8004, "SHA-1",   "WEAK"    },
    { 0x6601, "DES",     "BROKEN"  },
    { 0x6602, "RC2",     "WEAK"    },
    { 0x6801, "RC4",     "WEAK"    },
    { 0x6603, "3DES-112","WEAK"    },
    { 0x6609, "3DES",    "WEAK"    },
    { 0x800c, "SHA-256", "STRONG"  },
    { 0x800d, "SHA-384", "STRONG"  },
    { 0x800e, "SHA-512", "STRONG"  },
    { 0x6610, "AES-128", "STRONG"  },
    { 0x6611, "AES-192", "STRONG"  },
    { 0x6612, "AES-256", "STRONG"  },
    { 0,      NULL,      NULL      }
};

static const char* GetAlgName(DWORD id) {
    for (int i = 0; ALG_TABLE[i].name; i++)
        if (ALG_TABLE[i].id == id) return ALG_TABLE[i].name;
    return "UNKNOWN";
}

static const char* GetAlgStrength(DWORD id) {
    for (int i = 0; ALG_TABLE[i].name; i++)
        if (ALG_TABLE[i].id == id) return ALG_TABLE[i].strength;
    return "UNKNOWN";
}

static bool IsWeakAlg(DWORD id) {
    const char* s = GetAlgStrength(id);
    return (strcmp(s, "BROKEN") == 0 || strcmp(s, "WEAK") == 0);
}

/* ================================================================
 *  Emit detection
 * ================================================================ */
static void Emit(const char* source, const char* algo,
                 const char* strength, const char* detail)
{
    printf("[DETECTED] Source=%-35s Algorithm=%-10s Strength=%-8s Detail=%s\n",
           source, algo, strength, detail);
    if (gReport)
        fprintf(gReport,
                "[DETECTED] Source=%-35s Algorithm=%-10s Strength=%-8s Detail=%s\n",
                source, algo, strength, detail);
    gDetections[algo]++;
}

/* ================================================================
 *  Set a software breakpoint (INT3) at address
 * ================================================================ */
static bool SetBreakpoint(HANDLE hProcess, LPVOID addr,
                           const char* name)
{
    BYTE orig = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, addr, &orig, 1, &read) || read != 1)
        return false;

    BYTE int3 = 0xCC;
    SIZE_T written = 0;
    DWORD oldProt = 0;
    VirtualProtectEx(hProcess, addr, 1, PAGE_EXECUTE_READWRITE, &oldProt);
    WriteProcessMemory(hProcess, addr, &int3, 1, &written);
    VirtualProtectEx(hProcess, addr, 1, oldProt, &oldProt);
    FlushInstructionCache(hProcess, addr, 1);

    Breakpoint bp;
    bp.address      = addr;
    bp.originalByte = orig;
    bp.name         = name;
    bp.active       = true;
    gBreakpoints.push_back(bp);

    printf("[HOOK] Breakpoint set on %s at %p\n", name, addr);
    if (gReport)
        fprintf(gReport, "[HOOK] Breakpoint set on %s at %p\n", name, addr);
    return true;
}

/* ================================================================
 *  Restore original byte after breakpoint hit
 * ================================================================ */
static void RestoreBreakpointByte(HANDLE hProcess, Breakpoint& bp)
{
    DWORD oldProt = 0;
    VirtualProtectEx(hProcess, bp.address, 1,
                     PAGE_EXECUTE_READWRITE, &oldProt);
    WriteProcessMemory(hProcess, bp.address,
                       &bp.originalByte, 1, NULL);
    VirtualProtectEx(hProcess, bp.address, 1, oldProt, &oldProt);
    FlushInstructionCache(hProcess, bp.address, 1);
}

/* ================================================================
 *  Re-set breakpoint after single-step
 * ================================================================ */
static void ReSetBreakpoint(HANDLE hProcess, Breakpoint& bp)
{
    BYTE int3 = 0xCC;
    DWORD oldProt = 0;
    VirtualProtectEx(hProcess, bp.address, 1,
                     PAGE_EXECUTE_READWRITE, &oldProt);
    WriteProcessMemory(hProcess, bp.address, &int3, 1, NULL);
    VirtualProtectEx(hProcess, bp.address, 1, oldProt, &oldProt);
    FlushInstructionCache(hProcess, bp.address, 1);
    bp.active = true;
}

/* ── pending single-step info ── */
static LPVOID gPendingRestoreAddr = NULL;
static int    gPendingRestoreIdx  = -1;

/* ================================================================
 *  Find module base in target process
 * ================================================================ */
static LPVOID GetModuleBaseInProcess(HANDLE hProcess,
                                      const char* modName)
{
    HMODULE mods[1024];
    DWORD   needed = 0;
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed))
        return NULL;

    DWORD count = needed / sizeof(HMODULE);
    char  name[MAX_PATH];
    for (DWORD i = 0; i < count; i++) {
        GetModuleBaseNameA(hProcess, mods[i], name, sizeof(name));
        if (_stricmp(name, modName) == 0)
            return (LPVOID)mods[i];
    }
    return NULL;
}

/* ================================================================
 *  Install breakpoints once DLLs are loaded
 * ================================================================ */
static void TryInstallBreakpoints(HANDLE hProcess, HANDLE hThread)
{
    /* ── CryptCreateHash in advapi32.dll ── */
    LPVOID advBase = GetModuleBaseInProcess(hProcess, "advapi32.dll");
    if (advBase) {
        HMODULE hLocal = LoadLibraryA("advapi32.dll");
        if (hLocal) {
            LPVOID localFn = (LPVOID)GetProcAddress(hLocal, "CryptCreateHash");
            if (localFn) {
                LPVOID remoteFn = (LPVOID)((BYTE*)advBase +
                    ((BYTE*)localFn - (BYTE*)hLocal));
                /* check not already set */
                bool already = false;
                for (auto& b : gBreakpoints)
                    if (b.address == remoteFn) { already = true; break; }
                if (!already)
                    SetBreakpoint(hProcess, remoteFn, "CryptCreateHash");
            }
            FreeLibrary(hLocal);
        }
    }

    /* ── BCryptOpenAlgorithmProvider in bcrypt.dll ── */
    LPVOID bcBase = GetModuleBaseInProcess(hProcess, "bcrypt.dll");
    if (bcBase) {
        HMODULE hLocal = LoadLibraryA("bcrypt.dll");
        if (hLocal) {
            LPVOID localFn = (LPVOID)GetProcAddress(
                hLocal, "BCryptOpenAlgorithmProvider");
            if (localFn) {
                LPVOID remoteFn = (LPVOID)((BYTE*)bcBase +
                    ((BYTE*)localFn - (BYTE*)hLocal));
                bool already = false;
                for (auto& b : gBreakpoints)
                    if (b.address == remoteFn) { already = true; break; }
                if (!already)
                    SetBreakpoint(hProcess, remoteFn,
                                  "BCryptOpenAlgorithmProvider");
            }
            FreeLibrary(hLocal);
        }
    }
}

/* ================================================================
 *  Handle breakpoint hit
 * ================================================================ */
static void HandleBreakpoint(HANDLE hProcess, HANDLE hThread,
                              LPVOID addr, int bpIdx)
{
    Breakpoint& bp = gBreakpoints[bpIdx];

    /* ── x64: args in RCX, RDX, R8, R9 ── */
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &ctx);

    /* Step back one byte (INT3 is 1 byte) */
    ctx.Rip--;

    if (bp.name == "CryptCreateHash") {
        /* arg2 = ALG_ID = RDX */
        DWORD algId = (DWORD)(ctx.Rdx);
        const char* name     = GetAlgName(algId);
        const char* strength = GetAlgStrength(algId);
        char detail[64];
        snprintf(detail, sizeof(detail), "ALG_ID=0x%04X", algId);

        if (IsWeakAlg(algId)) {
            Emit("CryptCreateHash(advapi32.dll)",
                 name, strength, detail);
        } else {
            printf("[INFO] CryptCreateHash – strong algo: %s\n", name);
        }
    }
    else if (bp.name == "BCryptOpenAlgorithmProvider") {
        /* arg2 = pszAlgId = RDX (wide string pointer) */
        LPVOID wptr = (LPVOID)(ctx.Rdx);
        wchar_t wbuf[64] = {0};
        SIZE_T  read = 0;
        ReadProcessMemory(hProcess, wptr, wbuf, sizeof(wbuf)-2, &read);
        wbuf[63] = 0;

        /* convert to narrow */
        char narrow[64] = {0};
        WideCharToMultiByte(CP_ACP, 0, wbuf, -1,
                            narrow, sizeof(narrow)-1, NULL, NULL);

        /* check against weak list */
        std::string up = narrow;
        std::transform(up.begin(), up.end(), up.begin(), ::toupper);
        bool weak = (up.find("MD5")  != std::string::npos ||
                     up.find("MD4")  != std::string::npos ||
                     up.find("MD2")  != std::string::npos ||
                     up.find("SHA1") != std::string::npos ||
                     up.find("DES")  != std::string::npos ||
                     up.find("RC4")  != std::string::npos ||
                     up.find("RC2")  != std::string::npos);

        if (weak) {
            Emit("BCryptOpenAlgorithmProvider(bcrypt.dll)",
                 narrow, "WEAK/BROKEN",
                 ("AlgString=" + std::string(narrow)).c_str());
        } else {
            printf("[INFO] BCryptOpenAlgorithmProvider – strong algo: %s\n",
                   narrow);
        }
    }

    /* Restore original byte, enable single-step to re-set */
    RestoreBreakpointByte(hProcess, bp);
    bp.active = false;

    ctx.EFlags |= 0x100; /* Trap Flag = single step */
    SetThreadContext(hThread, &ctx);

    gPendingRestoreAddr = bp.address;
    gPendingRestoreIdx  = bpIdx;
}

/* ================================================================
 *  Print summary report
 * ================================================================ */
static void PrintSummary(void)
{
    const char* sep =
        "============================================================\n";
    printf("\n%s", sep);
    printf("  WEAK CRYPTO DETECTION SUMMARY\n");
    printf("%s", sep);

    if (gDetections.empty()) {
        printf("  No weak cryptographic usage detected.\n");
    } else {
        printf("  %-16s | Detections\n", "Algorithm");
        printf("  %s\n", std::string(40,'-').c_str());
        for (auto& kv : gDetections)
            printf("  %-16s | %d\n", kv.first.c_str(), kv.second);
    }
    printf("%s\n", sep);

    if (gReport) {
        fprintf(gReport, "\n%s", sep);
        fprintf(gReport, "  WEAK CRYPTO DETECTION SUMMARY\n");
        fprintf(gReport, "%s", sep);
        if (gDetections.empty()) {
            fprintf(gReport, "  No weak cryptographic usage detected.\n");
        } else {
            fprintf(gReport, "  %-16s | Detections\n", "Algorithm");
            for (auto& kv : gDetections)
                fprintf(gReport, "  %-16s | %d\n",
                        kv.first.c_str(), kv.second);
        }
        fprintf(gReport, "%s\n", sep);
    }
}

/* ================================================================
 *  main
 * ================================================================ */
int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage: WeakCryptoDetector.exe <target.exe> [args...]\n"
            "Example: WeakCryptoDetector.exe test_target.exe\n");
        return 1;
    }

    /* open report file */
    gReport = fopen("weak_crypto_report.txt", "w");
    if (!gReport)
        fprintf(stderr, "[WARN] Cannot open report file\n");

    printf("============================================================\n");
    printf("  Weak Crypto Detector – Dynamic Analysis Tool\n");
    printf("  CNS Mini Project\n");
    printf("============================================================\n\n");

    /* build command line */
    char cmdLine[4096] = {0};
    for (int i = 1; i < argc; i++) {
        if (i > 1) strcat_s(cmdLine, " ");
        strcat_s(cmdLine, argv[i]);
    }

    /* create target process suspended in debug mode */
    STARTUPINFOA        si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                        NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[ERROR] Cannot launch target: %s (err=%u)\n",
                cmdLine, GetLastError());
        return 1;
    }

    gProcess = pi.hProcess;
    printf("[INFO] Target launched: %s  PID=%u\n\n", cmdLine, pi.dwProcessId);

    /* ── debug event loop ── */
    DEBUG_EVENT evt = {};
    bool running    = true;
    bool bpsInstalled = false;
    int  bpRetryCount = 0;

    while (running) {
        if (!WaitForDebugEvent(&evt, 1000)) {
            /* timeout – try installing breakpoints if not done */
            if (!bpsInstalled && bpRetryCount++ < 10) {
                TryInstallBreakpoints(pi.hProcess, pi.hThread);
                /* check if we got any */
                if (!gBreakpoints.empty()) bpsInstalled = true;
            }
            ContinueDebugEvent(evt.dwProcessId,
                               evt.dwThreadId, DBG_CONTINUE);
            continue;
        }

        DWORD continueStatus = DBG_CONTINUE;

        switch (evt.dwDebugEventCode) {

        case CREATE_PROCESS_DEBUG_EVENT: {
            printf("[INFO] Process created.\n");
            /* small delay then install breakpoints */
            Sleep(200);
            TryInstallBreakpoints(pi.hProcess, pi.hThread);
            if (!gBreakpoints.empty()) bpsInstalled = true;
            CloseHandle(evt.u.CreateProcessInfo.hFile);
            break;
        }

        case LOAD_DLL_DEBUG_EVENT: {
            /* try installing after each DLL load */
            Sleep(50);
            if (!bpsInstalled) {
                TryInstallBreakpoints(pi.hProcess, pi.hThread);
                if (!gBreakpoints.empty()) bpsInstalled = true;
            } else {
                /* always try — new DLL might be advapi/bcrypt */
                size_t before = gBreakpoints.size();
                TryInstallBreakpoints(pi.hProcess, pi.hThread);
            }
            if (evt.u.LoadDll.hFile)
                CloseHandle(evt.u.LoadDll.hFile);
            break;
        }

        case EXCEPTION_DEBUG_EVENT: {
            DWORD code = evt.u.Exception.ExceptionRecord.ExceptionCode;
            LPVOID addr = evt.u.Exception.ExceptionRecord.ExceptionAddress;

            if (code == EXCEPTION_BREAKPOINT) {
                /* check if it's one of our breakpoints */
                int bpIdx = -1;
                for (int i = 0; i < (int)gBreakpoints.size(); i++) {
                    if (gBreakpoints[i].address == addr &&
                        gBreakpoints[i].active) {
                        bpIdx = i;
                        break;
                    }
                }

                if (bpIdx >= 0) {
                    /* get thread handle */
                    HANDLE hThread = OpenThread(
                        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                        THREAD_QUERY_INFORMATION,
                        FALSE, evt.dwThreadId);
                    HandleBreakpoint(pi.hProcess, hThread, addr, bpIdx);
                    CloseHandle(hThread);
                } else if (evt.u.Exception.dwFirstChance) {
                    /* initial system breakpoint — ignore */
                    continueStatus = DBG_CONTINUE;
                } else {
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            else if (code == EXCEPTION_SINGLE_STEP) {
                /* re-set our breakpoint after single step */
                if (gPendingRestoreIdx >= 0) {
                    ReSetBreakpoint(pi.hProcess,
                                    gBreakpoints[gPendingRestoreIdx]);
                    gPendingRestoreIdx  = -1;
                    gPendingRestoreAddr = NULL;
                }
            }
            else {
                if (evt.u.Exception.dwFirstChance)
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT:
            printf("\n[INFO] Target process exited (code=%u).\n",
                   evt.u.ExitProcess.dwExitCode);
            running = false;
            break;

        default:
            break;
        }

        ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continueStatus);
    }

    PrintSummary();

    if (gReport) {
        fclose(gReport);
        printf("[INFO] Report written to: weak_crypto_report.txt\n");
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
