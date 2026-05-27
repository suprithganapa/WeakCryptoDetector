# Weak Cryptographic Usage Detector Using Intel PinTool

**Course:** Cryptography and Network Security  
**Technique:** Dynamic Binary Instrumentation (DBI)  
**Platform:** Windows 10/11 (x64)  
**Tools:** Intel Pin, Visual Studio, VS Code

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [How It Works](#2-how-it-works)
3. [Project Structure](#3-project-structure)
4. [Prerequisites](#4-prerequisites)
5. [Step-by-Step Setup](#5-step-by-step-setup)
6. [Building the Project](#6-building-the-project)
7. [Running the Analysis](#7-running-the-analysis)
8. [Understanding the Output](#8-understanding-the-output)
9. [Extending the Tool](#9-extending-the-tool)
10. [Theory & Algorithm Details](#10-theory--algorithm-details)

---

## 1. Project Overview

This project implements a **runtime detector for weak cryptographic algorithms** using Intel's Pin dynamic binary instrumentation framework.

Instead of scanning source code (static analysis), the tool runs **alongside a live application** and intercepts cryptographic API calls in real time — no source code required.

### Algorithms Detected

| Algorithm | Type   | Status  | Why Weak |
|-----------|--------|---------|----------|
| MD2       | Hash   | BROKEN  | Collisions trivially found |
| MD4       | Hash   | BROKEN  | Fully broken, fast collisions |
| MD5       | Hash   | BROKEN  | Collisions found in seconds (Wang 2004) |
| SHA-1     | Hash   | WEAK    | SHAttered collision attack (2017) |
| DES       | Cipher | BROKEN  | 56-bit key, brute-forced in < 24h |
| 3DES      | Cipher | WEAK    | Sweet32 birthday attack, < 112-bit |
| RC2       | Cipher | WEAK    | Small effective key size |
| RC4       | Cipher | WEAK    | NOMORE attack, WEP/SSL broken |

### Detection Vectors

1. **Windows CryptoAPI hook** — intercepts `CryptCreateHash(hProv, ALG_ID, …)` in `advapi32.dll`
2. **BCrypt API hook** — intercepts `BCryptOpenAlgorithmProvider(…, L"MD5", …)` in `bcrypt.dll`
3. **OpenSSL / static library symbol scan** — finds routines named `MD5_Init`, `SHA1_Init`, `DES_ecb_encrypt`, etc.
4. **Generic symbol-name scan** — flags any routine containing keywords like `MD5`, `SHA1`, `RC4`, `DES_`, `BLOWFISH`

---

## 2. How It Works

```
┌─────────────────────────────────────────────┐
│              Intel Pin Framework             │
│  ┌──────────────┐    ┌──────────────────┐   │
│  │  JIT Compiler│───▶│  Instrumented    │   │
│  │  (Pin core)  │    │  Code Cache      │   │
│  └──────────────┘    └──────────────────┘   │
│         ▲                    │               │
│         │                    ▼               │
│  ┌──────────────┐    ┌──────────────────┐   │
│  │  Target App  │    │  Analysis        │   │
│  │  test_target │    │  Callbacks       │   │
│  │  .exe        │    │  (our Pin tool)  │   │
│  └──────────────┘    └──────────────────┘   │
└─────────────────────────────────────────────┘
         │
         ▼
  weak_crypto_report.txt
```

**Flow:**
1. Pin loads the target application
2. Before executing each image (DLL/EXE), our `ImageLoad` callback fires
3. We hook `CryptCreateHash`, `BCryptOpenAlgorithmProvider`, and any routine whose name matches weak-crypto keywords
4. When the target calls these functions, our analysis callbacks run and log the detection
5. On exit, a summary report is written

---

## 3. Project Structure

```
WeakCryptoDetector/
│
├── pintool/
│   ├── weak_crypto_detector.cpp   ← The Pin tool (DLL)
│   ├── Makefile                   ← nmake build file
│   └── build_pintool.bat          ← One-click build script
│
├── test_target/
│   ├── test_target.cpp            ← Demo app using weak crypto
│   └── build_target.bat           ← One-click build script
│
├── .vscode/
│   ├── tasks.json                 ← VS Code build tasks
│   └── c_cpp_properties.json     ← IntelliSense config
│
├── run_analysis.bat               ← Run Pin + tool + target
└── README.md                      ← This file
```

---

## 4. Prerequisites

### 4.1 Visual Studio (required for MSVC compiler)

1. Download **Visual Studio Community 2022** (free):  
   https://visualstudio.microsoft.com/downloads/

2. During installation, select the workload:  
   ☑ **Desktop development with C++**

3. Make sure these components are checked:  
   ☑ MSVC v143 (or later) C++ x64/x86 build tools  
   ☑ Windows 11 SDK (or Windows 10 SDK)

### 4.2 Intel Pin

1. Go to:  
   https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html

2. Download the **Windows** version (latest, e.g. Pin 3.31)

3. Extract the ZIP to `C:\pin`  
   (The folder should contain `pin.exe` directly at `C:\pin\pin.exe`)

4. Verify: open Command Prompt and run:
   ```
   C:\pin\pin.exe -help
   ```
   You should see Pin's help message.

### 4.3 VS Code

1. Download from https://code.visualstudio.com/

2. Install the **C/C++ extension** by Microsoft:  
   Open VS Code → Extensions (Ctrl+Shift+X) → search "C/C++" → Install

---

## 5. Step-by-Step Setup

### Step 1 – Get the project

Option A – if you received a ZIP: extract it to `C:\Users\<you>\WeakCryptoDetector\`

Option B – create the folder manually:
```
mkdir C:\Users\<you>\WeakCryptoDetector
mkdir C:\Users\<you>\WeakCryptoDetector\pintool
mkdir C:\Users\<you>\WeakCryptoDetector\test_target
mkdir C:\Users\<you>\WeakCryptoDetector\.vscode
```
Then copy each file into the matching sub-folder.

### Step 2 – Open in VS Code

```
File → Open Folder → select WeakCryptoDetector\
```

You should see the folder tree in the Explorer panel.

### Step 3 – Verify `PIN_ROOT` path

Open `pintool\build_pintool.bat` and `run_analysis.bat`.  
Confirm line:
```batch
set "PIN_ROOT=C:\pin"
```
If you extracted Pin elsewhere, update this path.

### Step 4 – Open a VS x64 Developer Command Prompt

> **Why?** The MSVC compiler (`cl.exe`) must be on your PATH.

Start menu → search for **"x64 Native Tools Command Prompt for VS 2022"** → open it.

Navigate to your project:
```
cd C:\Users\<you>\WeakCryptoDetector
```

---

## 6. Building the Project

### 6.1 Build the Test Target

From the VS x64 Command Prompt:
```batch
cd test_target
build_target.bat
```

Expected output:
```
[INFO] VS environment activated.
[INFO] Compiling test_target.cpp ...
test_target.cpp
[SUCCESS] test_target.exe built!
```

Or using VS Code: **Terminal → Run Task → 1 – Build Test Target**

### 6.2 Build the Pin Tool

```batch
cd ..\pintool
build_pintool.bat
```

Expected output:
```
[INFO] Building WeakCryptoDetector.dll ...
[INFO] PIN_ROOT = C:\pin
weak_crypto_detector.cpp
Creating library weak_crypto_detector.lib ...
[SUCCESS] weak_crypto_detector.dll built successfully!
```

Or using VS Code: **Terminal → Run Task → 2 – Build Pin Tool**

---

## 7. Running the Analysis

From the project root:
```batch
run_analysis.bat
```

Or using VS Code: **Terminal → Run Task → 3 – Run Analysis**

### What happens

```
pin.exe  -t  pintool\weak_crypto_detector.dll
         -o  weak_crypto_report.txt
         --  test_target\test_target.exe
```

You will see live output like:

```
========================================
  Weak Crypto Detector – Pin Tool
  CNS Mini Project
========================================
[IMAGE] Loaded: C:\Windows\System32\ntdll.dll
[IMAGE] Loaded: C:\Windows\System32\advapi32.dll
[HOOK]  CryptCreateHash in advapi32.dll
[HOOK]  BCryptOpenAlgorithmProvider in bcrypt.dll

[DETECTED] Source=CryptCreateHash(advapi32)  Algorithm=MD2  Strength=BROKEN  Detail=ALG_ID=0x00008001
[DETECTED] Source=CryptCreateHash(advapi32)  Algorithm=MD4  Strength=BROKEN  Detail=ALG_ID=0x00008002
[DETECTED] Source=CryptCreateHash(advapi32)  Algorithm=MD5  Strength=BROKEN  Detail=ALG_ID=0x00008003
[DETECTED] Source=CryptCreateHash(advapi32)  Algorithm=SHA-1  Strength=WEAK  Detail=ALG_ID=0x00008004
[DETECTED] Source=BCryptOpenAlgorithmProvider(bcrypt)  Algorithm=MD5  Strength=WEAK/BROKEN
[DETECTED] Source=BCryptOpenAlgorithmProvider(bcrypt)  Algorithm=SHA-1  Strength=WEAK/BROKEN

============================================================
  WEAK CRYPTO DETECTION SUMMARY
============================================================
  Algorithm        | Invocations
  ----------------------------------------
  MD2              | 1
  MD4              | 1
  MD5              | 3
  SHA-1            | 2
  DES              | 1
  RC4              | 1
============================================================
```

---

## 8. Understanding the Output

### Detection lines

```
[DETECTED] Source=<where detected>  Algorithm=<name>  Strength=<level>  Detail=<extra info>
```

| Field       | Meaning |
|-------------|---------|
| `Source`    | Which hook fired (CryptoAPI, BCrypt, symbol scan) |
| `Algorithm` | The weak algorithm name |
| `Strength`  | `BROKEN` (do not use) or `WEAK` (avoid if possible) |
| `Detail`    | ALG_ID hex code, return address, or symbol name |

### Static symbol lines

```
[STATIC-SYMBOL] Image=somelib.dll  Routine=MD5_Update  Algorithm=MD5  Strength=BROKEN
```
This means the linked binary contains a symbol named `MD5_Update` — the library was compiled with MD5 support, even if it hasn't been called yet.

### Report file

`weak_crypto_report.txt` contains the full log. Submit this with your project.

---

## 9. Extending the Tool

### Add a new algorithm to detect

In `weak_crypto_detector.cpp`, add a row to `WIN_ALGO_TABLE[]`:
```cpp
{ 0x0000XXXX, "YourAlgo", "BROKEN" },
```
And/or add a keyword to `WEAK_KEYWORDS[]`:
```cpp
{ "YOURLIB_FUNC_PREFIX", "YourAlgo", "BROKEN" },
```

### Analyse a real application

Replace `test_target\test_target.exe` with any real `.exe`:
```batch
C:\pin\pin.exe -t pintool\weak_crypto_detector.dll -o report.txt -- "C:\path\to\app.exe"
```

Examples of real apps you can test:
- WinSCP (older versions use MD5 for fingerprinting)
- Git for Windows (SHA-1 is used for object IDs — interesting!)
- Any legacy application that uses WinCrypt

### Verbose mode

```batch
C:\pin\pin.exe -t pintool\weak_crypto_detector.dll -o report.txt -v 1 -- test_target.exe
```

This also logs every image load and every strong-algorithm call.

---

## 10. Theory & Algorithm Details

### Why MD5 is broken

MD5 produces a 128-bit digest. In 2004, Wang et al. demonstrated a **collision attack** — two different inputs that produce the same MD5 hash — feasible in minutes on a laptop. This breaks its core property (collision resistance).

**Real-world impact:** Flame malware (2012) forged Microsoft code-signing certificates using MD5 collisions.

### Why SHA-1 is weak

SHA-1 produces a 160-bit digest. In 2017, Google's Project Zero and CWI Amsterdam published the **SHAttered** attack: the first practical SHA-1 collision (two different PDFs with the same SHA-1 hash). Cost: ~$75,000 of cloud compute.

**Real-world impact:** Git historically uses SHA-1 for object IDs (migrating to SHA-256).

### Why DES is broken

DES uses a 56-bit key — only 2^56 ≈ 72 quadrillion possible keys. In 1998, the EFF's **Deep Crack** machine brute-forced DES in 56 hours for under $250,000. Today a GPU cluster can do it in hours.

### Why RC4 is weak

RC4 has **statistical biases** in its keystream — certain bytes appear more often than random. The **NOMORE attack** (2015) exploits this to recover plaintext. It was already banned from TLS 1.3 and caused many WEP Wi-Fi vulnerabilities.

### Dynamic Binary Instrumentation (DBI)

DBI instruments a binary **at runtime without modifying the executable on disk**. The Pin framework:

1. Reads and JIT-recompiles basic blocks of target code
2. Inserts "analysis calls" (our callbacks) before/after selected instructions or function entries
3. Executes the instrumented code in a sandboxed environment

This approach works on **closed-source, obfuscated, and packed binaries** where static analysis fails.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `pin.exe not found` | Check `PIN_ROOT` path in `build_pintool.bat` and `run_analysis.bat` |
| `cl.exe not found` | Run from **x64 Native Tools Command Prompt for VS** |
| DLL build fails with LNK errors | Verify Pin version matches the paths in `Makefile` (intel64 vs ia32) |
| No detections in report | Make sure `test_target.exe` was built and runs on its own first |
| `CryptCreateHash failed: 0x80090008` | Normal — MD2/MD4 may be disabled on modern Windows; detection still fires |

---

*Project by: CNS Student — Intel Pin Dynamic Binary Instrumentation*
