# NPM Binary Scanner

[![Test Action](https://github.com/Unknown-Cyber-Inc/npm-binary-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/Unknown-Cyber-Inc/npm-binary-scanner/actions/workflows/test.yml)

A GitHub Action and CLI tool that scans npm packages (`node_modules`) for binary executables like DLL, EXE, ELF, SO, and other binary files. It reports which packages contain binaries along with their version numbers, and can optionally upload them to UnknownCyber for security analysis.

## Why Scan for Binaries?

NPM packages can include pre-compiled native binaries and executable scripts. While often legitimate (e.g., `esbuild`, `sharp`), these pose unique security risks:

| Risk | Description |
|------|-------------|
| **Supply Chain Attacks** | Malicious binaries injected into popular packages can execute arbitrary code during `npm install` |
| **Invisible Threats** | Native code bypasses JavaScript-based security scanners |
| **License Compliance** | Native binaries may carry different licensing terms than the JavaScript wrapper |
| **Vulnerability Gaps** | Memory-unsafe languages (C/C++) can have vulnerabilities not caught by JS tooling |
| **Post-Install Scripts** | Scripts in `preinstall`/`postinstall` hooks can execute malware |

This tool helps you:
- **Audit** which packages contain native code
- **Upload** binaries to UnknownCyber for malware analysis
- **Monitor** known threats in your dependency tree
- **Alert** on suspicious or malicious files

## Features

- 🔍 **Comprehensive Detection**: Identifies binaries by file extension and magic bytes
- 📦 **Package Attribution**: Associates each binary with its parent npm package and version
- 🔄 **Handles Nested Dependencies**: Scans all direct and transitive dependencies  
- ☁️ **UnknownCyber Integration**: Upload binaries for malware analysis
- 🔒 **Smart Deduplication**: Skips files already in UnknownCyber to save time and bandwidth
- ⚠️ **Threat Detection**: Fetches and displays reputation data for existing files
- 🧬 **YARA Scanning**: Local pattern matching for malware and suspicious patterns
- 📊 **Detailed Reports**: JSON output with full scan results and threat assessments
- 🚀 **GitHub Action**: Easy CI/CD integration

## Quick Start

### As a GitHub Action

Add this to your workflow (`.github/workflows/scan-binaries.yml`):

```yaml
name: Scan NPM Binaries

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - run: npm ci
      
      - name: Scan binaries
        uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
        with:
          upload: 'true'
          api-key: ${{ secrets.UC_API_KEY }}
```

### As a CLI Tool

```bash
# Clone and run directly
git clone https://github.com/Unknown-Cyber-Inc/npm-binary-scanner.git
cd your-project
node path/to/npm-binary-scanner/scanner.js

# With upload
node scanner.js --upload --api-key YOUR_API_KEY
```

## GitHub Action

### Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scan-path` | Path to directory containing node_modules | No | `.` |
| `deep-scan` | Enable magic bytes detection (slower) | No | `false` |
| `upload` | Upload binaries to UnknownCyber | No | `false` |
| `skip-existing` | Skip files already in UnknownCyber | No | `true` |
| `get-reputations` | Fetch threat data for existing files | No | `true` |
| `api-url` | UnknownCyber API URL | No | `https://api.unknowncyber.com` |
| `api-key` | UnknownCyber API key | No | `''` |
| `repo` | Repository name to tag uploads with | No | `${{ github.repository }}` |
| `yara-scan` | Enable YARA scanning | No | `false` |
| `yara-rules` | Path to additional YARA rules | No | `''` |
| `yara-include` | File patterns for YARA (e.g., `*.js,*.html`) | No | `''` |

### Outputs

| Output | Description |
|--------|-------------|
| `total-packages` | Number of packages containing binaries |
| `total-binaries` | Total number of binary files found |
| `results-file` | Path to the JSON results file |
| `upload-successful` | Number of successfully uploaded files |
| `upload-failed` | Number of failed uploads |
| `upload-skipped` | Number of files skipped (already exist in UC) |
| `threats-found` | Number of files with HIGH or MEDIUM threat level |
| `yara-matches` | Number of files with YARA rule matches |
| `yara-high-severity` | Number of high/critical severity YARA matches |

### Examples

#### Basic Scan (No Upload)

```yaml
- name: Scan binaries
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  id: scan

- name: Report
  run: echo "Found ${{ steps.scan.outputs.total-binaries }} binaries"
```

#### Scan with Upload (Smart Deduplication)

```yaml
- name: Scan and upload binaries
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  id: scan
  with:
    upload: 'true'
    api-key: ${{ secrets.UC_API_KEY }}

- name: Check for threats
  if: steps.scan.outputs.threats-found > 0
  run: |
    echo "::warning::Found ${{ steps.scan.outputs.threats-found }} files with elevated threat levels!"
```

By default, the scanner will:
1. Compute SHA256 hashes of all binaries
2. Check which files already exist in UnknownCyber
3. Skip uploading existing files (saves time and bandwidth)
4. Fetch and display reputation/threat data for existing files
5. Warn about any HIGH or MEDIUM threat level files

#### Force Upload All Files

```yaml
- name: Force upload all binaries
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  with:
    upload: 'true'
    skip-existing: 'false'  # Upload even if file exists
    api-key: ${{ secrets.UC_API_KEY }}
```

#### Fast Scan (Skip Reputation Checks)

```yaml
- name: Quick scan and upload
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  with:
    upload: 'true'
    get-reputations: 'false'  # Don't fetch threat data for existing files
    api-key: ${{ secrets.UC_API_KEY }}
```

#### Deep Scan with Custom Path

```yaml
- name: Deep scan frontend
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  with:
    scan-path: './packages/frontend'
    deep-scan: 'true'
    upload: 'true'
    api-key: ${{ secrets.UC_API_KEY }}
```

#### Add Results to PR Summary

```yaml
- name: Scan binaries
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  id: scan
  with:
    upload: 'true'
    api-key: ${{ secrets.UC_API_KEY }}

- name: Add summary
  run: |
    echo "## Binary Scan Results" >> $GITHUB_STEP_SUMMARY
    echo "- Packages: ${{ steps.scan.outputs.total-packages }}" >> $GITHUB_STEP_SUMMARY
    echo "- Binaries: ${{ steps.scan.outputs.total-binaries }}" >> $GITHUB_STEP_SUMMARY
    echo "- Uploaded: ${{ steps.scan.outputs.upload-successful }}" >> $GITHUB_STEP_SUMMARY
    echo "- Skipped (existing): ${{ steps.scan.outputs.upload-skipped }}" >> $GITHUB_STEP_SUMMARY
    echo "- ⚠️ Threats found: ${{ steps.scan.outputs.threats-found }}" >> $GITHUB_STEP_SUMMARY
```

#### Fail on Threats Detected

```yaml
- name: Scan binaries
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  id: scan
  with:
    upload: 'true'
    api-key: ${{ secrets.UC_API_KEY }}

- name: Fail if threats found
  if: steps.scan.outputs.threats-found > 0
  run: |
    echo "::error::Security scan found ${{ steps.scan.outputs.threats-found }} files with HIGH or MEDIUM threat levels!"
    exit 1
```

## CLI Usage

### Command Line Options

```
node scanner.js [options] [path]

Options:
  --deep              Enable deep scan using magic bytes
  --upload            Upload found binaries to UnknownCyber API
  --force-upload      Upload all files even if they already exist in UC
  --no-reputations    Skip fetching reputation data for existing files
  --api-url <url>     API base URL (or set UC_API_URL env var)
  --api-key <key>     API key (or set UC_API_KEY env var)
  --repo <name>       Repository name for tagging (or set UC_REPO env var)
  --help, -h          Show help message
```

### Examples

```bash
# Scan current directory
node scanner.js

# Scan specific project
node scanner.js ./my-project

# Deep scan with magic byte detection
node scanner.js --deep

# Scan and upload (skips existing files by default)
node scanner.js --upload --api-url https://api.unknowncyber.com --api-key YOUR_KEY

# Force upload all files (ignore deduplication)
node scanner.js --upload --force-upload --api-key YOUR_KEY

# Fast upload without reputation checks
node scanner.js --upload --no-reputations --api-key YOUR_KEY

# Using environment variables
export UC_API_URL="https://api.unknowncyber.com"
export UC_API_KEY="your-api-key"
export UC_REPO="my-org/my-repo"
node scanner.js --upload
```

## How Deduplication Works

When uploading to UnknownCyber, the scanner performs smart deduplication:

```
┌─────────────────────────────────────────────────────────────┐
│  1. Scan node_modules for binaries                          │
│     └─> Found 150 executables                               │
│                                                             │
│  2. Compute SHA256 hashes                                   │
│     └─> Hashing [150/150]...                                │
│                                                             │
│  3. Check existing files in UnknownCyber                    │
│     └─> 120 already exist, 30 are new                       │
│                                                             │
│  4. Fetch reputation data for existing files                │
│     └─> HIGH: 2, MEDIUM: 5, LOW: 113                        │
│                                                             │
│  5. Upload only new files                                   │
│     └─> Uploading 30 new files...                           │
│                                                             │
│  6. Report threats                                          │
│     └─> ⚠ WARNING: 7 files with elevated threat levels!    │
└─────────────────────────────────────────────────────────────┘
```

This approach:
- **Saves bandwidth** by not re-uploading existing files
- **Saves time** by parallelizing hash lookups
- **Provides immediate insights** on known threats in your dependencies
- **Maintains history** by preserving existing analysis data

## Threat Levels

When reputation data is fetched, files are categorized by threat level:

| Level | Description | Action |
|-------|-------------|--------|
| **HIGH** | Known malware or high-confidence malicious | 🔴 Immediate investigation required |
| **MEDIUM** | Suspicious behavior or moderate risk | 🟠 Review recommended |
| **CAUTION** | Minor concerns or low-confidence detections | 🟡 Monitor |
| **LOW** | Minimal risk indicators | 🟢 Generally safe |
| **NONE** | No threats detected | ✅ Clean |
| **UNKNOWN** | Not enough data for assessment | ❓ Pending analysis |

Threat assessment is based on three factors:

### 1. Antivirus Results
Detection ratio from multiple AV engines (typically ~76 scanners):

| Detections | Level | Interpretation |
|------------|-------|----------------|
| ≥10% (8+/76) | HIGH | Serious concern - multiple engines agree |
| ≥5% (4-7/76) | MEDIUM | Needs attention |
| 2-3 detections | CAUTION | Worth investigating |
| 1 detection | LOW | Likely false positive |
| 0 detections | NONE | Clean |

### 2. Genomic Similarity
Code similarity to known malware families using UnknownCyber's genomic analysis:

| Condition | Level | Interpretation |
|-----------|-------|----------------|
| Exact clone of known malware (100% match) | HIGH | Binary is identical to known threat |
| Similar to known threats (<100% match) | MEDIUM | Shares code with malicious families |
| Similar files exist, none malicious | LOW | Matches found but no known threats |
| No similar files found | NONE | Unique or not in database |

### 3. Code Signing
Digital signature validity for Windows PE files:

| Signature Status | Level | Interpretation |
|------------------|-------|----------------|
| Signed but invalid | HIGH | Signature tampered, expired, or revoked - strong indicator of compromise |
| Unsigned | CAUTION | No authenticity guarantee - common for open-source binaries |
| Valid signature | NONE | Verified publisher identity |
| Unknown | UNKNOWN | Signature data unavailable |

### 4. YARA Pattern Matching
Local scanning using YARA rules to detect malware patterns:

| Severity (from rule metadata) | Level | Interpretation |
|------------------------------|-------|----------------|
| `critical` | HIGH | Known malware signatures, active threats |
| `high` | HIGH | Strong indicators of malicious behavior |
| `medium` | MEDIUM | Suspicious patterns worth investigating |
| `low` | LOW | Minor concerns, informational |

YARA results are reported via:
- `yara-matches` output: Total files with any YARA match
- `yara-high-severity` output: Files matching critical/high severity rules

#### Block Pipeline on YARA Matches

```yaml
- name: Scan with YARA
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  id: scan
  with:
    yara-scan: 'true'
    yara-include: '*.js'

- name: Fail on high-severity YARA matches
  if: steps.scan.outputs.yara-high-severity > 0
  run: |
    echo "::error::YARA detected ${{ steps.scan.outputs.yara-high-severity }} high-severity matches!"
    exit 1

- name: Fail on any YARA match
  if: steps.scan.outputs.yara-matches > 0
  run: |
    echo "::error::YARA detected matches in ${{ steps.scan.outputs.yara-matches }} files!"
    exit 1
```

## GitHub Actions Annotations

When running as a GitHub Action, the scanner automatically emits annotations based on threat analysis:

| Threat Level | Annotation Type | Visibility |
|--------------|-----------------|------------|
| **HIGH** | `::error::` | 🔴 Red error in checks, blocks PR merge (if required) |
| **MEDIUM** | `::warning::` | 🟡 Yellow warning in checks |
| **CAUTION** | `::notice::` | 🔵 Blue notice in checks |

Each annotation includes details about which reputation factor triggered it:

```
::error title=High Threat - AV::@malicious/pkg/evil.exe - AV Detection: 45/70 - malicious
::warning title=Medium Threat - Similarity::suspicious.dll - Suspicious similarity (15 similar files)
::notice title=Caution - Signature::unsigned.exe - Unsigned binary
```

These annotations appear in:
- **PR Checks** - Visible on pull request pages
- **Job Logs** - Inline with scanner output
- **Annotations Tab** - Summary view in Actions

### Automatic Tag Syncing

When files already exist in UnknownCyber, the scanner automatically syncs tags:
- Checks existing tags on each file
- Adds missing `SW_<package>_<version>` and `REPO_<repo>` tags
- Ensures consistent tagging across repositories

## YARA Scanning

The scanner includes optional YARA scanning to detect malware patterns and suspicious code in binaries and source files.

### Scan Binaries Only

```yaml
- name: Scan binaries with YARA
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  with:
    yara-scan: 'true'
```

### Scan JavaScript Files

Detect obfuscated malicious code in JS files (e.g., supply chain attacks):

```yaml
- name: Scan JS files with YARA
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  with:
    yara-scan: 'true'
    yara-include: '*.js'
```

### Scan Multiple File Types

```yaml
- name: Scan JS, HTML, and MJS files
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  with:
    yara-scan: 'true'
    yara-include: '*.js,*.html,*.mjs'
```

### Add Custom Rules

```yaml
- name: Scan with custom YARA rules
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  with:
    yara-scan: 'true'
    yara-rules: './my-rules'  # Path to your .yar files
```

### Bundled Rules

The scanner includes these YARA rule categories:

| Rule File | Description |
|-----------|-------------|
| `malware.yar` | Backdoors, info stealers, droppers, webshells, npm-specific malware |
| `suspicious.yar` | PowerShell cradles, Base64 execution, process injection, anti-debug |
| `crypto.yar` | Mining pools, XMRig, Coinhive, CPU/GPU miner patterns |
| `shai_hulud.yar` | Obfuscated JavaScript patterns (npm supply chain attacks) |

### YARA CLI Usage

```bash
# Scan binaries from results.json
python yara_scanner.py --input results.json

# Scan JavaScript files
python yara_scanner.py --dir ./node_modules --include "*.js"

# Scan multiple file types
python yara_scanner.py --dir ./node_modules --include "*.js" --include "*.html" --include "*.mjs"

# Scan all files in a directory
python yara_scanner.py --dir ./node_modules

# Use only custom rules (skip bundled)
python yara_scanner.py --dir ./node_modules --include "*.js" --rules ./my-rules --no-bundled-rules

# Output to file with GitHub annotations
python yara_scanner.py --input results.json --output yara.json --github-annotations
```

### YARA Results

YARA matches are reported with severity levels from rule metadata:

| Severity | Description | Annotation |
|----------|-------------|------------|
| **critical** | Known malware, active threats | 🔴 `::error::` |
| **high** | Strong indicators of malicious behavior | 🔴 `::error::` |
| **medium** | Suspicious patterns worth investigating | 🟡 `::warning::` |
| **low** | Minor concerns, informational | 🔵 `::notice::` |

### Fail on YARA Matches

```yaml
- name: Scan with YARA
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  id: scan
  with:
    yara-scan: 'true'

- name: Fail if malware detected
  if: steps.scan.outputs.yara-high-severity > 0
  run: |
    echo "::error::YARA detected ${{ steps.scan.outputs.yara-high-severity }} high-severity matches!"
    exit 1
```

## Detected Binary Types

| Platform | Extensions/Types |
|----------|-----------------|
| Windows | `.exe`, `.dll`, `.sys`, `.ocx`, `.com`, `.scr` |
| Linux/Unix | `.so`, `.o`, `.a`, ELF executables |
| macOS | `.dylib`, `.bundle`, Mach-O binaries |
| Node.js | `.node` (native addons) |
| WebAssembly | `.wasm` |
| General | `.bin`, `.dat` |

## Detected Script Types

Executable scripts are also detected as potential attack vectors:

| Platform | Extensions |
|----------|------------|
| Windows | `.bat`, `.cmd`, `.ps1`, `.vbs`, `.vbe`, `.wsf`, `.wsh` |
| Unix/Linux | `.sh`, `.bash`, `.zsh`, `.csh`, `.ksh` |
| Cross-platform | `.pl` (Perl), `.rb` (Ruby), `.py`, `.pyw` (Python) |

## Upload Details

When uploading to UnknownCyber, each executable is tagged with:

| Field | Format | Example |
|-------|--------|---------|
| **Filename** | Path below `node_modules` | `@esbuild/win32-x64/esbuild.exe` |
| **SHA256** | File hash | `e3b0c44298fc1c14...` |
| **Package Tag** | `SW_<package>_<version>` | `SW_@esbuild/win32-x64_0.20.2` |
| **Repo Tag** | `REPO_<owner>/<repo>` | `REPO_my-org/my-app` |

The repository tag helps identify which project the binary came from, useful when the same package version appears in multiple repositories.

## Setting Up the API Key

1. Get your API key from [UnknownCyber](https://unknowncyber.com)
2. Add it as a repository secret:
   - Go to your repo → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `UC_API_KEY`
   - Value: Your API key

## Output Files

The scanner produces a JSON report (`binary-scan-results.json`) containing:

```json
{
  "scanPath": "/path/to/node_modules",
  "scanDate": "2024-01-15T10:30:00.000Z",
  "totalPackages": 25,
  "totalExecutables": 150,
  "totalBinaries": 145,
  "totalScripts": 5,
  "packages": [...],
  "uploadResults": {
    "successful": [...],
    "failed": [...],
    "skipped": [...],
    "reputations": [
      {
        "file": "@esbuild/win32-x64/esbuild.exe",
        "sha256": "abc123...",
        "reputation": {
          "overallThreatLevel": "none",
          "antivirus": { "verdict": "clean", "detectionRatio": "0/70" },
          "similarity": { "hasMaliciousMatches": false },
          "signature": { "signatureStatus": "valid_signed" }
        }
      }
    ]
  }
}
```

## Common Packages with Binaries

Many popular npm packages include native binaries:

- **esbuild** - Fast JavaScript bundler
- **sharp** - Image processing
- **sqlite3** - SQLite database bindings
- **rollup** - Module bundler (native acceleration)
- **swc** - Rust-based JavaScript compiler
- **fsevents** - macOS file system events
- **sentry-cli** - Sentry command-line tool

## Requirements

- Node.js 18+ (for GitHub Action)
- Node.js 12+ (for CLI)
- Python 3.8+ with `yara-python` (for YARA scanning, optional)
- No other external dependencies

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
