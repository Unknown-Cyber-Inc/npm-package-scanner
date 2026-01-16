# UC Software Scan

[![Test Action](https://github.com/Unknown-Cyber-Inc/uc-software-scan/actions/workflows/test.yml/badge.svg)](https://github.com/Unknown-Cyber-Inc/uc-software-scan/actions/workflows/test.yml)

A GitHub Action and CLI tool that scans software packages for security threats. It **auto-detects** installed packages from multiple ecosystems (npm, pip, Maven, Cargo, Go, Ruby, NuGet, dpkg, apk, rpm), finds binary executables and scripts, then uploads them to UnknownCyber for multi-layer threat analysis including AV scanning, genomic similarity, and SBOM tracking.

## Supported Ecosystems

| Ecosystem | Package Directory | Metadata Source | Tag Format |
|-----------|------------------|-----------------|------------|
| **npm** | `node_modules/` | `package.json` | `SW_npm/pkg_version` |
| **pip** | `site-packages/` | `*.dist-info/METADATA` | `SW_pip/pkg_version` |
| **Maven** | `.m2/repository/`, `lib/` | `pom.xml` or path | `SW_maven/group:artifact_version` |
| **Cargo** | `target/release/` | `Cargo.toml` | `SW_cargo/pkg_version` |
| **Go** | `vendor/`, `pkg/mod/` | `go.mod` | `SW_go/module_version` |
| **Ruby** | `vendor/bundle/` | `*.gemspec` | `SW_ruby/gem_version` |
| **NuGet** | `packages/` | `*.nuspec` | `SW_nuget/pkg_version` |
| **dpkg** | `/usr/lib/` | `/var/lib/dpkg/status` | `SW_dpkg/pkg_version` |
| **apk** | `/usr/lib/`, `/lib/` | `/lib/apk/db/installed` | `SW_apk/pkg_version` |
| **rpm** | `/usr/lib64/` | `/var/lib/rpm/` | `SW_rpm/pkg_version` |

The scanner **automatically detects** which ecosystems are present after your build/install step—no configuration required.

## Why Scan Package Binaries?

Packages can include pre-compiled native binaries and executable scripts. While often legitimate (e.g., `esbuild`, `sharp`, `numpy`), these pose unique security risks:

| Risk | Description |
|------|-------------|
| **Supply Chain Attacks** | Malicious binaries injected into popular packages can execute arbitrary code during build, install, or other dev stages |
| **Invisible Threats** | Native code bypasses JavaScript-based security scanners |
| **License Compliance** | Native binaries may carry different licensing terms than the JavaScript wrapper |
| **Vulnerability Gaps** | Memory-unsafe languages (C/C++) can have vulnerabilities not caught by JS tooling |
| **Post-Install Scripts** | Scripts in `preinstall`/`postinstall` hooks can execute malware |
| **Regulatory Compliance** | SBOM requirements (EO 14028, NTIA) demand visibility into all software components |

## Security Analysis

This tool performs multiple layers of security analysis to detect threats that traditional scanners miss:

### 🦠 Antivirus Detection

Files are scanned by **70+ antivirus engines** via UnknownCyber. This multi-engine approach catches threats that any single AV might miss, providing comprehensive malware detection with minimal false negatives.

| Detection Ratio | Threat Level | Action |
|-----------------|--------------|--------|
| ≥10% of engines | 🔴 HIGH | Block pipeline, immediate investigation |
| ≥1% of engines | 🟡 MEDIUM | Warning, review recommended |
| Any detection | 🟠 CAUTION | Notice, monitor for changes |

### 🧬 Genomic Similarity Analysis

Beyond signature-based detection, UnknownCyber analyzes the **structural DNA** of executables. This catches:

- **Zero-day threats**: Malware variants that haven't been catalogued yet
- **Polymorphic malware**: Code that mutates to evade signatures
- **Repacked threats**: Known malware hidden in new wrappers
- **Code reuse**: Components borrowed from known malicious families
- **Vulnerable code**: Libraries with known CVEs reused across packages
- **Trojanized packages**: Malicious code injected between versions—a common supply chain attack TTP

Even if a file is brand new and has zero AV detections, genomic analysis can identify it as structurally similar to known threats—catching attacks before they're widely recognized.

By tracking code across successive versions, UnknownCyber can detect when legitimate packages are compromised—identifying the exact code changes that introduce backdoors or malware, even when attackers try to hide modifications in otherwise normal updates.

### 🔍 YARA Pattern Scanning

Local pattern matching using YARA rules detects:

- **Obfuscated JavaScript**: Encoded payloads, suspicious string patterns
- **Crypto miners**: Mining pools, XMRig, CPU/GPU miner signatures
- **Backdoors & Webshells**: Remote access tools, command injection patterns
- **Suspicious behaviors**: PowerShell cradles, process injection, anti-debugging

Bundled rules target supply-chain threats like the Shai Hulud worm and others.

### ✍️ Code Signature Verification

Validates digital signatures on executables to establish trust:

| Status | Meaning |
|--------|---------|
| ✅ **Valid** | Signed by trusted publisher, signature intact |
| ⚠️ **Invalid** | Signature broken or tampered |
| ❓ **Unsigned** | No signature (common for open-source tools) |

Invalid signatures are strong indicators of tampering and warrant immediate investigation.

### 📜 License Compliance

Automatically scans all packages for license compatibility issues:

| Category | Examples | Risk Level |
|----------|----------|------------|
| ✅ **Allowed** | MIT, Apache-2.0, BSD, ISC | Safe for commercial use |
| ⚠️ **Warning** | LGPL, MPL, EPL | May have conditions, review recommended |
| ❌ **Denied** | GPL, AGPL, SSPL, CC-NC | Strong copyleft or commercial restrictions |

Key capabilities:
- **Policy presets**: `permissive` (default), `strict`, `copyleft-ok`
- **Custom policies**: Define your own allowed/warning/denied lists
- **Package overrides**: Approve specific packages after review
- **Transitive scanning**: Checks nested dependencies, not just direct

📖 See the [License Compliance Guide](docs/LICENSE-COMPLIANCE.md) for detailed documentation on license types, risks, and policy configuration.

### 📦 Dependency Inventory & SBOM Compliance

Beyond security scanning, uploading to UnknownCyber builds a **centralized inventory** of all third-party packages across your organization's repositories. Each file is tagged with package name, version, and source repository—giving you a single source of truth for dependency tracking. This helps organizations:

- **Know what's deployed** — See all third-party components across projects
- **Track versions** — Monitor which versions are in use, including in released software
- **Meet SBOM regulations** — Comply with requirements like Executive Order 14028, NTIA guidelines, and customer audits

### 🔮 Coming Soon

| Feature | Description |
|---------|-------------|
| **CVE Scanning** | Check binaries against known vulnerabilities database |
| **Security Hardening** | Verify ASLR, DEP, stack canaries, and other protections |
| **SBOM Generation** | Software Bill of Materials in SPDX/CycloneDX formats |

### 🎬 See It in Action

Want to see these capabilities working on a real project? Check out the **[UC Software Scan Demo](docs/UC-SOFTWARE-SCAN-DEMO.md)** — a walkthrough of a mock project evolving over multiple releases, demonstrating binary detection, vulnerability scanning, and malware injection testing.

👉 **[Demo Repository](https://github.com/Unknown-Cyber-Inc/uc-scanner-demo)** | **[Demo Documentation](docs/UC-SOFTWARE-SCAN-DEMO.md)**

## Features

- 🔍 **Comprehensive Detection**: Identifies binaries by file extension and magic bytes
- 🌐 **Multi-Ecosystem Support**: Auto-detects npm, pip, Maven, Cargo, Go, and Ruby packages
- 📦 **Package Attribution**: Associates each binary with its parent package and version
- 🔄 **Handles Nested Dependencies**: Scans all direct and transitive dependencies  
- ☁️ **UnknownCyber Integration**: Upload binaries for multi-layer threat analysis
- 🔒 **Smart Deduplication**: Skips files already analyzed to save time and bandwidth
- 🏷️ **Automatic Tagging**: Tags files with `SW_<ecosystem>/<package>_<version>` and repository
- ⚠️ **Pipeline Integration**: Blocks CI/CD on high-severity threats with detailed annotations
- 📊 **Detailed Reports**: JSON output with full scan results and threat assessments
- 🚀 **GitHub Action & CLI**: Flexible integration options

## Quick Start

### As a GitHub Action

Add this to your workflow (`.github/workflows/scan-binaries.yml`):

```yaml
name: Scan Package Binaries

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Install your dependencies (npm, pip, etc.)
      - run: npm ci          # or: pip install -r requirements.txt
      
      # Scanner auto-detects which ecosystems are installed
      - name: Scan binaries
        uses: Unknown-Cyber-Inc/uc-software-scan@v1
        with:
          upload: 'true'
          api-key: ${{ secrets.UC_API_KEY }}
```

The scanner automatically detects installed package ecosystems—no configuration needed.

### As a CLI Tool

```bash
# Clone and run directly
git clone https://github.com/Unknown-Cyber-Inc/uc-software-scan.git
cd your-project
node path/to/uc-software-scan/scanner.js

# With upload
node scanner.js --upload --api-key YOUR_API_KEY
```

## GitHub Action

### Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scan-path` | Path to directory to scan | No | `.` |
| `ecosystems` | Ecosystems to scan (comma-separated: `npm,pip,maven,cargo,go,ruby`) | No | Auto-detect |
| `deep-scan` | Enable magic bytes detection (slower) | No | `false` |
| `upload` | Upload files to UnknownCyber | No | `false` |
| `skip-existing` | Skip files already in UnknownCyber | No | `true` |
| `get-reputations` | Fetch threat data for existing files | No | `true` |
| `include-package-json` | Include package.json files (for SBOM) | No | `false` |
| `include-all-files` | Include ALL files (not just executables) | No | `false` |
| `api-url` | UnknownCyber API URL | No | `https://api.unknowncyber.com` |
| `api-key` | UnknownCyber API key | No | `''` |
| `repo` | Repository name to tag uploads with | No | `${{ github.repository }}` |
| `yara-scan` | Enable YARA scanning | No | `false` |
| `yara-rules` | Path to additional YARA rules | No | `''` |
| `yara-include` | File patterns for YARA (e.g., `*.js,*.html`) | No | `''` |
| `generate-summary` | Generate summary report with links to UC reports | No | `false` |
| `fail-on-threats` | Fail if HIGH/MEDIUM threats or high-severity YARA matches found | No | `false` |
| `license-check` | Enable license compliance checking (npm only) | No | `false` |
| `license-policy` | Policy file or preset (`permissive`, `strict`, `copyleft-ok`) | No | `permissive` |
| `fail-on-license` | Fail if denied licenses are found | No | `false` |

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
| `license-allowed` | Number of packages with allowed licenses |
| `license-warning` | Number of packages needing license review |
| `license-denied` | Number of packages with denied licenses |

### Examples

#### Basic Scan (No Upload)

```yaml
- name: Scan binaries
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  id: scan

- name: Report
  run: echo "Found ${{ steps.scan.outputs.total-binaries }} binaries"
```

#### Scan with Upload (Smart Deduplication)

```yaml
- name: Scan and upload binaries
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
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
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    upload: 'true'
    skip-existing: 'false'  # Upload even if file exists
    api-key: ${{ secrets.UC_API_KEY }}
```

#### Fast Scan (Skip Reputation Checks)

```yaml
- name: Quick scan and upload
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    upload: 'true'
    get-reputations: 'false'  # Don't fetch threat data for existing files
    api-key: ${{ secrets.UC_API_KEY }}
```

#### Deep Scan with Custom Path

```yaml
- name: Deep scan frontend
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    scan-path: './packages/frontend'
    deep-scan: 'true'
    upload: 'true'
    api-key: ${{ secrets.UC_API_KEY }}
```

#### Include package.json for SBOM

Upload package.json files to enable Software Bill of Materials (SBOM) creation:

```yaml
- name: Scan with SBOM support
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    upload: 'true'
    include-package-json: 'true'
    api-key: ${{ secrets.UC_API_KEY }}
```

#### Upload All Files

Upload everything in node_modules (executables, metadata, source files):

```yaml
- name: Full package upload
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    upload: 'true'
    include-all-files: 'true'
    api-key: ${{ secrets.UC_API_KEY }}
```

Note: Reputation data is only fetched for executable files (binaries and scripts), not for metadata or other files.

#### Complete Scan with Summary and Fail on Threats

The simplest way to get full security scanning with a detailed report:

```yaml
- name: Scan packages
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    upload: 'true'
    deep-scan: 'true'
    yara-scan: 'true'
    yara-include: '*.js,*.exe'
    generate-summary: 'true'
    fail-on-threats: 'true'
    api-key: ${{ secrets.UC_API_KEY }}
```

This single step:
- Scans all binaries and scripts
- Runs YARA rules on JS and EXE files
- Uploads files to UnknownCyber for analysis
- Generates a detailed summary with links to [UC reports](https://unknowncyber.com/files/<sha256>/report/)
- Fails the pipeline if threats are detected

#### Custom Summary (Manual)

If you need a custom summary format, you can build it from outputs:

```yaml
- name: Scan binaries
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
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

- name: Fail if threats found
  if: steps.scan.outputs.threats-found > 0
  run: exit 1
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

Files are categorized by overall threat level based on the [Security Analysis](#security-analysis) factors:

| Level | Description | Action |
|-------|-------------|--------|
| **HIGH** | Known malware, invalid signatures, or critical YARA matches | 🔴 Immediate investigation required |
| **MEDIUM** | Suspicious similarity, moderate AV detections, or medium YARA matches | 🟠 Review recommended |
| **CAUTION** | Minor AV detections, unsigned binaries, or low YARA matches | 🟡 Monitor |
| **LOW** | Minimal risk indicators | 🟢 Generally safe |
| **NONE** | No threats detected | ✅ Clean |
| **UNKNOWN** | Not enough data for assessment | ❓ Pending analysis |

The overall threat level is the highest level from any of these factors:
- **Antivirus Detection** — Multi-engine scan results
- **Genomic Similarity** — Structural similarity to known malware
- **Code Signature** — Digital signature validity
- **YARA Matches** — Pattern-based detections

See [Security Analysis](#security-analysis) for detailed thresholds and explanations of each factor.

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
- Adds missing `SW_npm/<package>_<version>` and `REPO_<repo>` tags
- Ensures consistent tagging across repositories

## License Compliance

The scanner can check npm package licenses against a configurable policy to detect licensing issues that could create legal or compliance risks.

📖 **[Full License Compliance Guide](docs/LICENSE-COMPLIANCE.md)** - Comprehensive documentation on license types, risks, and best practices.

### Quick Start

```yaml
- name: Scan with license check
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    license-check: 'true'
    fail-on-license: 'true'
```

### Policy Presets

| Preset | Description |
|--------|-------------|
| `permissive` | Default. Allows MIT, Apache-2.0, BSD. Warns on LGPL, MPL. Denies GPL, AGPL. |
| `strict` | All non-permissive licenses require review |
| `copyleft-ok` | Allows GPL/LGPL (for open source projects) |

### Custom Policy

Create a `license-policy.json` file:

```json
{
  "allowed": ["MIT", "Apache-2.0", "BSD-3-Clause"],
  "warning": ["LGPL-3.0", "MPL-2.0"],
  "denied": ["GPL-3.0", "AGPL-3.0"],
  "unknownPolicy": "warning",
  "overrides": {
    "reviewed-package": "allowed"
  }
}
```

Use it in your workflow:

```yaml
- name: Scan with custom policy
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    license-check: 'true'
    license-policy: './license-policy.json'
    fail-on-license: 'true'
```

### License Categories

| Category | Examples | Risk |
|----------|----------|------|
| ✅ **Allowed** | MIT, Apache-2.0, BSD, ISC | Safe for commercial use |
| ⚠️ **Warning** | LGPL, MPL, EPL | May have conditions, review recommended |
| ❌ **Denied** | GPL, AGPL, SSPL, CC-NC | Strong copyleft or commercial restrictions |

## YARA Scanning

The scanner includes optional YARA scanning to detect malware patterns and suspicious code in binaries and source files.

### Automatic Upload of Matches

When both `upload: 'true'` and `yara-scan: 'true'` are enabled, **all files that match YARA rules are automatically uploaded** to UnknownCyber, regardless of whether they were included in the initial scan. This ensures:

- Complete visibility into security-flagged files
- Detailed analysis available via UC's web interface
- Files are tagged with `YARA_MATCH` for easy filtering
- Report links in GitHub Actions summary point directly to file analysis

### Scan Binaries Only

```yaml
- name: Scan binaries with YARA
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    yara-scan: 'true'
```

### Scan JavaScript Files

Detect obfuscated malicious code in JS files (e.g., supply chain attacks):

```yaml
- name: Scan JS files with YARA
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    yara-scan: 'true'
    yara-include: '*.js'
```

### Scan Multiple File Types

```yaml
- name: Scan JS, HTML, and MJS files
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  with:
    yara-scan: 'true'
    yara-include: '*.js,*.html,*.mjs'
```

### Add Custom Rules

```yaml
- name: Scan with custom YARA rules
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
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

### YARA Outputs

| Output | Description |
|--------|-------------|
| `yara-matches` | Total files with any YARA match |
| `yara-high-severity` | Files matching critical/high severity rules |

Severity levels (`critical`, `high`, `medium`, `low`) are defined in rule metadata and map to [Threat Levels](#threat-levels).

### Block Pipeline on YARA Matches

```yaml
- name: Scan with YARA
  uses: Unknown-Cyber-Inc/uc-software-scan@v1
  id: scan
  with:
    yara-scan: 'true'
    yara-include: '*.js'

# Option 1: Fail only on high-severity matches (malware signatures)
- name: Fail on malware detection
  if: steps.scan.outputs.yara-high-severity > 0
  run: |
    echo "::error::YARA detected ${{ steps.scan.outputs.yara-high-severity }} high-severity matches!"
    exit 1

# Option 2: Fail on ANY YARA match (stricter)
- name: Fail on any YARA match
  if: steps.scan.outputs.yara-matches > 0
  run: |
    echo "::error::YARA detected matches in ${{ steps.scan.outputs.yara-matches }} files!"
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
| **Package Tag** | `SW_npm/<package>_<version>` | `SW_npm/@esbuild/win32-x64_0.20.2` |
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

## Creating a Demo Repository

A script is included to create a demo repository showing the scanner's capabilities with evolving package versions over time.

### Usage

```bash
# Create demo with default settings
node create-demo.js ../my-scanner-demo

# Specify custom repository name
node create-demo.js ../my-scanner-demo --repo-name=my-scanner-demo

# Specify GitHub organization
node create-demo.js ../my-scanner-demo --repo-name=my-demo --org=MyOrg
```

### What It Creates

The script generates a repository with **6 versioned releases** (v1.0.0 through v2.0.0), each with backdated commits simulating package evolution:

| Version | Date | Packages Added |
|---------|------|----------------|
| v1.0.0 | Jan 15, 2025 | esbuild, lodash, source-map |
| v1.1.0 | Mar 1, 2025 | + rollup |
| v1.2.0 | May 1, 2025 | + @swc/core, eslint-config-prettier |
| v1.3.0 | Jul 1, 2025 | + @sentry/cli |
| v1.4.0 | Sep 1, 2025 | + minimist (vulnerable version) |
| v2.0.0 | Nov 15, 2025 | Updated to latest versions |

### Features Demonstrated

- **All-files upload**: Every file in `node_modules` is uploaded to UnknownCyber
- **YARA scanning**: Scans JS and EXE files for malicious patterns
- **Detailed summaries**: GitHub Actions annotations showing threats
- **Pipeline blocking**: Fails on high-severity detections
- **Malware detection**: Optionally downloads real malware samples (Shai Hulud) to demonstrate YARA detection

## Malware Test Injection

A reusable composite action is included for injecting **real malware samples** into any ecosystem for security testing. This validates that your scanning setup correctly detects threats.

> ⚠️ **Important**: Create a **separate, manual-only workflow** for malware testing. Do not trigger malware injection on regular pushes or via commit messages—this could accidentally fail your normal CI/CD pipeline.

### Quick Start

Create a separate workflow file (e.g., `.github/workflows/malware-test.yml`):

```yaml
name: Malware Detection Test

on:
  workflow_dispatch:  # Manual trigger only

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
      
      - uses: Unknown-Cyber-Inc/uc-software-scan/malware-test-inject@main
        with:
          api-key: ${{ secrets.UC_API_KEY }}
          ecosystem: npm
          package-name: test-malware-package
      
      - uses: Unknown-Cyber-Inc/uc-software-scan@main
        with:
          yara-scan: 'true'
          fail-on-threats: 'false'
          api-key: ${{ secrets.UC_API_KEY }}
```

Then trigger manually from GitHub Actions → "Malware Detection Test" → "Run workflow".

### Supported Ecosystems

| Ecosystem | Target Directory |
|-----------|------------------|
| `npm` | `node_modules/<package>/` |
| `pip` | `site-packages/<package>/` |
| `maven` | `.m2/repository/com/test/<package>/<version>/` |
| `cargo` | `target/release/` |
| `go` | `vendor/github.com/test/<package>/` |
| `ruby` | `vendor/bundle/ruby/gems/<package>-<version>/` |
| `nuget` | `packages/<package>/<version>/` |
| `generic` | `./<package>/` |

### Available Samples

| Sample Type | Description | Detection |
|-------------|-------------|-----------|
| `obfuscated-js` | Shai Hulud obfuscated JavaScript backdoor | 45+ AV engines |
| `elf-malware` | Neotyxa Linux ELF malware binary | 52+ AV engines |
| `pe-malware` | Windows PE malware executable | 38+ AV engines |
| `all` | Download all available samples | - |

### Complete Testing Workflow

```yaml
name: Security Test

on:
  workflow_dispatch:
    inputs:
      inject-malware:
        type: boolean
        default: false

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
      
      # Inject malware (only when requested)
      - uses: Unknown-Cyber-Inc/uc-software-scan/malware-test-inject@main
        if: ${{ inputs.inject-malware }}
        with:
          api-key: ${{ secrets.UC_API_KEY }}
          ecosystem: npm
          samples: obfuscated-js,elf-malware
      
      # Scan and fail if malware detected
      - uses: Unknown-Cyber-Inc/uc-software-scan@main
        with:
          api-key: ${{ secrets.UC_API_KEY }}
          fail-on-threats: 'true'
```

📖 See [malware-test-inject/README.md](malware-test-inject/README.md) for full documentation.

### Setup Steps

1. Create the demo: `node create-demo.js ../my-demo --repo-name=my-demo`
2. Create a GitHub repository with the same name
3. Add remote: `git remote add origin git@github.com:YourOrg/my-demo.git`
4. Push incrementally (to trigger separate workflows):
   ```bash
   git reset --hard v1.0.0 && git push --force origin main && git push origin v1.0.0
   # Wait for workflow, then repeat for each version
   ```
5. Add `UC_API_KEY` secret in GitHub repo settings

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
