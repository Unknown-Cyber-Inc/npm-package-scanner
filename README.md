# NPM Binary Scanner

[![Test Action](https://github.com/Unknown-Cyber-Inc/npm-binary-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/Unknown-Cyber-Inc/npm-binary-scanner/actions/workflows/test.yml)

A GitHub Action and CLI tool that scans npm packages (`node_modules`) for binary executables like DLL, EXE, ELF, SO, and other binary files. It reports which packages contain binaries along with their version numbers, and can optionally upload them to UnknownCyber for security analysis.

## Features

- 🔍 **Comprehensive Detection**: Identifies binaries by file extension and magic bytes
- 📦 **Package Attribution**: Associates each binary with its parent npm package and version
- 🔄 **Handles Nested Dependencies**: Scans all direct and transitive dependencies  
- ☁️ **UnknownCyber Integration**: Upload binaries for malware analysis
- 📊 **Detailed Reports**: JSON output with full scan results
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
| `api-url` | UnknownCyber API URL | No | `https://api.unknowncyber.com` |
| `api-key` | UnknownCyber API key | No | `''` |
| `repo` | Repository name to tag uploads with | No | `${{ github.repository }}` |

### Outputs

| Output | Description |
|--------|-------------|
| `total-packages` | Number of packages containing binaries |
| `total-binaries` | Total number of binary files found |
| `results-file` | Path to the JSON results file |
| `upload-successful` | Number of successfully uploaded files |
| `upload-failed` | Number of failed uploads |

### Examples

#### Basic Scan (No Upload)

```yaml
- name: Scan binaries
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  id: scan

- name: Report
  run: echo "Found ${{ steps.scan.outputs.total-binaries }} binaries"
```

#### Scan with Upload

```yaml
- name: Scan and upload binaries
  uses: Unknown-Cyber-Inc/npm-binary-scanner@v1
  with:
    upload: 'true'
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
```

## CLI Usage

### Command Line Options

```
node scanner.js [options] [path]

Options:
  --deep              Enable deep scan using magic bytes
  --upload            Upload found binaries to UnknownCyber API
  --api-url <url>     API base URL (or set UC_API_URL env var)
  --api-key <key>     API key (or set UC_API_KEY env var)
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

# Scan and upload
node scanner.js --upload --api-url https://api.unknowncyber.com --api-key YOUR_KEY

# Using environment variables
export UC_API_URL="https://api.unknowncyber.com"
export UC_API_KEY="your-api-key"
node scanner.js --upload
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
| **Package Tag** | `SW_<package>@<version>` | `SW_@esbuild/win32-x64@0.20.2` |
| **Repo Tag** | `REPO_<owner>/<repo>` | `REPO_my-org/my-app` |

The repository tag helps identify which project the binary came from, useful when the same package version appears in multiple repositories.

## Setting Up the API Key

1. Get your API key from [UnknownCyber](https://unknowncyber.com)
2. Add it as a repository secret:
   - Go to your repo → Settings → Secrets and variables → Actions
   - Click "New repository secret"
   - Name: `UC_API_KEY`
   - Value: Your API key

## Common Packages with Binaries

Many popular npm packages include native binaries:

- **esbuild** - Fast JavaScript bundler
- **sharp** - Image processing
- **sqlite3** - SQLite database bindings
- **rollup** - Module bundler (native acceleration)
- **swc** - Rust-based JavaScript compiler
- **fsevents** - macOS file system events
- **sentry-cli** - Sentry command-line tool

## Security Considerations

This tool helps with:

1. **Supply Chain Auditing** - Identify packages with native code
2. **License Compliance** - Native binaries may have different licensing
3. **Security Review** - Native code can have vulnerabilities not caught by JS scanners
4. **Malware Detection** - Upload to UnknownCyber for analysis

## Requirements

- Node.js 18+ (for GitHub Action)
- Node.js 12+ (for CLI)
- No external dependencies

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
