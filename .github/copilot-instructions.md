# UC Software Scan - AI Agent Guide

## Project Overview

This is a **GitHub Action and CLI tool** that scans software packages for security threats. It auto-detects packages from 10 ecosystems (npm, pip, Maven, Cargo, Go, Ruby, NuGet, dpkg, apk, rpm), identifies binaries/scripts, uploads them to UnknownCyber for threat analysis (AV, genomic similarity, YARA), and provides license compliance checking.

**Key components:**

- `scanner.js` - Core scanner (auto-detects ecosystems, finds binaries, uploads to UC)
- `ecosystems.js` - Ecosystem-specific package metadata extraction (10 ecosystems)
- `file-reputation.js` - UC API client for reputation checks and tag management
- `yara_scanner.py` - Python YARA scanner with bundled rules in `rules/`
- `license-checker.js` - License compliance checker (npm only)
- `generate-summary.js` - GitHub Actions markdown summary generator
- `action.yml` - GitHub Action composite with 24+ inputs

## Architecture Patterns

### Ecosystem Detection Strategy

Each ecosystem in `ecosystems.js` defines:

- `directories`: Where packages are installed (e.g., `['node_modules']` for npm)
- `tagPrefix`: Tag format for UC (e.g., `SW_npm/`)
- `findPackageInfo(filePath, rootDir)`: Extracts package name/version from file paths

**Auto-detection flow:** `detectEcosystems()` checks for ecosystem-specific directories → builds a list of detected ecosystems → scans each ecosystem's directories.

**Important:** When adding ecosystem support, implement a `findPackageInfo` function that traverses directory structure to find metadata files (package.json, METADATA, pom.xml, etc.).

### File Scanning Architecture

The scanner uses a **two-phase approach** for binary detection:

1. **Extension-based** (fast): Checks against `BINARY_EXTENSIONS` and `SCRIPT_EXTENSIONS` sets
2. **Magic bytes** (thorough): Reads first 8 bytes to detect ELF, PE, Mach-O, WASM, etc. when `--deep` enabled

`scanDirectory()` recursively walks directories, skipping `SKIP_DIRS` and `SKIP_PATTERNS` for performance.

### Deduplication & Upload Flow

The scanner implements smart deduplication to avoid re-uploading files:

```
computeHashes() → checkExistingFiles() → getReputationsForExisting() → syncTagsForExisting() → uploadBinaries()
```

- `checkExistingFiles()`: Batches SHA256 checks (100 at a time) to UC API
- Splits results into `existing` vs `toUpload`
- Gets reputations for existing files in parallel (10 at a time)
- Syncs missing tags on existing files
- Uploads only new files with `multipart/form-data`

**Critical:** The `skip-existing` default is `true` - only uploads files not already in UC.

### Threat Level Calculation

Reputation data comes from multiple sources (`file-reputation.js`):

- **AV detections**: 70+ engines, threat level based on detection percentage
- **Genomic similarity**: Structural code similarity to known malware
- **Code signatures**: Validates digital signatures (valid/invalid/unsigned)
- **YARA matches**: Pattern-based detections with severity metadata

`determineOverallThreatLevel()` returns the **highest** threat level across all factors. GitHub annotations are emitted based on threat level: HIGH=error, MEDIUM=warning, CAUTION=notice.

## Development Workflows

### Testing Ecosystem Detection

Use the comprehensive test suite in `.github/workflows/test.yml`:

```bash
# Run individual ecosystem tests locally:
node scanner.js test-ecosystems/npm-project
node scanner.js test-ecosystems/pip-project
node scanner.js test-ecosystems/cargo-project
```

Tests verify: ecosystem detection, package attribution, binary discovery, hash computation.

### Creating Test Binaries

`create-test-binaries.js` generates fake binaries with proper magic bytes for testing:

```bash
node create-test-binaries.js
```

**DO NOT** commit real executables - only test files with valid magic signatures.

### Running YARA Scans

YARA scanning requires `yara-python>=4.3.0`:

```bash
pip install yara-python
python yara_scanner.py --input binary-scan-results.json --output yara-results.json --github-annotations
```

Rules in `rules/` target supply chain threats (crypto miners, obfuscated JS, Shai Hulud worm patterns).

### License Compliance

License checker scans npm packages only (currently):

```bash
node license-checker.js --path node_modules --output license-results.json --policy permissive
```

Policies: `permissive` (default), `strict`, `copyleft-ok`, or custom JSON file. See `docs/LICENSE-COMPLIANCE.md`.

### Collecting Lock Files for SBOM

To add lock file collection for backend SBOM generation:

**Lock files by ecosystem:**
- npm: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- pip: `requirements.txt`, `Pipfile.lock`, `poetry.lock`
- Maven: `pom.xml` (dependency management section)
- Cargo: `Cargo.lock`
- Go: `go.sum`
- Ruby: `Gemfile.lock`
- NuGet: `packages.lock.json`

**Implementation pattern (similar to `includePackageJson`):**

1. Add lock file detection in `scanDirectory()` around line 289:
```javascript
else if (includeLockFiles && isLockFile(entry.name, ecosystem)) {
  detectedType = 'LOCK';
  category = 'metadata';
}
```

2. Define `isLockFile()` helper:
```javascript
const LOCK_FILES = {
  npm: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
  pip: ['requirements.txt', 'Pipfile.lock', 'poetry.lock'],
  cargo: ['Cargo.lock'],
  go: ['go.sum', 'go.mod'],
  ruby: ['Gemfile.lock'],
  nuget: ['packages.lock.json']
};
```

3. Add CLI flag `--include-lock-files` and GitHub Action input `include-lock-files`

4. Lock files are in root or ecosystem directories - search parent directories from scan-path

5. Upload lock files with tag `SBOM_LOCK/<ecosystem>` for backend processing

## Key Conventions

### Tagging Format

All UC uploads are tagged with:

- **Software tag**: `SW_<ecosystem>/<package>_<version>` (e.g., `SW_npm/esbuild_0.19.0`)
- **Repo tag**: `REPO_<org>/<repo>` (e.g., `REPO_myorg/myrepo`)

Tag syncing ensures consistency when files already exist in UC.

### Output File Names

Scanner produces JSON outputs in scan-path directory:

- `binary-scan-results.json` - Main scan results
- `yara-results.json` - YARA matches
- `license-results.json` - License compliance

**Never change these names** - they're hardcoded in action.yml steps and summary generation.

**Lock file collection:** When `include-lock-files` enabled, lock files are included in `binary-scan-results.json` with `category: 'metadata'` and `detectedType: 'LOCK'`. These can be filtered and uploaded separately for backend SBOM processing.

### Error Handling

Functions use **async/await with try-catch**. Failed uploads are logged but don't stop the scan:

```javascript
try {
  await uploadFile(...);
  successful.push(binary);
} catch (err) {
  failed.push({ ...binary, error: err.message });
}
```

Parallel operations use `Promise.all()` with error isolation.

### GitHub Actions Integration

The action uses **composite runs** (`action.yml`). Key patterns:

- Environment variables passed via `env:` block
- Outputs extracted from JSON using `node -e` one-liners
- Conditional steps with `if:` expressions
- Background Python setup only when YARA enabled

## API Integration

### UnknownCyber API Client

`file-reputation.js` is a standalone module with no external dependencies:

```javascript
const client = createReputationClient({ apiUrl, apiKey });
const reputations = await getFileReputations(client, ["sha256hash"]);
const tags = await getFileTags(client, "sha256hash");
await addFileTags(client, "sha256hash", ["SW_npm/pkg_1.0.0"]);
```

**Authentication:** API key passed as query parameter (`?key=xxx`).

**Batching:** `checkFileExistence()` chunks hashes into groups of 100 to avoid URL length limits.

**Retry logic:** Built-in with exponential backoff (3 retries default).

## Common Pitfalls

1. **Magic bytes detection:** Always read at least 8 bytes - some signatures are longer than 4 bytes
2. **Path handling:** Use `path.relative()` for cross-platform compatibility, normalize separators
3. **Circular symlinks:** Scanner tracks visited directories with `Set` to prevent infinite loops
4. **Large ecosystems:** npm/pip can have 1000+ packages - use streaming and batching
5. **Missing metadata:** `findPackageInfo()` may return `null` - always handle gracefully
6. **Python path handling:** YARA scanner needs both Windows and Unix path support

## Documentation

- **README.md** - User-facing docs with tables, quick starts, examples
- **docs/LICENSE-COMPLIANCE.md** - Comprehensive license guide (445 lines)
- **examples/** - Workflow examples for common use cases

When documenting features, include:

- Input/output table with defaults
- Flow diagram using ASCII art (see README deduplication flow)
- Threat level tables with icons (🔴🟠🟡🟢)
- Code examples with actual command syntax
