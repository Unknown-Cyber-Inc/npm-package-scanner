# UC Software Scan Demo

This document describes the demonstration repository created to showcase the UC Software Scan GitHub Action in action.

## Overview

The demo simulates a real-world software project evolving over time, with third-party npm packages being added, updated, and occasionally downgraded. Each version triggers the security scanning workflow, demonstrating how UC Software Scan monitors your software supply chain across releases.

### Demo Repository

**Repository:** [Unknown-Cyber-Inc/uc-scanner-demo](https://github.com/Unknown-Cyber-Inc/uc-scanner-demo)

### How It Was Created

The demo repository was generated using the `create-demo.js` script in this repository:

```bash
node create-demo.js ../uc-scanner-demo --repo-name=uc-scanner-demo --org=Unknown-Cyber-Inc
```

This script:
1. Creates a mock npm project with realistic dependencies
2. Simulates software evolution through multiple releases
3. Uses backdated git commits to show realistic version history
4. Sets up GitHub Actions workflow for automatic scanning on each push
5. Tags each release for easy navigation

---

## Release History

The demo progresses through six versions, each representing a point in time with evolving dependencies.

### v1.0.0 — Initial Release (2025-01-15)

**Commit:** [dd41572](https://github.com/Unknown-Cyber-Inc/uc-scanner-demo/tree/dd415724052aea98c8d0c1eef976da723fe5fbfd)

Basic tooling setup with minimal dependencies.

| Package | Version | Notes |
|---------|---------|-------|
| esbuild | 0.24.2 | Build tool from late 2024 |
| lodash | 4.17.21 | Stable, no known vulnerabilities |
| source-map | 0.7.4 | Stable |

---

### v1.1.0 — Add Bundler (2025-03-01)

**Commit:** [9838893](https://github.com/Unknown-Cyber-Inc/uc-scanner-demo/tree/98388f33e0753e06345f0b4238186d145b1f36cc)

Added Rollup for more advanced bundling capabilities.

| Package | Version | Notes |
|---------|---------|-------|
| esbuild | 0.25.0 | Updated |
| rollup | 4.12.0 | **New** — bundler |
| lodash | 4.17.21 | — |
| source-map | 0.7.4 | — |

---

### v1.2.0 — Add SWC Compiler (2025-05-01)

**Commit:** [6e84f4f](https://github.com/Unknown-Cyber-Inc/uc-scanner-demo/tree/6e84f4f8109a8a78da9c83066c5a894b57c34804)

Introduced SWC for faster TypeScript/JavaScript compilation and eslint-config-prettier for code formatting.

| Package | Version | Notes |
|---------|---------|-------|
| esbuild | 0.25.4 | Updated |
| rollup | 4.18.0 | Updated |
| @swc/core | 1.5.0 | **New** — Rust-based compiler |
| eslint-config-prettier | 10.1.2 | **New** — formatting config |
| lodash | 4.17.21 | — |
| source-map | 0.7.4 | — |

---

### v1.3.0 — Add Sentry CLI (2025-07-01)

**Commit:** [781a985](https://github.com/Unknown-Cyber-Inc/uc-scanner-demo/tree/781a9852e4cd3665a78744772420b25fb79bc02b)

Added Sentry CLI for error monitoring integration.

| Package | Version | Notes |
|---------|---------|-------|
| esbuild | 0.25.8 | Updated |
| rollup | 4.18.0 | — |
| @swc/core | 1.6.0 | Updated |
| @sentry/cli | 2.41.1 | **New** — error monitoring |
| eslint-config-prettier | 10.1.5 | Updated |
| lodash | 4.17.21 | — |
| source-map | 0.7.4 | — |

---

### v1.4.0 — Vulnerable Dependencies (2025-09-01)

**Commit:** [b6850dd](https://github.com/Unknown-Cyber-Inc/uc-scanner-demo/tree/b6850dd9427aecd28b9105b3a7e3c3a1c297e958)

⚠️ **This release intentionally introduces vulnerable packages to demonstrate security scanning.**

| Package | Version | Notes |
|---------|---------|-------|
| esbuild | 0.25.10 | Updated |
| rollup | 4.18.0 | — |
| @swc/core | 1.7.0 | Updated |
| @sentry/cli | 2.41.1 | — |
| eslint-config-prettier | 10.1.7 | Updated |
| minimist | 1.2.5 | **New** — ⚠️ CVE-2021-44906 (Prototype Pollution) |
| lodash | 4.17.20 | ⚠️ **Downgraded** from 4.17.21 — known vulnerabilities |
| source-map | 0.7.4 | — |

**Why the lodash downgrade?**  
The downgrade from lodash 4.17.21 to 4.17.20 was intentional to demonstrate how UC Software Scan detects dependency regressions to vulnerable versions. Combined with the vulnerable minimist version, this release shows the scanner's ability to identify security risks from both new vulnerable packages and downgrades.

---

### v2.0.0 — Major Update (2025-11-15)

Major version bump with significant updates across the toolchain.

| Package | Version | Notes |
|---------|---------|-------|
| esbuild | 0.27.2 | Major update |
| rollup | 4.18.0 | — |
| @swc/core | 1.11.31 | Major update |
| @sentry/cli | 2.41.1 | — |
| eslint-config-prettier | 10.1.8 | Updated |
| minimist | 1.2.5 | Still vulnerable |
| lodash | 4.17.20 | Still vulnerable |
| source-map | 0.7.4 | — |

---

## Malware Injection Testing

A separate workflow demonstrates malware detection capabilities using the `malware-test-inject` action. This is triggered **manually only** via workflow dispatch to avoid accidental injection during normal development.

### Pipeline Failure Example

**Run:** [Pipeline #20931594246](https://github.com/Unknown-Cyber-Inc/uc-scanner-demo/actions/runs/20931594246) — Malware detected, pipeline failed as expected.

This run demonstrates the scanner correctly identifying injected malware samples and failing the build to prevent compromised code from being deployed.

### How to Test Malware Detection

1. Navigate to the demo repository's Actions tab
2. Select the "Malware Detection Test" workflow
3. Click "Run workflow"
4. Choose which samples to inject (or use "all")
5. The workflow will:
   - Install npm dependencies
   - Inject malware samples into `node_modules/`
   - Run UC Software Scan with YARA detection
   - **Fail** if malware is detected (expected behavior)

---

## GitHub Actions Workflow

The demo repository uses the following workflow (`.github/workflows/scan.yml`):

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - run: npm install
      
      - name: Scan packages
        uses: Unknown-Cyber-Inc/uc-software-scan@main
        with:
          upload: 'true'
          deep-scan: 'true'
          include-all-files: 'true'
          yara-scan: 'true'
          yara-include: '*.js,*.exe,*.elf'
          generate-summary: 'true'
          fail-on-threats: 'true'
          license-check: 'true'
          api-key: ${{ secrets.UC_API_KEY }}
```

---

## Key Demonstrations

| Capability | How Demonstrated |
|------------|------------------|
| **Binary Detection** | Scans native binaries in esbuild, rollup, @swc/core, @sentry/cli |
| **Version Tracking** | Detects package updates and downgrades across releases |
| **Vulnerability Detection** | Identifies vulnerable minimist and lodash versions in v1.4.0 |
| **Malware Detection** | YARA rules catch injected malware samples |
| **License Compliance** | Reports license distribution across dependencies |
| **Supply Chain Monitoring** | Tracks evolving dependencies over project lifetime |

---

## Recreating the Demo

To create your own demo repository:

```bash
# Clone the main repository
git clone https://github.com/Unknown-Cyber-Inc/uc-software-scan.git
cd uc-software-scan

# Generate the demo
node create-demo.js ../my-demo --repo-name=my-scanner-demo --org=YourOrg

# Set up the remote
cd ../my-demo
git remote add origin git@github.com:YourOrg/my-scanner-demo.git
git push -u origin main --tags

# Add your UC_API_KEY secret in GitHub repository settings
```

---

## See Also

- [UC Software Scan Action](../README.md)
- [Malware Test Injection Action](../malware-test-inject/README.md)
- [License Compliance Documentation](./LICENSE-COMPLIANCE.md)
