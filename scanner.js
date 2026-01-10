#!/usr/bin/env node

/**
 * NPM Binary Scanner
 * Scans npm packages (node_modules) for binary executables like DLL, EXE, ELF, SO, etc.
 * Reports the package name, version, and file paths for each binary found.
 * Optionally uploads found binaries to UnknownCyber API.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');

// Binary file extensions to look for
const BINARY_EXTENSIONS = new Set([
  // Windows executables
  '.exe', '.dll', '.sys', '.ocx', '.com', '.scr',
  // Linux/Unix
  '.so', '.o', '.a',
  // macOS
  '.dylib', '.bundle',
  // Node.js native addons
  '.node',
  // General
  '.bin', '.dat',
  // WebAssembly
  '.wasm'
]);

// Executable script extensions (text-based but can execute malicious code)
const SCRIPT_EXTENSIONS = new Set([
  // Windows scripts
  '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.wsf', '.wsh',
  // Unix shell scripts
  '.sh', '.bash', '.zsh', '.csh', '.ksh',
  // Other scripting languages commonly used in attacks
  '.pl', '.rb', '.py', '.pyw'
]);

// Magic bytes signatures for binary detection (hex)
const MAGIC_SIGNATURES = {
  // ELF (Linux executables/shared objects)
  ELF: Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
  // PE (Windows EXE/DLL)
  MZ: Buffer.from([0x4d, 0x5a]),
  // Mach-O (macOS) - various architectures
  MACHO_32: Buffer.from([0xfe, 0xed, 0xfa, 0xce]),
  MACHO_64: Buffer.from([0xfe, 0xed, 0xfa, 0xcf]),
  MACHO_32_REV: Buffer.from([0xce, 0xfa, 0xed, 0xfe]),
  MACHO_64_REV: Buffer.from([0xcf, 0xfa, 0xed, 0xfe]),
  // Universal Binary (macOS)
  FAT_BINARY: Buffer.from([0xca, 0xfe, 0xba, 0xbe]),
  // WebAssembly
  WASM: Buffer.from([0x00, 0x61, 0x73, 0x6d]),
};

// Directories to skip for faster scanning
const SKIP_DIRS = new Set([
  '.bin', '.cache', '.git', '.github', '.vscode',
  '__tests__', '__mocks__', 'test', 'tests', 'spec', 'specs',
  'docs', 'doc', 'documentation', 'example', 'examples',
  'coverage', '.nyc_output', 'typings', '@types'
]);

// File patterns to skip (no binaries here)
const SKIP_PATTERNS = [
  /\.d\.ts$/,
  /\.map$/,
  /\.md$/,
  /\.txt$/,
  /\.json$/,
  /\.yml$/,
  /\.yaml$/,
  /\.lock$/
];

let deepMagicScan = false;
let scannedDirs = 0;
let scannedFiles = 0;

/**
 * Check if a file is a binary by reading its magic bytes
 */
function checkMagicBytes(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buffer = Buffer.alloc(4);
    const bytesRead = fs.readSync(fd, buffer, 0, 4, 0);
    fs.closeSync(fd);

    if (bytesRead < 2) return null;

    for (const [type, signature] of Object.entries(MAGIC_SIGNATURES)) {
      if (buffer.slice(0, signature.length).equals(signature)) {
        return type;
      }
    }
    return null;
  } catch (err) {
    return null;
  }
}

/**
 * Check if a file is binary by extension
 */
function isBinaryByExtension(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return BINARY_EXTENSIONS.has(ext);
}

/**
 * Check if a file is an executable script by extension
 */
function isScriptByExtension(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return SCRIPT_EXTENSIONS.has(ext);
}

/**
 * Should skip this file based on patterns?
 */
function shouldSkipFile(filename) {
  return SKIP_PATTERNS.some(pattern => pattern.test(filename));
}

/**
 * Find the nearest package.json for a given file path
 */
function findPackageInfo(filePath, nodeModulesRoot) {
  let dir = path.dirname(filePath);
  
  while (dir.length >= nodeModulesRoot.length) {
    const packageJsonPath = path.join(dir, 'package.json');
    
    if (fs.existsSync(packageJsonPath)) {
      try {
        const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
        const relativePath = path.relative(nodeModulesRoot, dir);
        
        // Determine if it's a scoped package
        let packageName = packageJson.name || path.basename(dir);
        
        return {
          name: packageName,
          version: packageJson.version || 'unknown',
          path: dir,
          relativePath: relativePath
        };
      } catch (err) {
        // Continue searching up
      }
    }
    
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  
  return null;
}

/**
 * Recursively scan a directory for binary files
 */
function scanDirectory(dir, nodeModulesRoot, results, visited = new Set()) {
  // Resolve real path to handle symlinks and avoid infinite loops
  let realDir;
  try {
    realDir = fs.realpathSync(dir);
    if (visited.has(realDir)) return;
    visited.add(realDir);
  } catch (err) {
    return;
  }

  scannedDirs++;
  
  // Progress indicator every 500 directories
  if (scannedDirs % 500 === 0) {
    process.stdout.write(`\rScanned ${scannedDirs} directories, ${scannedFiles} files, found ${results.length} binaries...`);
  }

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    try {
      if (entry.isDirectory()) {
        // Skip certain directories for speed
        if (SKIP_DIRS.has(entry.name)) continue;
        scanDirectory(fullPath, nodeModulesRoot, results, visited);
      } else if (entry.isFile()) {
        scannedFiles++;
        
        // Skip files that definitely won't be binaries or scripts
        if (shouldSkipFile(entry.name)) continue;
        
        let detectedType = null;
        let category = 'binary'; // 'binary' or 'script'
        
        // Check for binary by extension first (faster)
        if (isBinaryByExtension(fullPath)) {
          detectedType = path.extname(fullPath).toLowerCase().slice(1).toUpperCase();
        } 
        // Check for executable scripts
        else if (isScriptByExtension(fullPath)) {
          detectedType = path.extname(fullPath).toLowerCase().slice(1).toUpperCase();
          category = 'script';
        }
        // Deep scan: check magic bytes for binaries without known extensions
        else if (deepMagicScan) {
          const magicType = checkMagicBytes(fullPath);
          if (magicType) {
            detectedType = magicType;
          }
        }

        if (detectedType) {
          const packageInfo = findPackageInfo(fullPath, nodeModulesRoot);
          const relativePath = path.relative(nodeModulesRoot, fullPath);
          
          results.push({
            file: relativePath,
            absolutePath: fullPath,
            type: detectedType,
            category: category,
            package: packageInfo ? packageInfo.name : 'unknown',
            version: packageInfo ? packageInfo.version : 'unknown',
            packagePath: packageInfo ? packageInfo.relativePath : 'unknown'
          });
        }
      }
    } catch (err) {
      // Skip files we can't access
    }
  }
}

/**
 * Generate a unique boundary for multipart form data
 */
function generateBoundary() {
  return '----FormBoundary' + Math.random().toString(36).substring(2);
}

/**
 * Upload a file to UnknownCyber API using streams for large files
 */
function uploadFile(apiUrl, apiKey, filePath, filename, tag) {
  return new Promise((resolve, reject) => {
    const boundary = generateBoundary();
    const fileSize = fs.statSync(filePath).size;
    
    // Query parameters for upload
    const queryParams = new URLSearchParams({
      key: apiKey,
      skip_unpack: 'false',
      extract: 'true',
      recursive: 'true',
      retain_wrapper: 'true',
      no_links: 'true'
    });
    
    const url = new URL(`${apiUrl}/v2/files?${queryParams.toString()}`);
    
    // Build form data parts
    const fields = {
      filename: filename,
      tags: tag,
      notes: `Binary from npm package, scanned on ${new Date().toISOString()}`,
      password: ''
    };
    
    // Pre-file parts
    let preFileData = '';
    for (const [name, value] of Object.entries(fields)) {
      preFileData += `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="${name}"\r\n\r\n` +
        `${value}\r\n`;
    }
    preFileData += `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="filedata"; filename="${path.basename(filePath)}"\r\n` +
      `Content-Type: application/octet-stream\r\n\r\n`;
    
    // Post-file parts
    const postFileData = `\r\n--${boundary}--\r\n`;
    
    // Calculate total content length
    const contentLength = Buffer.byteLength(preFileData) + fileSize + Buffer.byteLength(postFileData);
    
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': contentLength
      },
      timeout: 300000 // 5 minute timeout for large files
    };
    
    const protocol = url.protocol === 'https:' ? https : http;
    
    const req = protocol.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve({ success: true, status: res.statusCode, data: JSON.parse(data) });
          } catch {
            resolve({ success: true, status: res.statusCode, data: data });
          }
        } else {
          resolve({ success: false, status: res.statusCode, error: data });
        }
      });
    });
    
    req.on('error', (err) => {
      reject(err);
    });
    
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    
    // Write pre-file data
    req.write(preFileData);
    
    // Stream the file
    const fileStream = fs.createReadStream(filePath);
    fileStream.on('data', chunk => req.write(chunk));
    fileStream.on('end', () => {
      req.write(postFileData);
      req.end();
    });
    fileStream.on('error', err => {
      req.destroy();
      reject(err);
    });
  });
}

/**
 * Upload all found binaries
 */
async function uploadBinaries(results, apiUrl, apiKey, repo) {
  console.log('\n' + '='.repeat(80));
  console.log('UPLOADING EXECUTABLES TO UNKNOWNCYBER');
  console.log('='.repeat(80));
  console.log(`API URL: ${apiUrl}`);
  if (repo) {
    console.log(`Repository: ${repo}`);
  }
  console.log(`Total files to upload: ${results.length}\n`);
  
  const uploadResults = {
    successful: [],
    failed: []
  };
  
  for (let i = 0; i < results.length; i++) {
    const binary = results[i];
    
    // Build tags array: SW_<package>@<version> and optionally REPO_<repo>
    const tags = [];
    tags.push(`SW_${binary.package}@${binary.version}`.replace(/\s+/g, '_'));
    if (repo) {
      tags.push(`REPO_${repo}`.replace(/\s+/g, '_'));
    }
    const tagString = tags.join(',');
    
    // Filename is the path below node_modules (using forward slashes)
    const filename = binary.file.replace(/\\/g, '/');
    
    process.stdout.write(`[${i + 1}/${results.length}] Uploading ${filename}... `);
    
    try {
      const result = await uploadFile(apiUrl, apiKey, binary.absolutePath, filename, tagString);
      
        if (result.success) {
          console.log('\x1b[32m✓ OK\x1b[0m');
          uploadResults.successful.push({
            file: filename,
            tags: tags,
            status: result.status
          });
        } else {
          console.log(`\x1b[31m✗ Failed (${result.status})\x1b[0m`);
          // Show error details
          if (result.error) {
            try {
              const errObj = JSON.parse(result.error);
              console.log(`      Error: ${JSON.stringify(errObj, null, 2).split('\n').join('\n      ')}`);
            } catch {
              console.log(`      Error: ${result.error.substring(0, 200)}`);
            }
          }
          uploadResults.failed.push({
            file: filename,
            tags: tags,
            status: result.status,
            error: result.error
          });
        }
    } catch (err) {
      console.log(`\x1b[31m✗ Error: ${err.message}\x1b[0m`);
      uploadResults.failed.push({
        file: filename,
        tags: tags,
        error: err.message
      });
    }
  }
  
  // Summary
  console.log('\n' + '-'.repeat(60));
  console.log('Upload Summary:');
  console.log(`  Successful: ${uploadResults.successful.length}`);
  console.log(`  Failed: ${uploadResults.failed.length}`);
  
  if (uploadResults.failed.length > 0) {
    console.log('\nFailed uploads:');
    for (const fail of uploadResults.failed) {
      console.log(`  - ${fail.file}: ${fail.error || `HTTP ${fail.status}`}`);
    }
  }
  
  return uploadResults;
}

/**
 * Main function to scan node_modules
 */
async function scanNodeModules(targetDir, options = {}) {
  const nodeModulesPath = path.join(targetDir, 'node_modules');
  
  if (!fs.existsSync(nodeModulesPath)) {
    console.error(`Error: node_modules not found at ${nodeModulesPath}`);
    console.error('Please run this tool from a directory containing node_modules, or specify the path as an argument.');
    process.exit(1);
  }

  console.log(`\nScanning: ${nodeModulesPath}`);
  console.log(`Deep magic byte scan: ${deepMagicScan ? 'enabled' : 'disabled (use --deep for thorough scan)'}\n`);

  const results = [];
  const startTime = Date.now();
  
  scanDirectory(nodeModulesPath, nodeModulesPath, results);
  
  // Clear progress line
  process.stdout.write('\r' + ' '.repeat(80) + '\r');
  
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

  // Group results by package
  const byPackage = {};
  let totalBinaries = 0;
  let totalScripts = 0;
  
  for (const result of results) {
    const key = `${result.package}@${result.version}`;
    if (!byPackage[key]) {
      byPackage[key] = {
        package: result.package,
        version: result.version,
        files: []
      };
    }
    byPackage[key].files.push({
      file: result.file,
      type: result.type,
      category: result.category || 'binary'
    });
    
    if (result.category === 'script') {
      totalScripts++;
    } else {
      totalBinaries++;
    }
  }

  // Sort packages alphabetically
  const sortedPackages = Object.values(byPackage).sort((a, b) => 
    a.package.localeCompare(b.package)
  );

  // Output results
  console.log('='.repeat(80));
  console.log('EXECUTABLES FOUND IN NODE_MODULES');
  console.log('='.repeat(80));
  console.log();

  if (sortedPackages.length === 0) {
    console.log('No executable files found.');
  } else {
    let totalFiles = 0;
    
    for (const pkg of sortedPackages) {
      console.log(`\x1b[36m📦 ${pkg.package}\x1b[0m @ \x1b[33m${pkg.version}\x1b[0m`);
      console.log('-'.repeat(60));
      
      for (const file of pkg.files) {
        const categoryIcon = file.category === 'script' ? '📜' : '⚙️';
        const typeColor = file.category === 'script' ? '\x1b[35m' : '\x1b[32m'; // magenta for scripts, green for binaries
        console.log(`   ${categoryIcon} [${typeColor}${file.type.padEnd(8)}\x1b[0m] ${file.file}`);
        totalFiles++;
      }
      console.log();
    }

    console.log('='.repeat(80));
    console.log('SUMMARY');
    console.log('='.repeat(80));
    console.log(`Total packages with executables: ${sortedPackages.length}`);
    console.log(`Total executable files found: ${totalFiles}`);
    console.log(`  - Binary files: ${totalBinaries}`);
    console.log(`  - Script files: ${totalScripts}`);
    console.log(`Directories scanned: ${scannedDirs}`);
    console.log(`Files checked: ${scannedFiles}`);
    console.log(`Scan completed in: ${elapsed}s`);
  }

  // Also output JSON for programmatic use
  const jsonOutput = {
    scanPath: nodeModulesPath,
    scanDate: new Date().toISOString(),
    deepScan: deepMagicScan,
    totalPackages: sortedPackages.length,
    totalExecutables: results.length,
    totalBinaries: totalBinaries,
    totalScripts: totalScripts,
    directoriesScanned: scannedDirs,
    filesChecked: scannedFiles,
    packages: sortedPackages
  };

  const jsonOutputPath = path.join(targetDir, 'binary-scan-results.json');
  fs.writeFileSync(jsonOutputPath, JSON.stringify(jsonOutput, null, 2));
  console.log(`\nDetailed results saved to: ${jsonOutputPath}`);

  // Upload if requested
  if (options.upload && results.length > 0) {
    if (!options.apiKey) {
      console.error('\nError: API key required for upload. Use --api-key or set UC_API_KEY environment variable.');
      process.exit(1);
    }
    if (!options.apiUrl) {
      console.error('\nError: API URL required for upload. Use --api-url or set UC_API_URL environment variable.');
      process.exit(1);
    }
    
    const uploadResults = await uploadBinaries(results, options.apiUrl, options.apiKey, options.repo);
    jsonOutput.uploadResults = uploadResults;
    
    // Update JSON with upload results
    fs.writeFileSync(jsonOutputPath, JSON.stringify(jsonOutput, null, 2));
  }

  return jsonOutput;
}

/**
 * Parse command line arguments
 */
function parseArgs(args) {
  const options = {
    targetDir: process.cwd(),
    deep: false,
    upload: false,
    apiUrl: process.env.UC_API_URL || '',
    apiKey: process.env.UC_API_KEY || '',
    repo: process.env.UC_REPO || ''
  };
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else if (arg === '--deep') {
      options.deep = true;
    } else if (arg === '--upload') {
      options.upload = true;
    } else if (arg === '--api-url') {
      options.apiUrl = args[++i];
    } else if (arg === '--api-key') {
      options.apiKey = args[++i];
    } else if (arg === '--repo') {
      options.repo = args[++i];
    } else if (!arg.startsWith('-')) {
      options.targetDir = path.resolve(arg);
    }
  }
  
  return options;
}

function printHelp() {
  console.log(`
NPM Binary Scanner
==================

Scans npm packages (node_modules) for binary executables and executable scripts,
then optionally uploads them to UnknownCyber API for security analysis.

Usage:
  node scanner.js [options] [path]

Options:
  --deep              Enable deep scan using magic bytes (slower but finds more)
  --upload            Upload found executables to UnknownCyber API
  --api-url <url>     API base URL (or set UC_API_URL env var)
  --api-key <key>     API key for authentication (or set UC_API_KEY env var)
  --repo <name>       Repository name to tag uploads with (or set UC_REPO env var)
  --help, -h          Show this help message

Examples:
  # Scan current directory
  node scanner.js
  
  # Scan specific directory  
  node scanner.js ./my-project
  
  # Deep scan with magic byte detection
  node scanner.js --deep
  
  # Scan and upload to UnknownCyber
  node scanner.js --upload --api-url https://api.unknowncyber.com --api-key YOUR_KEY
  
  # Scan and upload with repository tag
  node scanner.js --upload --repo my-org/my-repo --api-key YOUR_KEY
  
  # Using environment variables
  set UC_API_URL=https://api.unknowncyber.com
  set UC_API_KEY=your-api-key
  set UC_REPO=my-org/my-repo
  node scanner.js --upload

Detected Binary Types:
  - Windows: EXE, DLL, SYS, OCX, COM, SCR
  - Linux: ELF executables, SO (shared objects), O, A
  - macOS: Mach-O, DYLIB, Bundle
  - Node.js: .node (native addons)
  - WebAssembly: WASM
  - Other: BIN, DAT

Detected Script Types (potential attack vectors):
  - Windows: BAT, CMD, PS1, VBS, VBE, WSF, WSH
  - Unix: SH, BASH, ZSH, CSH, KSH
  - Cross-platform: PL (Perl), RB (Ruby), PY/PYW (Python)

Upload Details:
  When --upload is specified, each executable is uploaded with:
  - Filename: Path relative to node_modules (e.g., "@esbuild/win32-x64/esbuild.exe")
  - Tags: "SW_<package>@<version>" (e.g., "SW_@esbuild/win32-x64@0.20.2")
          "REPO_<repo>" if --repo is specified (e.g., "REPO_my-org/my-repo")

Output:
  - Console output grouped by package (⚙️ for binaries, 📜 for scripts)
  - JSON file (binary-scan-results.json) with detailed results and upload status
`);
}

// Main entry point
const args = process.argv.slice(2);
const options = parseArgs(args);

deepMagicScan = options.deep;

scanNodeModules(options.targetDir, options);
