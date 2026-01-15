#!/usr/bin/env node

/**
 * UC Software Scan - Multi-Ecosystem Package Scanner
 * 
 * Scans software packages for binary executables, scripts, and security threats.
 * Supports: npm, pip, maven, cargo, go, ruby, nuget, dpkg, apk, rpm.
 * Reports the package name, version, and file paths for each binary found.
 * Optionally uploads found binaries to UnknownCyber API for threat analysis.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const { URL } = require('url');

// Ecosystem configuration module
const { 
  ECOSYSTEMS, 
  detectEcosystems, 
  getEcosystem, 
  getAvailableEcosystems,
  findEcosystemDirectory,
  findEcosystemScanDirectories
} = require('./ecosystems');

// File reputation module for checking existing files
const { createReputationClient, checkFileExistence, getFileReputations, getFileTags, addFileTags } = require('./file-reputation');

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
  '.wasm',
  // Java
  '.jar', '.war', '.ear', '.class'
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
  // Java class file
  JAVA_CLASS: Buffer.from([0xca, 0xfe, 0xba, 0xbe]),
  // ZIP (JAR, WAR, etc.)
  ZIP: Buffer.from([0x50, 0x4b, 0x03, 0x04]),
};

// Directories to skip for faster scanning
const SKIP_DIRS = new Set([
  '.bin', '.cache', '.git', '.github', '.vscode',
  '__tests__', '__mocks__', 'test', 'tests', 'spec', 'specs',
  'docs', 'doc', 'documentation', 'example', 'examples',
  'coverage', '.nyc_output', 'typings', '@types',
  '__pycache__', '.pytest_cache', '.tox', '.mypy_cache',
  '.gradle', '.idea', '.settings'
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
  /\.lock$/,
  /\.pyc$/,
  /\.pyo$/
];

// Lock files by ecosystem for SBOM generation
const LOCK_FILES = {
  npm: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
  pip: ['requirements.txt', 'Pipfile.lock', 'poetry.lock'],
  cargo: ['Cargo.lock'],
  go: ['go.sum', 'go.mod'],
  ruby: ['Gemfile.lock'],
  nuget: ['packages.lock.json'],
  maven: ['pom.xml'] // Maven uses pom.xml for dependency management
};

let deepMagicScan = false;
let includePackageJson = false;
let includeLockFiles = false;
let includeAllFiles = false;
let scannedDirs = 0;
let scannedFiles = 0;

/**
 * Compute SHA256 hash of a file
 * @param {string} filePath - Path to file
 * @returns {Promise<string>} - SHA256 hash in lowercase hex
 */
function computeFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    
    stream.on('data', data => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

/**
 * Compute hashes for all binary files
 * @param {object[]} results - Array of scan results
 * @returns {Promise<object[]>} - Results with sha256 property added
 */
async function computeHashes(results) {
  console.log('\nComputing file hashes...');
  
  for (let i = 0; i < results.length; i++) {
    const binary = results[i];
    process.stdout.write(`\rHashing [${i + 1}/${results.length}]: ${binary.file.substring(0, 50)}...`);
    
    try {
      binary.sha256 = await computeFileHash(binary.absolutePath);
    } catch (err) {
      console.log(`\n  Warning: Could not hash ${binary.file}: ${err.message}`);
      binary.sha256 = null;
    }
  }
  
  process.stdout.write('\r' + ' '.repeat(80) + '\r');
  console.log(`Computed hashes for ${results.filter(r => r.sha256).length} files`);
  
  return results;
}

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
  if (BINARY_EXTENSIONS.has(ext)) return true;
  
  // Check for versioned shared libraries (e.g., libssl.so.1.1, libcurl.so.4.6.0)
  const filename = path.basename(filePath).toLowerCase();
  if (/\.so\.\d/.test(filename)) return true;
  
  // Check for versioned DLLs (e.g., mylib.dll.1)
  if (/\.dll\.\d/.test(filename)) return true;
  
  // Check for versioned dylibs (e.g., libssl.1.0.dylib)
  if (/\.\d+\.dylib$/.test(filename)) return true;
  
  return false;
}

/**
 * Check if a file is an executable script by extension
 */
function isScriptByExtension(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return SCRIPT_EXTENSIONS.has(ext);
}

/**
 * Check if a file is a lock file for the given ecosystem
 */
function isLockFile(filename, ecosystem) {
  if (!ecosystem) return false;
  const lockFiles = LOCK_FILES[ecosystem.name] || [];
  return lockFiles.includes(filename);
}

/**
 * Should skip this file based on patterns and scan mode?
 */
function shouldSkipFile(filename) {
  // If including all files, don't skip anything
  if (includeAllFiles) return false;
  
  // If including package.json, don't skip it
  if (includePackageJson && filename === 'package.json') return false;
  
  // If including lock files, check if this is a lock file
  if (includeLockFiles) {
    // Check against all ecosystem lock files
    for (const lockFiles of Object.values(LOCK_FILES)) {
      if (lockFiles.includes(filename)) return false;
    }
  }
  
  return SKIP_PATTERNS.some(pattern => pattern.test(filename));
}

/**
 * Recursively scan a directory for binary files
 * @param {string} dir - Directory to scan
 * @param {string} rootDir - Root package directory
 * @param {object[]} results - Array to store results
 * @param {object} ecosystem - Ecosystem configuration
 * @param {Set} visited - Set of visited directories (for symlink handling)
 */
function scanDirectory(dir, rootDir, results, ecosystem, visited = new Set()) {
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
        // Skip dist-info and egg-info directories (Python metadata)
        if (entry.name.endsWith('.dist-info') || entry.name.endsWith('.egg-info')) continue;
        scanDirectory(fullPath, rootDir, results, ecosystem, visited);
      } else if (entry.isFile()) {
        scannedFiles++;
        
        // Skip files that definitely won't be of interest
        if (shouldSkipFile(entry.name)) continue;
        
        let detectedType = null;
        let category = 'binary'; // 'binary', 'script', 'metadata', or 'other'
        
        // Check for binary by extension first (faster)
        if (isBinaryByExtension(fullPath)) {
          // Handle versioned shared libraries (e.g., libssl.so.1.1 -> SO)
          const filename = path.basename(fullPath).toLowerCase();
          if (/\.so\.\d/.test(filename)) {
            detectedType = 'SO';
          } else if (/\.dll\.\d/.test(filename)) {
            detectedType = 'DLL';
          } else if (/\.\d+\.dylib$/.test(filename)) {
            detectedType = 'DYLIB';
          } else {
            detectedType = path.extname(fullPath).toLowerCase().slice(1).toUpperCase();
          }
        } 
        // Check for executable scripts
        else if (isScriptByExtension(fullPath)) {
          detectedType = path.extname(fullPath).toLowerCase().slice(1).toUpperCase();
          category = 'script';
        }
        // Check for package.json (for SBOM)
        else if ((includePackageJson || includeAllFiles) && entry.name === 'package.json') {
          detectedType = 'JSON';
          category = 'metadata';
        }
        // Check for lock files (for SBOM)
        else if ((includeLockFiles || includeAllFiles) && isLockFile(entry.name, ecosystem)) {
          detectedType = 'LOCK';
          category = 'metadata';
        }
        // Deep scan: check magic bytes for binaries without known extensions
        else if (deepMagicScan) {
          const magicType = checkMagicBytes(fullPath);
          if (magicType) {
            detectedType = magicType;
          }
        }
        
        // Include all other files if in all-files mode (and no type detected yet)
        if (!detectedType && includeAllFiles) {
          const ext = path.extname(fullPath).toLowerCase();
          detectedType = ext ? ext.slice(1).toUpperCase() : 'FILE';
          category = 'other';
        }

        if (detectedType) {
          const packageInfo = ecosystem.findPackageInfo(fullPath, rootDir);
          const relativePath = path.relative(rootDir, fullPath);
          
          results.push({
            file: relativePath,
            absolutePath: fullPath,
            type: detectedType,
            category: category,
            ecosystem: ecosystem.name,
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
 * @param {string} apiUrl - API base URL
 * @param {string} apiKey - API key
 * @param {string} filePath - Local file path
 * @param {string} filename - Filename for upload
 * @param {string[]} tags - Array of tags to attach
 */
function uploadFile(apiUrl, apiKey, filePath, filename, tags) {
  return new Promise((resolve, reject) => {
    const boundary = generateBoundary();
    const fileSize = fs.statSync(filePath).size;
    
    // Build query parameters - each tag as separate tags[] parameter
    const queryParams = new URLSearchParams({
      key: apiKey,
      skip_unpack: 'false',
      extract: 'true',
      recursive: 'true',
      retain_wrapper: 'true',
      no_links: 'true'
    });
    // Add each tag as a separate tags[] query parameter
    for (const tag of tags) {
      queryParams.append('tags[]', tag);
    }
    
    const url = new URL(`${apiUrl}/v2/files?${queryParams.toString()}`);
    
    // Build form data parts - each tag as separate multipart section
    let preFileData = '';
    
    // Filename field
    preFileData += `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="filename"\r\n\r\n` +
      `${filename}\r\n`;
    
    // Each tag as a separate form-data part with name="tags"
    for (const tag of tags) {
      preFileData += `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="tags"\r\n\r\n` +
        `${tag}\r\n`;
    }
    
    // Notes field
    preFileData += `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="notes"\r\n\r\n` +
      `Binary from package scan, scanned on ${new Date().toISOString()}\r\n`;
    
    // Password field (empty)
    preFileData += `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="password"\r\n\r\n` +
      `\r\n`;
    
    // File data part header
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
 * Check which files already exist in UnknownCyber
 * @param {object[]} results - Array of scan results with sha256 hashes
 * @param {string} apiUrl - API base URL
 * @param {string} apiKey - API key
 * @returns {Promise<{toUpload: object[], existing: object[]}>}
 */
async function checkExistingFiles(results, apiUrl, apiKey) {
  console.log('\n' + '='.repeat(80));
  console.log('CHECKING EXISTING FILES IN UNKNOWNCYBER');
  console.log('='.repeat(80));
  
  // Filter results that have valid hashes
  const hashableResults = results.filter(r => r.sha256);
  console.log(`\nChecking ${hashableResults.length} files with valid hashes...`);
  
  if (hashableResults.length === 0) {
    return { toUpload: results, existing: [] };
  }
  
  try {
    const client = createReputationClient({ apiUrl, apiKey });
    const hashes = hashableResults.map(r => r.sha256);
    
    // Check existence in batches
    const { existing: existingHashes, notFound: notFoundHashes } = await checkFileExistence(client, hashes, {
      concurrency: 10
    });
    
    const existingSet = new Set(existingHashes);
    const existing = hashableResults.filter(r => existingSet.has(r.sha256));
    const toUpload = results.filter(r => !r.sha256 || !existingSet.has(r.sha256));
    
    console.log(`\n  Already in UC: ${existing.length} files`);
    console.log(`  New files to upload: ${toUpload.length} files`);
    
    if (existing.length > 0) {
      console.log('\n  Existing files (will skip):');
      for (const file of existing.slice(0, 10)) {
        console.log(`    - ${file.file} (${file.sha256.substring(0, 12)}...)`);
      }
      if (existing.length > 10) {
        console.log(`    ... and ${existing.length - 10} more`);
      }
    }
    
    return { toUpload, existing };
  } catch (err) {
    console.log(`\n  Warning: Could not check existing files: ${err.message}`);
    console.log('  Will attempt to upload all files...');
    return { toUpload: results, existing: [] };
  }
}

/**
 * Get reputation data for existing files
 * @param {object[]} existingFiles - Files that exist in UC
 * @param {string} apiUrl - API base URL
 * @param {string} apiKey - API key
 * @returns {Promise<object[]>}
 */
async function getReputationsForExisting(existingFiles, apiUrl, apiKey) {
  if (existingFiles.length === 0) return [];
  
  console.log('\n' + '-'.repeat(60));
  console.log('Getting reputation data for existing files...');
  
  try {
    const client = createReputationClient({ apiUrl, apiKey });
    const reputations = [];
    
    for (let i = 0; i < existingFiles.length; i++) {
      const file = existingFiles[i];
      process.stdout.write(`\r  [${i + 1}/${existingFiles.length}] Checking ${file.file.substring(0, 40)}...`);
      
      try {
        const rep = await getFileReputations(client, file.sha256);
        reputations.push({
          file: file.file,
          sha256: file.sha256,
          package: file.package,
          version: file.version,
          ecosystem: file.ecosystem,
          reputation: rep
        });
      } catch (err) {
        reputations.push({
          file: file.file,
          sha256: file.sha256,
          package: file.package,
          version: file.version,
          ecosystem: file.ecosystem,
          error: err.message
        });
      }
    }
    
    process.stdout.write('\r' + ' '.repeat(80) + '\r');
    
    // Summary of reputations
    const byThreat = { high: 0, medium: 0, caution: 0, low: 0, none: 0, unknown: 0 };
    for (const rep of reputations) {
      if (rep.reputation) {
        byThreat[rep.reputation.overallThreatLevel] = (byThreat[rep.reputation.overallThreatLevel] || 0) + 1;
      }
    }
    
    console.log('  Reputation summary for existing files:');
    if (byThreat.high > 0) console.log(`    \x1b[31m⚠ HIGH: ${byThreat.high}\x1b[0m`);
    if (byThreat.medium > 0) console.log(`    \x1b[33m⚠ MEDIUM: ${byThreat.medium}\x1b[0m`);
    if (byThreat.caution > 0) console.log(`    \x1b[33m! CAUTION: ${byThreat.caution}\x1b[0m`);
    if (byThreat.low > 0) console.log(`    \x1b[32m✓ LOW: ${byThreat.low}\x1b[0m`);
    if (byThreat.none > 0) console.log(`    \x1b[32m✓ NONE: ${byThreat.none}\x1b[0m`);
    if (byThreat.unknown > 0) console.log(`    ? UNKNOWN: ${byThreat.unknown}`);
    
    return reputations;
  } catch (err) {
    console.log(`\n  Warning: Could not get reputations: ${err.message}`);
    return [];
  }
}

/**
 * Sync tags for existing files - add missing tags
 * @param {object[]} existingFiles - Files that exist in UC
 * @param {string} apiUrl - API base URL
 * @param {string} apiKey - API key
 * @param {string} repo - Repository name (optional)
 * @returns {Promise<object>} - { synced: [], alreadyTagged: [], failed: [] }
 */
async function syncTagsForExisting(existingFiles, apiUrl, apiKey, repo) {
  if (existingFiles.length === 0) return { synced: [], alreadyTagged: [], failed: [] };
  
  console.log('\n' + '-'.repeat(60));
  console.log('Syncing tags for existing files...');
  
  const results = { synced: [], alreadyTagged: [], failed: [] };
  
  try {
    const client = createReputationClient({ apiUrl, apiKey });
    
    for (let i = 0; i < existingFiles.length; i++) {
      const file = existingFiles[i];
      process.stdout.write(`\r  [${i + 1}/${existingFiles.length}] Checking tags for ${file.file.substring(0, 40)}...`);
      
      // Get ecosystem config for tag prefix
      const ecosystem = getEcosystem(file.ecosystem) || getEcosystem('generic');
      
      // Build expected tags
      const expectedTags = [];
      expectedTags.push(`${ecosystem.tagPrefix}/${file.package}_${file.version}`.replace(/\s+/g, '_'));
      if (repo) {
        expectedTags.push(`REPO_${repo}`.replace(/\s+/g, '_'));
      }
      
      try {
        // Get current tags
        const currentTags = await getFileTags(client, file.sha256);
        const currentTagSet = new Set(currentTags);
        
        // Find missing tags
        const missingTags = expectedTags.filter(t => !currentTagSet.has(t));
        
        if (missingTags.length === 0) {
          results.alreadyTagged.push({
            file: file.file,
            sha256: file.sha256,
            tags: expectedTags
          });
        } else {
          // Add missing tags
          const addResult = await addFileTags(client, file.sha256, missingTags);
          
          if (addResult.added.length > 0 || addResult.existing.length > 0) {
            results.synced.push({
              file: file.file,
              sha256: file.sha256,
              addedTags: addResult.added,
              existingTags: addResult.existing
            });
          }
          
          if (addResult.failed.length > 0) {
            results.failed.push({
              file: file.file,
              sha256: file.sha256,
              failedTags: addResult.failed
            });
          }
        }
      } catch (err) {
        results.failed.push({
          file: file.file,
          sha256: file.sha256,
          error: err.message
        });
      }
    }
    
    process.stdout.write('\r' + ' '.repeat(80) + '\r');
    
    // Summary
    console.log('  Tag sync summary:');
    console.log(`    Already tagged: ${results.alreadyTagged.length}`);
    console.log(`    Tags added: ${results.synced.length}`);
    if (results.failed.length > 0) {
      console.log(`    \x1b[31mFailed: ${results.failed.length}\x1b[0m`);
    }
    
    return results;
  } catch (err) {
    console.log(`\n  Warning: Could not sync tags: ${err.message}`);
    return results;
  }
}

/**
 * Upload all found binaries
 */
async function uploadBinaries(results, apiUrl, apiKey, repo, options = {}) {
  const { skipExisting = true, getReputations = true } = options;
  
  // Compute hashes first
  await computeHashes(results);
  
  let toUpload = results;
  let existingFiles = [];
  let existingReputations = [];
  
  // Check for existing files if enabled
  let tagSyncResults = { synced: [], alreadyTagged: [], failed: [] };
  
  if (skipExisting) {
    const checkResult = await checkExistingFiles(results, apiUrl, apiKey);
    toUpload = checkResult.toUpload;
    existingFiles = checkResult.existing;
    
    // Sync tags for existing files (add missing tags)
    if (existingFiles.length > 0) {
      tagSyncResults = await syncTagsForExisting(existingFiles, apiUrl, apiKey, repo);
    }
    
    // Get reputations for existing EXECUTABLE files only (not metadata/other)
    if (getReputations && existingFiles.length > 0) {
      const executableFiles = existingFiles.filter(f => 
        f.category === 'binary' || f.category === 'script' || !f.category
      );
      if (executableFiles.length > 0) {
        existingReputations = await getReputationsForExisting(executableFiles, apiUrl, apiKey);
      }
    }
  }
  
  console.log('\n' + '='.repeat(80));
  console.log('UPLOADING EXECUTABLES TO UNKNOWNCYBER');
  console.log('='.repeat(80));
  console.log(`API URL: ${apiUrl}`);
  if (repo) {
    console.log(`Repository: ${repo}`);
  }
  console.log(`Total files to upload: ${toUpload.length} (${existingFiles.length} already exist)\n`);
  
  const uploadResults = {
    successful: [],
    failed: [],
    skipped: existingFiles.map(f => ({
      file: f.file,
      sha256: f.sha256,
      reason: 'already_exists'
    })),
    tagSync: tagSyncResults,
    reputations: existingReputations
  };
  
  if (toUpload.length === 0) {
    console.log('No new files to upload.');
    return uploadResults;
  }
  
  for (let i = 0; i < toUpload.length; i++) {
    const binary = toUpload[i];
    
    // Get ecosystem config for tag prefix
    const ecosystem = getEcosystem(binary.ecosystem) || getEcosystem('generic');
    
    // Build tags array: SW_<pm>/<package>_<version> and optionally REPO_<repo>
    const tags = [];
    tags.push(`${ecosystem.tagPrefix}/${binary.package}_${binary.version}`.replace(/\s+/g, '_'));
    if (repo) {
      tags.push(`REPO_${repo}`.replace(/\s+/g, '_'));
    }
    
    // Filename is the relative path (using forward slashes)
    const filename = binary.file.replace(/\\/g, '/');
    
    process.stdout.write(`[${i + 1}/${toUpload.length}] Uploading ${filename}... `);
    
    try {
      const result = await uploadFile(apiUrl, apiKey, binary.absolutePath, filename, tags);
      
        if (result.success) {
          console.log('\x1b[32m✓ OK\x1b[0m');
          uploadResults.successful.push({
            file: filename,
            sha256: binary.sha256,
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
            sha256: binary.sha256,
            tags: tags,
            status: result.status,
            error: result.error
          });
        }
    } catch (err) {
      console.log(`\x1b[31m✗ Error: ${err.message}\x1b[0m`);
      uploadResults.failed.push({
        file: filename,
        sha256: binary.sha256,
        tags: tags,
        error: err.message
      });
    }
  }
  
  // Summary
  console.log('\n' + '-'.repeat(60));
  console.log('Upload Summary:');
  console.log(`  Uploaded: ${uploadResults.successful.length}`);
  console.log(`  Failed: ${uploadResults.failed.length}`);
  console.log(`  Skipped (already exist): ${uploadResults.skipped.length}`);
  
  if (uploadResults.failed.length > 0) {
    console.log('\nFailed uploads:');
    for (const fail of uploadResults.failed) {
      console.log(`  - ${fail.file}: ${fail.error || `HTTP ${fail.status}`}`);
    }
  }
  
  // Report on threats found in existing files and emit GitHub Actions annotations
  emitThreatAnnotations(existingReputations);
  
  return uploadResults;
}

/**
 * Emit GitHub Actions annotations for threat detections
 * @param {object[]} reputations - Array of reputation results
 */
function emitThreatAnnotations(reputations) {
  if (!reputations || reputations.length === 0) return;
  
  const threats = {
    high: [],
    medium: [],
    caution: []
  };
  
  // Categorize threats by reputation type
  for (const rep of reputations) {
    if (!rep.reputation) continue;
    
    const file = rep.file;
    const pkg = `${rep.package}@${rep.version}`;
    const r = rep.reputation;
    
    // AV reputation
    if (r.antivirus) {
      const avLevel = r.antivirus.threatLevel;
      if (avLevel === 'high') {
        threats.high.push({
          type: 'AV',
          file,
          pkg,
          detail: `AV Detection: ${r.antivirus.detectionRatio} - ${r.antivirus.verdict}`,
          topThreats: r.antivirus.topThreats?.slice(0, 3).join(', ')
        });
      } else if (avLevel === 'medium') {
        threats.medium.push({
          type: 'AV',
          file,
          pkg,
          detail: `AV Detection: ${r.antivirus.detectionRatio} - ${r.antivirus.verdict}`
        });
      } else if (avLevel === 'caution') {
        threats.caution.push({
          type: 'AV',
          file,
          pkg,
          detail: `AV Detection: ${r.antivirus.detectionRatio} - ${r.antivirus.verdict}`
        });
      }
    }
    
    // Similarity reputation
    if (r.similarity) {
      const simLevel = r.similarity.threatLevel;
      if (simLevel === 'high') {
        threats.high.push({
          type: 'Similarity',
          file,
          pkg,
          detail: `Malicious clone detected (${r.similarity.cloneCount} clones, ${r.similarity.similarCount} similar)`
        });
      } else if (simLevel === 'medium') {
        threats.medium.push({
          type: 'Similarity',
          file,
          pkg,
          detail: `Suspicious similarity (${r.similarity.similarCount} similar files)`
        });
      }
    }
    
    // Signature reputation
    if (r.signature) {
      const sigLevel = r.signature.threatLevel;
      if (sigLevel === 'high') {
        threats.high.push({
          type: 'Signature',
          file,
          pkg,
          detail: `Invalid code signature: ${r.signature.signatureStatus}`
        });
      } else if (sigLevel === 'caution' && r.signature.signatureStatus === 'unsigned') {
        threats.caution.push({
          type: 'Signature',
          file,
          pkg,
          detail: 'Unsigned binary'
        });
      }
    }
  }
  
  // Print console summary
  const totalThreats = threats.high.length + threats.medium.length + threats.caution.length;
  if (totalThreats > 0) {
    console.log('\n' + '='.repeat(60));
    console.log('\x1b[31m⚠  THREAT ANALYSIS RESULTS\x1b[0m');
    console.log('='.repeat(60));
    
    if (threats.high.length > 0) {
      console.log(`\n\x1b[31m  HIGH THREATS: ${threats.high.length}\x1b[0m`);
      for (const t of threats.high) {
        console.log(`    [${t.type}] ${t.file}`);
        console.log(`           Package: ${t.pkg}`);
        console.log(`           ${t.detail}`);
        if (t.topThreats) console.log(`           Threats: ${t.topThreats}`);
      }
    }
    
    if (threats.medium.length > 0) {
      console.log(`\n\x1b[33m  MEDIUM THREATS: ${threats.medium.length}\x1b[0m`);
      for (const t of threats.medium) {
        console.log(`    [${t.type}] ${t.file}`);
        console.log(`           Package: ${t.pkg}`);
        console.log(`           ${t.detail}`);
      }
    }
    
    if (threats.caution.length > 0) {
      console.log(`\n\x1b[33m  CAUTION: ${threats.caution.length}\x1b[0m`);
      for (const t of threats.caution) {
        console.log(`    [${t.type}] ${t.file}`);
        console.log(`           ${t.detail}`);
      }
    }
  }
  
  // Emit GitHub Actions annotations
  // HIGH threats = errors
  for (const t of threats.high) {
    const msg = `[${t.type}] ${t.pkg}: ${t.detail}`;
    console.log(`::error title=High Threat - ${t.type}::${t.file} - ${msg}`);
  }
  
  // MEDIUM threats = warnings
  for (const t of threats.medium) {
    const msg = `[${t.type}] ${t.pkg}: ${t.detail}`;
    console.log(`::warning title=Medium Threat - ${t.type}::${t.file} - ${msg}`);
  }
  
  // CAUTION = notices
  for (const t of threats.caution) {
    const msg = `[${t.type}] ${t.pkg}: ${t.detail}`;
    console.log(`::notice title=Caution - ${t.type}::${t.file} - ${msg}`);
  }
  
  return threats;
}

/**
 * Main function to scan packages
 * @param {string} targetDir - Directory to scan
 * @param {object} options - Scan options
 */
async function scanPackages(targetDir, options = {}) {
  const {
    ecosystems: requestedEcosystems = [],
    autoDetect = true
  } = options;
  
  // Determine which ecosystems to scan
  let ecosystemsToScan = [];
  
  if (requestedEcosystems.length > 0) {
    // Use explicitly requested ecosystems
    ecosystemsToScan = requestedEcosystems.map(name => {
      const eco = getEcosystem(name);
      if (!eco) {
        console.warn(`Warning: Unknown ecosystem '${name}', skipping`);
        return null;
      }
      return eco;
    }).filter(Boolean);
  } else if (autoDetect) {
    // Auto-detect ecosystems
    const detected = detectEcosystems(targetDir);
    if (detected.length > 0) {
      ecosystemsToScan = detected.map(name => getEcosystem(name));
      console.log(`\nAuto-detected ecosystems: ${detected.join(', ')}`);
    } else {
      console.log('\nNo known package ecosystems detected. Use --ecosystem to specify one.');
      console.log(`Available ecosystems: ${getAvailableEcosystems().join(', ')}`);
      process.exit(1);
    }
  }
  
  if (ecosystemsToScan.length === 0) {
    console.error('Error: No ecosystems to scan');
    process.exit(1);
  }
  
  const allResults = [];
  const startTime = Date.now();
  
  // Scan each ecosystem
  for (const ecosystem of ecosystemsToScan) {
    // For Linux package managers (dpkg, apk, rpm), scan multiple library directories
    // For other ecosystems, scan the single package directory
    const scanDirs = findEcosystemScanDirectories(targetDir, ecosystem.name);
    
    if (scanDirs.length === 0) {
      // Fallback to detection directory
      const detectionDir = findEcosystemDirectory(targetDir, ecosystem.name);
      if (!detectionDir) {
        console.log(`\nSkipping ${ecosystem.displayName}: directory not found`);
        continue;
      }
      scanDirs.push(detectionDir);
    }
    
    console.log(`\n${'='.repeat(80)}`);
    console.log(`SCANNING ${ecosystem.displayName.toUpperCase()}`);
    console.log('='.repeat(80));
    console.log(`Directories: ${scanDirs.map(d => path.relative(targetDir, d) || '.').join(', ')}`);
    console.log(`Deep magic byte scan: ${deepMagicScan ? 'enabled' : 'disabled (use --deep for thorough scan)'}\n`);
    
    const results = [];
    scannedDirs = 0;
    scannedFiles = 0;
    
    // Scan all relevant directories for this ecosystem
    for (const scanDir of scanDirs) {
      scanDirectory(scanDir, targetDir, results, ecosystem);
    }
    
    // Clear progress line
    process.stdout.write('\r' + ' '.repeat(80) + '\r');
    
    console.log(`Found ${results.length} files in ${ecosystem.displayName}`);
    allResults.push(...results);
  }
  
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

  // Group results by package
  const byPackage = {};
  let totalBinaries = 0;
  let totalScripts = 0;
  let totalMetadata = 0;
  let totalOther = 0;
  
  for (const result of allResults) {
    const key = `${result.ecosystem}:${result.package}@${result.version}`;
    if (!byPackage[key]) {
      byPackage[key] = {
        ecosystem: result.ecosystem,
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
    
    switch (result.category) {
      case 'script':
        totalScripts++;
        break;
      case 'metadata':
        totalMetadata++;
        break;
      case 'other':
        totalOther++;
        break;
      default:
        totalBinaries++;
    }
  }

  // Sort packages by ecosystem then name
  const sortedPackages = Object.values(byPackage).sort((a, b) => {
    if (a.ecosystem !== b.ecosystem) {
      return a.ecosystem.localeCompare(b.ecosystem);
    }
    return a.package.localeCompare(b.package);
  });

  // Output results
  console.log('\n' + '='.repeat(80));
  console.log('EXECUTABLES FOUND');
  console.log('='.repeat(80));
  console.log();

  if (sortedPackages.length === 0) {
    console.log('No executable files found.');
  } else {
    let totalFiles = 0;
    let currentEcosystem = null;
    
    for (const pkg of sortedPackages) {
      // Print ecosystem header when it changes
      if (pkg.ecosystem !== currentEcosystem) {
        currentEcosystem = pkg.ecosystem;
        const eco = getEcosystem(currentEcosystem);
        console.log(`\n\x1b[35m▶ ${eco ? eco.displayName : currentEcosystem}\x1b[0m`);
        console.log('-'.repeat(60));
      }
      
      console.log(`\x1b[36m📦 ${pkg.package}\x1b[0m @ \x1b[33m${pkg.version}\x1b[0m`);
      
      for (const file of pkg.files) {
        let categoryIcon, typeColor;
        switch (file.category) {
          case 'script':
            categoryIcon = '📜';
            typeColor = '\x1b[35m'; // magenta
            break;
          case 'metadata':
            categoryIcon = '📋';
            typeColor = '\x1b[36m'; // cyan
            break;
          case 'other':
            categoryIcon = '📄';
            typeColor = '\x1b[90m'; // gray
            break;
          default:
            categoryIcon = '⚙️';
            typeColor = '\x1b[32m'; // green
        }
        console.log(`   ${categoryIcon} [${typeColor}${file.type.padEnd(8)}\x1b[0m] ${file.file}`);
        totalFiles++;
      }
    }

    console.log('\n' + '='.repeat(80));
    console.log('SUMMARY');
    console.log('='.repeat(80));
    console.log(`Ecosystems scanned: ${ecosystemsToScan.map(e => e.displayName).join(', ')}`);
    console.log(`Total packages with files: ${sortedPackages.length}`);
    console.log(`Total files found: ${totalFiles}`);
    console.log(`  - Binary files: ${totalBinaries}`);
    console.log(`  - Script files: ${totalScripts}`);
    if (totalMetadata > 0) console.log(`  - Metadata files: ${totalMetadata}`);
    if (totalOther > 0) console.log(`  - Other files: ${totalOther}`);
    console.log(`Scan completed in: ${elapsed}s`);
  }

  // Also output JSON for programmatic use
  const jsonOutput = {
    scanPath: targetDir,
    scanDate: new Date().toISOString(),
    deepScan: deepMagicScan,
    includePackageJson: includePackageJson,
    includeAllFiles: includeAllFiles,
    ecosystems: ecosystemsToScan.map(e => e.name),
    totalPackages: sortedPackages.length,
    totalFiles: allResults.length,
    totalBinaries: totalBinaries,
    totalScripts: totalScripts,
    totalMetadata: totalMetadata,
    totalOther: totalOther,
    packages: sortedPackages
  };

  const jsonOutputPath = path.join(targetDir, 'binary-scan-results.json');
  fs.writeFileSync(jsonOutputPath, JSON.stringify(jsonOutput, null, 2));
  console.log(`\nDetailed results saved to: ${jsonOutputPath}`);

  // Upload if requested
  if (options.upload && allResults.length > 0) {
    if (!options.apiKey) {
      console.error('\nError: API key required for upload. Use --api-key or set UC_API_KEY environment variable.');
      process.exit(1);
    }
    if (!options.apiUrl) {
      console.error('\nError: API URL required for upload. Use --api-url or set UC_API_URL environment variable.');
      process.exit(1);
    }
    
    const uploadResults = await uploadBinaries(allResults, options.apiUrl, options.apiKey, options.repo, {
      skipExisting: options.skipExisting,
      getReputations: options.getReputations
    });
    jsonOutput.uploadResults = uploadResults;
    
    // Update JSON with upload results
    fs.writeFileSync(jsonOutputPath, JSON.stringify(jsonOutput, null, 2));
  }

  return jsonOutput;
}

// Legacy function for backwards compatibility
async function scanNodeModules(targetDir, options = {}) {
  return scanPackages(targetDir, { ...options, ecosystems: ['npm'] });
}

/**
 * Parse command line arguments
 */
function parseArgs(args) {
  const options = {
    targetDir: process.cwd(),
    ecosystems: [],
    autoDetect: true,
    deep: false,
    upload: false,
    skipExisting: true,
    getReputations: true,
    includePackageJson: false,
    includeLockFiles: false,
    includeAllFiles: false,
    apiUrl: process.env.UC_API_URL || '',
    apiKey: process.env.UC_API_KEY || '',
    repo: process.env.UC_REPO || ''
  };
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else if (arg === '--list-ecosystems') {
      console.log('\nAvailable ecosystems:');
      for (const [name, config] of Object.entries(ECOSYSTEMS)) {
        console.log(`  ${name.padEnd(10)} - ${config.description}`);
        console.log(`             Directories: ${config.directories.join(', ')}`);
        console.log(`             Tag prefix: ${config.tagPrefix}/`);
      }
      process.exit(0);
    } else if (arg === '--ecosystem' || arg === '-e') {
      const eco = args[++i];
      if (eco) {
        options.ecosystems.push(...eco.split(','));
        options.autoDetect = false;
      }
    } else if (arg === '--deep') {
      options.deep = true;
    } else if (arg === '--upload') {
      options.upload = true;
    } else if (arg === '--force-upload' || arg === '--no-skip') {
      options.skipExisting = false;
    } else if (arg === '--no-reputations') {
      options.getReputations = false;
    } else if (arg === '--include-package-json' || arg === '--package-json') {
      options.includePackageJson = true;
    } else if (arg === '--include-lock-files' || arg === '--lock-files') {
      options.includeLockFiles = true;
    } else if (arg === '--all-files') {
      options.includeAllFiles = true;
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
Multi-Ecosystem Package Scanner
===============================

Scans package directories for binary executables and executable scripts,
then optionally uploads them to UnknownCyber API for security analysis.

Supports: npm, pip, maven, cargo, go, ruby, and generic directory scans.

Usage:
  node scanner.js [options] [path]

Ecosystem Options:
  --ecosystem, -e <name>  Specify ecosystem(s) to scan (comma-separated)
                          Available: npm, pip, maven, cargo, go, ruby, generic
                          If not specified, auto-detects from directory structure
  --list-ecosystems       List all available ecosystems and exit

Scan Options:
  --deep                  Enable deep scan using magic bytes (slower but finds more)

File Selection:
  --include-package-json  Include package.json files (for SBOM creation)
  --include-lock-files    Include lock files for SBOM generation
                          (package-lock.json, yarn.lock, requirements.txt, etc.)
  --all-files             Include ALL files (not just executables)

Upload Options:
  --upload                Upload found files to UnknownCyber API
  --force-upload          Upload all files even if they already exist in UC
  --no-reputations        Skip fetching reputation data for existing files

API Configuration:
  --api-url <url>         API base URL (or set UC_API_URL env var)
  --api-key <key>         API key for authentication (or set UC_API_KEY env var)
  --repo <name>           Repository name to tag uploads with (or set UC_REPO env var)

General:
  --help, -h              Show this help message

Examples:
  # Auto-detect and scan all ecosystems in current directory
  node scanner.js
  
  # Scan specific ecosystem
  node scanner.js --ecosystem npm
  node scanner.js -e pip ./my-python-project
  
  # Scan multiple ecosystems
  node scanner.js --ecosystem npm,pip ./my-project
  
  # Scan npm packages (legacy behavior)
  node scanner.js ./my-project
  
  # Deep scan with upload
  node scanner.js --deep --upload --api-key YOUR_KEY
  
  # Scan extracted container filesystem
  node scanner.js --ecosystem generic ./extracted-container

Tag Format:
  Files are tagged with: SW_<ecosystem>/<package>_<version>
  Examples:
    - SW_npm/@esbuild/win32-x64_0.20.2
    - SW_pip/requests_2.31.0
    - SW_maven/org.apache.commons:commons-lang3_3.12.0
    - SW_cargo/serde_1.0.193

Detected Binary Types:
  - Windows: EXE, DLL, SYS, OCX, COM, SCR
  - Linux: ELF executables, SO (shared objects), O, A
  - macOS: Mach-O, DYLIB, Bundle
  - Node.js: .node (native addons)
  - Java: JAR, WAR, EAR, CLASS
  - WebAssembly: WASM
  - Other: BIN, DAT

Detected Script Types (potential attack vectors):
  - Windows: BAT, CMD, PS1, VBS, VBE, WSF, WSH
  - Unix: SH, BASH, ZSH, CSH, KSH
  - Cross-platform: PL (Perl), RB (Ruby), PY/PYW (Python)
`);
}

// Main entry point
const args = process.argv.slice(2);
const options = parseArgs(args);

deepMagicScan = options.deep;
includePackageJson = options.includePackageJson;
includeLockFiles = options.includeLockFiles;
includeAllFiles = options.includeAllFiles;

scanPackages(options.targetDir, options);
