/**
 * UnknownCyber File Reputation Module
 *
 * A standalone, headless module for fetching file reputation data from the UnknownCyber API.
 * This module is designed for batch processing and GitHub Actions, supporting parallel requests.
 *
 * Authentication is done via API key passed as a query parameter.
 *
 * Usage:
 *   const { createReputationClient, getFileReputations } = require('./file-reputation');
 *
 *   const client = createReputationClient({
 *     apiUrl: 'https://api.unknowncyber.com',
 *     apiKey: 'your-api-key',
 *   });
 *
 *   const reputations = await getFileReputations(client, 'sha256hash');
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

// ============================================================================
// Constants
// ============================================================================

const THREAT_LEVEL_RANK = {
  high: 6,
  medium: 5,
  caution: 4,
  new: 3,
  low: 2,
  unknown: 1,
  none: 0,
};

const DEFAULT_TIMEOUT = 30000;
const DEFAULT_RETRIES = 3;
const DEFAULT_RETRY_DELAY = 1000;

// ============================================================================
// Internal HTTP Client
// ============================================================================

/**
 * Make an HTTP request with retry logic
 * @param {string} baseUrl - API base URL
 * @param {string} apiKey - API key for authentication
 * @param {string} endpoint - API endpoint
 * @param {object} options - Request options
 * @returns {Promise<any>}
 */
async function makeRequest(baseUrl, apiKey, endpoint, options = {}) {
  const { method = 'GET', params = {}, body, timeout = DEFAULT_TIMEOUT, retries = DEFAULT_RETRIES, retryDelay = DEFAULT_RETRY_DELAY } = options;

  // Build URL with query parameters
  const searchParams = new URLSearchParams();
  searchParams.append('key', apiKey);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      searchParams.append(key, String(value));
    }
  }

  const urlString = `${baseUrl.replace(/\/$/, '')}${endpoint}?${searchParams.toString()}`;
  const url = new URL(urlString);

  const requestOptions = {
    hostname: url.hostname,
    port: url.port || (url.protocol === 'https:' ? 443 : 80),
    path: url.pathname + url.search,
    method,
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    timeout,
  };

  let lastError = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const result = await new Promise((resolve, reject) => {
        const protocol = url.protocol === 'https:' ? https : http;

        const req = protocol.request(requestOptions, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) {
              try {
                const parsed = JSON.parse(data);
                // UnknownCyber API wraps responses in resource/resources
                if (parsed.resource !== undefined) resolve(parsed.resource);
                else if (parsed.resources !== undefined) resolve(parsed.resources);
                else resolve(parsed);
              } catch {
                resolve(data);
              }
            } else if (res.statusCode === 404) {
              // File not found - return null instead of error
              resolve(null);
            } else {
              reject(new Error(`HTTP ${res.statusCode}: ${data.substring(0, 200)}`));
            }
          });
        });

        req.on('error', reject);
        req.on('timeout', () => {
          req.destroy();
          reject(new Error('Request timeout'));
        });

        if (body) {
          req.write(JSON.stringify(body));
        }
        req.end();
      });

      return result;
    } catch (error) {
      lastError = error;

      // Don't retry on 4xx errors (except 429 rate limit)
      if (error.message && error.message.includes('HTTP 4') && !error.message.includes('HTTP 429')) {
        throw error;
      }

      // Wait before retrying
      if (attempt < retries) {
        await sleep(retryDelay * Math.pow(2, attempt));
      }
    }
  }

  throw lastError || new Error('Request failed after retries');
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Make an HTTP POST request with form data
 * @param {string} baseUrl - API base URL
 * @param {string} apiKey - API key for authentication
 * @param {string} endpoint - API endpoint
 * @param {object} options - Request options
 * @returns {Promise<any>}
 */
async function makeFormRequest(baseUrl, apiKey, endpoint, options = {}) {
  const { fields = {}, timeout = DEFAULT_TIMEOUT } = options;

  // Build URL with API key
  const searchParams = new URLSearchParams();
  searchParams.append('key', apiKey);

  const urlString = `${baseUrl.replace(/\/$/, '')}${endpoint}?${searchParams.toString()}`;
  const url = new URL(urlString);

  // Build multipart form data
  const boundary = '----FormBoundary' + Math.random().toString(36).substring(2);
  let body = '';
  
  for (const [name, value] of Object.entries(fields)) {
    body += `--${boundary}\r\n`;
    body += `Content-Disposition: form-data; name="${name}"\r\n\r\n`;
    body += `${value}\r\n`;
  }
  body += `--${boundary}--\r\n`;

  const requestOptions = {
    hostname: url.hostname,
    port: url.port || (url.protocol === 'https:' ? 443 : 80),
    path: url.pathname + url.search,
    method: 'POST',
    headers: {
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
      'Content-Length': Buffer.byteLength(body),
    },
    timeout,
  };

  return new Promise((resolve, reject) => {
    const protocol = url.protocol === 'https:' ? https : http;

    const req = protocol.request(requestOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            const parsed = JSON.parse(data);
            if (parsed.resource !== undefined) resolve(parsed.resource);
            else if (parsed.resources !== undefined) resolve(parsed.resources);
            else resolve(parsed);
          } catch {
            resolve(data);
          }
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${data.substring(0, 200)}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    req.write(body);
    req.end();
  });
}

// ============================================================================
// Reputation Client
// ============================================================================

/**
 * Create a reputation client
 * @param {object} config - Client configuration
 * @param {string} config.apiUrl - API base URL
 * @param {string} config.apiKey - API key for authentication
 * @param {number} [config.timeout] - Request timeout in ms
 * @param {number} [config.retries] - Number of retries
 * @returns {object} - Reputation client
 */
function createReputationClient(config) {
  const { apiUrl, apiKey, timeout = DEFAULT_TIMEOUT, retries = DEFAULT_RETRIES, retryDelay = DEFAULT_RETRY_DELAY } = config;

  if (!apiUrl) throw new Error('apiUrl is required');
  if (!apiKey) throw new Error('apiKey is required');

  const requestOptions = { timeout, retries, retryDelay };

  return {
    // Expose config for external functions
    _apiUrl: apiUrl,
    _apiKey: apiKey,
    _timeout: timeout,
    _retries: retries,
    _retryDelay: retryDelay,
    /**
     * Get basic file information including detection counts
     * @param {string} hash - File hash
     * @returns {Promise<object|null>}
     */
    async getFile(hash) {
      try {
        return await makeRequest(apiUrl, apiKey, `/v2/files/${hash}/`, {
          ...requestOptions,
          params: {
            read_mask: 'sha1,sha256,md5,sha512,detection_count,scanner_count,scan_date,av_names,object_class,filetype',
          },
        });
      } catch {
        return null;
      }
    },

    /**
     * Get AV scan results
     * @param {string} hash - File hash
     * @returns {Promise<object[]|null>}
     */
    async getAVScan(hash) {
      try {
        return await makeRequest(apiUrl, apiKey, `/v2/files/${hash}/avscan/`, {
          ...requestOptions,
          params: { suppress: true },
        });
      } catch {
        return null;
      }
    },

    /**
     * Get file details including signature information
     * @param {string} hash - File hash
     * @returns {Promise<object|null>}
     */
    async getFileDetails(hash) {
      try {
        return await makeRequest(apiUrl, apiKey, `/v2/files/${hash}/details/`, requestOptions);
      } catch {
        return null;
      }
    },

    /**
     * Get similarity matches for a file
     * @param {string} hash - File hash
     * @param {number} [minThreshold] - Minimum similarity threshold (default 0.7)
     * @returns {Promise<object[]>}
     */
    async getSimilarities(hash, minThreshold = 0.7) {
      try {
        const result = await makeRequest(apiUrl, apiKey, '/v2/files/bulk/', {
          ...requestOptions,
          method: 'POST',
          params: {
            action: 'get',
            read_mask: 'sha1',
            dynamic_mask: 'similarities,similarities.detected',
            min_threshold: minThreshold,
          },
          body: { ids: hash },
        });

        return result?.[0]?.similarities || [];
      } catch {
        return [];
      }
    },

    /**
     * Get clone matches (100% similarity)
     * @param {string} hash - File hash
     * @returns {Promise<object[]>}
     */
    async getClones(hash) {
      return this.getSimilarities(hash, 1.0);
    },

    /**
     * Check if a file exists in UnknownCyber database
     * @param {string} hash - File hash
     * @returns {Promise<boolean>}
     */
    async fileExists(hash) {
      const file = await this.getFile(hash);
      return file !== null;
    },
  };
}

// ============================================================================
// Reputation Assessment Functions
// ============================================================================

/**
 * Assess AV-based reputation
 * @param {object|null} fileInfo - File info from API
 * @param {object[]|null} avScanData - AV scan data from API
 * @returns {object}
 */
function assessAVReputation(fileInfo, avScanData) {
  const detectionCount = fileInfo?.detection_count || 0;
  const scannerCount = fileInfo?.scanner_count || 0;
  const avNames = fileInfo?.av_names || [];

  // Extract VirusTotal report if available
  const vtReport = avScanData?.[0]?.virustotal;
  const report = vtReport
    ? {
        positives: vtReport.positives,
        total: vtReport.total,
        scanDate: vtReport.scan_date,
        scans: (vtReport.scans || []).map(s => ({
          scanner: s.scanner,
          detected: s.detected,
          name: s.name,
          version: s.version,
          update: s.update,
        })),
      }
    : null;

  // Determine verdict
  let verdict;
  let threatLevel;

  if (scannerCount === 0) {
    verdict = 'unknown';
    threatLevel = 'unknown';
  } else if (detectionCount === 0) {
    verdict = 'clean';
    threatLevel = 'none';
  } else {
    const ratio = detectionCount / scannerCount;

    // Thresholds:
    // - HIGH: ≥10% (8+ of 76) - serious concern
    // - MEDIUM: ≥5% (4-7 of 76) - needs attention
    // - CAUTION: 2-3 detections - worth investigating
    // - LOW: 1 detection - likely false positive
    if (ratio >= 0.10) {
      verdict = 'malicious';
      threatLevel = 'high';
    } else if (ratio >= 0.05) {
      verdict = 'malicious';
      threatLevel = 'medium';
    } else if (detectionCount >= 2) {
      verdict = 'suspicious';
      threatLevel = 'caution';
    } else {
      verdict = 'suspicious';
      threatLevel = 'low';
    }
  }

  return {
    type: 'antivirus',
    verdict,
    threatLevel,
    detectionRatio: `${detectionCount}/${scannerCount}`,
    detectionCount,
    scannerCount,
    scanDate: fileInfo?.scan_date,
    topThreats: avNames.slice(0, 10),
    report,
  };
}

/**
 * Assess similarity-based reputation
 * @param {object[]} clones - Clone matches
 * @param {object[]} similarities - Similarity matches
 * @returns {object}
 */
function assessSimilarityReputation(clones, similarities) {
  const allMatches = [...clones, ...similarities];
  const hasMaliciousMatches = allMatches.some(m => m.detected && m.similarity >= 1.0);
  const hasSuspiciousMatches = allMatches.some(m => m.detected && m.similarity < 1.0);
  const highestSimilarity = allMatches.length > 0
    ? Math.max(...allMatches.map(m => m.similarity))
    : 0;

  let threatLevel;

  if (hasMaliciousMatches) {
    threatLevel = 'high';
  } else if (hasSuspiciousMatches) {
    threatLevel = 'medium';
  } else if (allMatches.length > 0) {
    threatLevel = 'low';
  } else {
    threatLevel = 'none';
  }

  return {
    type: 'similarity',
    threatLevel,
    hasMaliciousMatches,
    hasSuspiciousMatches,
    cloneCount: clones.length,
    similarCount: similarities.length,
    highestSimilarity,
    matches: allMatches.slice(0, 20),
  };
}

/**
 * Assess code signing-based reputation
 * @param {object|null} fileDetails - File details from API
 * @returns {object}
 */
function assessSignatureReputation(fileDetails) {
  const signature = fileDetails?.signature;

  if (!signature) {
    return {
      type: 'signature',
      threatLevel: 'unknown',
      signatureStatus: 'unknown',
      isSigned: false,
      isValid: false,
    };
  }

  const isSigned = Boolean(signature.signed);
  const isValid = Boolean(signature.valid);

  let signatureStatus;
  let threatLevel;

  if (!isSigned) {
    signatureStatus = 'unsigned';
    threatLevel = 'caution';
  } else if (isValid) {
    signatureStatus = 'valid_signed';
    threatLevel = 'none';
  } else {
    signatureStatus = 'signed_but_invalid';
    threatLevel = 'high';
  }

  // Extract signature details
  const details = {};
  for (const [key, value] of Object.entries(signature)) {
    if (key !== 'signed' && key !== 'valid' && typeof value === 'string') {
      details[key] = value;
    }
  }

  return {
    type: 'signature',
    threatLevel,
    signatureStatus,
    isSigned,
    isValid,
    details: Object.keys(details).length > 0 ? details : null,
  };
}

/**
 * Calculate overall threat level
 * @param {object} av - AV reputation
 * @param {object} similarity - Similarity reputation
 * @param {object} signature - Signature reputation
 * @returns {string}
 */
function calculateOverallThreatLevel(av, similarity, signature) {
  const levels = [av.threatLevel, similarity.threatLevel, signature.threatLevel];

  return levels.reduce((highest, current) => {
    return THREAT_LEVEL_RANK[current] > THREAT_LEVEL_RANK[highest]
      ? current
      : highest;
  }, 'none');
}

/**
 * Detect hash type from hash string
 * @param {string} hash - File hash
 * @returns {string}
 */
function detectHashType(hash) {
  const len = hash.length;
  if (len === 32) return 'md5';
  if (len === 40) return 'sha1';
  if (len === 64) return 'sha256';
  if (len === 128) return 'sha512';
  return 'sha256';
}

// ============================================================================
// Public API Functions
// ============================================================================

/**
 * Get all reputation assessments for a file hash
 * @param {object} client - Reputation client
 * @param {string} hash - File hash
 * @returns {Promise<object>}
 */
async function getFileReputations(client, hash) {
  // Fetch all data in parallel
  const [fileInfo, avScanData, fileDetails, clones, similarities] =
    await Promise.all([
      client.getFile(hash),
      client.getAVScan(hash),
      client.getFileDetails(hash),
      client.getClones(hash),
      client.getSimilarities(hash),
    ]);

  // Assess each reputation type
  const antivirus = assessAVReputation(fileInfo, avScanData);
  const similarity = assessSimilarityReputation(clones, similarities);
  const signature = assessSignatureReputation(fileDetails);

  // Calculate overall threat level
  const overallThreatLevel = calculateOverallThreatLevel(
    antivirus,
    similarity,
    signature
  );

  return {
    hash,
    hashType: detectHashType(hash),
    exists: fileInfo !== null,
    antivirus,
    similarity,
    signature,
    overallThreatLevel,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Get reputations for multiple file hashes in parallel
 * @param {object} client - Reputation client
 * @param {string[]} hashes - Array of file hashes
 * @param {object} [options] - Options
 * @param {number} [options.concurrency] - Concurrency limit
 * @returns {Promise<object[]>}
 */
async function getFileReputationsBatch(client, hashes, options = {}) {
  const concurrency = options.concurrency || 5;
  const results = [];

  for (let i = 0; i < hashes.length; i += concurrency) {
    const batch = hashes.slice(i, i + concurrency);

    const batchResults = await Promise.all(
      batch.map(async hash => {
        try {
          return await getFileReputations(client, hash);
        } catch (error) {
          return {
            hash,
            error: error.message || 'Unknown error',
          };
        }
      })
    );

    results.push(...batchResults);
  }

  return results;
}

/**
 * Quick check for just AV reputation (faster, fewer API calls)
 * @param {object} client - Reputation client
 * @param {string} hash - File hash
 * @returns {Promise<object>}
 */
async function getAVReputationOnly(client, hash) {
  const [fileInfo, avScanData] = await Promise.all([
    client.getFile(hash),
    client.getAVScan(hash),
  ]);

  return assessAVReputation(fileInfo, avScanData);
}

/**
 * Quick check for similarity reputation only
 * @param {object} client - Reputation client
 * @param {string} hash - File hash
 * @returns {Promise<object>}
 */
async function getSimilarityReputationOnly(client, hash) {
  const [clones, similarities] = await Promise.all([
    client.getClones(hash),
    client.getSimilarities(hash),
  ]);

  return assessSimilarityReputation(clones, similarities);
}

/**
 * Quick check for signature reputation only
 * @param {object} client - Reputation client
 * @param {string} hash - File hash
 * @returns {Promise<object>}
 */
async function getSignatureReputationOnly(client, hash) {
  const fileDetails = await client.getFileDetails(hash);
  return assessSignatureReputation(fileDetails);
}

/**
 * Check if a file hash exists in UnknownCyber (useful for deduplication before upload)
 * @param {object} client - Reputation client
 * @param {string} hash - File hash
 * @returns {Promise<boolean>}
 */
async function fileExists(client, hash) {
  return client.fileExists(hash);
}

/**
 * Get tags for a file
 * @param {object} client - Reputation client  
 * @param {string} hash - File hash
 * @returns {Promise<string[]>} - Array of tag names
 */
async function getFileTags(client, hash) {
  const result = await makeRequest(client._apiUrl, client._apiKey, `/v2/files/${hash}/tags/`, {
    timeout: client._timeout,
    retries: client._retries,
    retryDelay: client._retryDelay,
  });
  
  if (!result) return [];
  
  // API returns array of tag objects with 'name' property
  if (Array.isArray(result)) {
    return result.map(t => t.name || t).filter(Boolean);
  }
  
  return [];
}

/**
 * Add tags to a file
 * @param {object} client - Reputation client
 * @param {string} hash - File hash
 * @param {string[]} tags - Array of tag names to add
 * @returns {Promise<{added: string[], existing: string[], failed: string[]}>}
 */
async function addFileTags(client, hash, tags) {
  const results = { added: [], existing: [], failed: [] };
  
  for (const tag of tags) {
    try {
      await makeFormRequest(client._apiUrl, client._apiKey, `/v2/files/${hash}/tags/`, {
        timeout: client._timeout,
        fields: { name: tag }
      });
      results.added.push(tag);
    } catch (err) {
      // Check if tag already exists (might return 409 or similar)
      if (err.message && err.message.includes('409')) {
        results.existing.push(tag);
      } else {
        results.failed.push(tag);
      }
    }
  }
  
  return results;
}

/**
 * Check multiple file hashes for existence (for batch deduplication)
 * @param {object} client - Reputation client
 * @param {string[]} hashes - Array of file hashes
 * @param {object} [options] - Options
 * @param {number} [options.concurrency] - Concurrency limit
 * @returns {Promise<object>} - Object with { existing: string[], notFound: string[] }
 */
async function checkFileExistence(client, hashes, options = {}) {
  const concurrency = options.concurrency || 10;
  const existing = [];
  const notFound = [];

  for (let i = 0; i < hashes.length; i += concurrency) {
    const batch = hashes.slice(i, i + concurrency);

    const results = await Promise.all(
      batch.map(async hash => {
        const exists = await client.fileExists(hash);
        return { hash, exists };
      })
    );

    for (const result of results) {
      if (result.exists) {
        existing.push(result.hash);
      } else {
        notFound.push(result.hash);
      }
    }
  }

  return { existing, notFound };
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Check if a hash appears to be in a valid format
 * @param {string} hash - Hash string to validate
 * @returns {boolean}
 */
function isValidHash(hash) {
  return /^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{128}$/.test(hash);
}

/**
 * Get threat level configuration for display
 * @param {string} level - Threat level
 * @returns {object}
 */
function getThreatLevelConfig(level) {
  const configs = {
    high: { text: 'High', rank: 6, color: '#d32f2f' },
    medium: { text: 'Medium', rank: 5, color: '#f57c00' },
    caution: { text: 'Caution', rank: 4, color: '#ffa726' },
    new: { text: 'New', rank: 3, color: '#7c4dff' },
    low: { text: 'Low', rank: 2, color: '#66bb6a' },
    unknown: { text: 'Unknown', rank: 1, color: '#9e9e9e' },
    none: { text: 'None', rank: 0, color: '#4caf50' },
  };
  return configs[level] || configs.unknown;
}

/**
 * Compare two threat levels
 * @param {string} a - First threat level
 * @param {string} b - Second threat level
 * @returns {number} - Positive if a > b, negative if a < b, 0 if equal
 */
function compareThreatLevels(a, b) {
  return THREAT_LEVEL_RANK[a] - THREAT_LEVEL_RANK[b];
}

// ============================================================================
// Exports
// ============================================================================

module.exports = {
  // Client creation
  createReputationClient,

  // Full reputation checks
  getFileReputations,
  getFileReputationsBatch,

  // Individual reputation type checks
  getAVReputationOnly,
  getSimilarityReputationOnly,
  getSignatureReputationOnly,

  // File existence checks (for deduplication)
  fileExists,
  checkFileExistence,

  // Tag management
  getFileTags,
  addFileTags,

  // Utilities
  isValidHash,
  getThreatLevelConfig,
  compareThreatLevels,
  detectHashType,

  // Assessment functions (for custom logic)
  assessAVReputation,
  assessSimilarityReputation,
  assessSignatureReputation,
  calculateOverallThreatLevel,
};

