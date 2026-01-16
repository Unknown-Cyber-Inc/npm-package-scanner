# Software Configuration Misconfiguration Scanner

This document outlines the design for scanning configuration files to detect security vulnerabilities, misconfigurations, and best practice violations.

## Overview

Configuration files are a common source of security vulnerabilities. Misconfigurations can expose services to the internet, leak credentials, enable weak encryption, or create other security gaps. This scanner aims to detect these issues across multiple application types.

---

## Configuration Misconfiguration Categories

### 1. Security Headers / Hardening
*Applies to: nginx, Apache, web servers*

- Missing security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options)
- Server version disclosure (`server_tokens on`)
- Directory listing enabled (`autoindex on`)
- Default error pages exposing stack traces or versions

### 2. TLS/Crypto Weaknesses
*Applies to: nginx, Apache, HAProxy, database configs, any TLS termination*

- Weak TLS versions enabled (TLS 1.0, TLS 1.1, SSLv3, SSLv2)
- Weak cipher suites (RC4, DES, 3DES, export ciphers, NULL ciphers)
- Missing HSTS or HSTS without preload
- Short DH parameters (< 2048 bits)
- Self-signed or expired certificates referenced in config

### 3. Access Control Issues
*Applies to: nginx, Apache, databases, SSH, cloud configs*

- Binding to `0.0.0.0` when localhost is intended
- Missing authentication on admin endpoints
- Overly permissive `allow` directives (`allow all`, `0.0.0.0/0`)
- Exposed sensitive paths (`/.git`, `/.env`, `/admin`, `/phpmyadmin`, `/.aws`)
- Default credentials referenced
- Anonymous access enabled

### 4. Secrets Exposure
*Applies to: any configuration file*

- Hardcoded passwords and API keys
- Database credentials in plaintext
- AWS/GCP/Azure access keys and secrets
- Private keys or certificates embedded in config
- OAuth client secrets
- JWT signing keys

### 5. Resource & DoS Protection
*Applies to: nginx, Apache, databases, application servers*

- Missing rate limiting
- No connection or request timeouts
- Unlimited request body size (`client_max_body_size 0`)
- No worker or connection limits
- Missing keepalive timeouts

### 6. Dangerous Directives
*Applies to: nginx, PHP, application configs*

- `proxy_pass` to user-controlled or internal destinations (SSRF)
- `alias` path traversal vulnerabilities in nginx
- PHP `allow_url_include`, `display_errors` in production
- Debug mode enabled in production environments
- Eval or code execution features enabled

### 7. Deprecated/Insecure Features
*Applies to: various*

- Legacy protocols enabled (HTTP/1.0, FTP, telnet)
- Deprecated configuration directives
- Known-vulnerable module versions referenced
- End-of-life software versions

---

## Suggested Configuration Files to Support

| Category | Config Files | Format |
|----------|-------------|--------|
| **Web Servers** | `nginx.conf`, `httpd.conf`, `.htaccess`, `sites-available/*` | nginx-style, Apache |
| **Databases** | `my.cnf` (MySQL), `postgresql.conf`, `pg_hba.conf`, `mongod.conf`, `redis.conf` | INI, key-value |
| **SSH** | `sshd_config`, `ssh_config` | key-value |
| **Docker** | `Dockerfile`, `docker-compose.yml`, `docker-compose.yaml` | Dockerfile, YAML |
| **Kubernetes** | `*.yaml`, `*.yml` (deployments, pods, services, configmaps) | YAML |
| **PHP** | `php.ini`, `php-fpm.conf` | INI |
| **Application** | `.env`, `.env.*`, `config.json`, `settings.json` | key-value, JSON |
| **Cloud (AWS)** | IAM policies, S3 bucket policies, CloudFormation templates | JSON, YAML |
| **Cloud (Azure)** | ARM templates, Azure Policy definitions | JSON |
| **CI/CD** | `.gitlab-ci.yml`, `.github/workflows/*.yml`, `Jenkinsfile` | YAML, Groovy |

---

## Detection Approach: Horizontal vs Vertical

### Horizontal Patterns (Universal Rules)

These patterns can be detected with generic rules that work across **any** configuration file format, regardless of the specific application.

| Pattern | Examples | Detection Method |
|---------|----------|------------------|
| **Secrets/Credentials** | `password=secret123`, `api_key=sk-xxx`, `AWS_SECRET_ACCESS_KEY` | Regex for key names + entropy analysis for values |
| **Network Exposure** | `0.0.0.0`, `*`, `0.0.0.0/0`, `bind_address: *`, `listen *:80` | Common binding/CIDR patterns |
| **Debug/Dev Modes** | `debug=true`, `DEBUG_MODE=1`, `environment: development` | Keyword matching |
| **Weak TLS Versions** | `TLSv1`, `TLSv1.1`, `SSLv3`, `ssl_protocols TLSv1` | TLS/SSL version strings |
| **Permissive Access** | `allow all`, `permit any`, `* *`, `public: true`, `anonymous: true` | Common permissive keywords |
| **Dangerous Ports Exposed** | `:22`, `:3306`, `:5432`, `:6379`, `:27017` on 0.0.0.0 | Port number patterns with exposure |
| **Root/Admin Users** | `user root`, `USER root`, `runAsUser: 0` | Privileged user patterns |

**Advantage:** Write once, detect everywhere. A secrets scanner catches credentials whether they're in `nginx.conf`, `docker-compose.yml`, or `.env`.

### Vertical Patterns (Application-Specific Rules)

These patterns require understanding the specific application's configuration syntax and semantics.

| Application | Specific Issues | Why Vertical? |
|-------------|----------------|---------------|
| **nginx** | `proxy_pass` SSRF, `alias` path traversal, `internal` misuse | Directive semantics, block context matters |
| **Kubernetes** | `privileged: true`, `hostPID`, `hostNetwork`, missing `securityContext` | Resource type and field relationships |
| **Docker** | `--privileged`, capability additions, missing `USER`, exposed ports | Dockerfile instruction semantics |
| **Apache** | `AllowOverride All`, `Options +Indexes +ExecCGI` | Module-specific directives |
| **AWS IAM** | `"Effect": "Allow"` + `"Resource": "*"` + `"Action": "*"` | Policy document structure and logic |
| **PostgreSQL** | `pg_hba.conf` trust authentication, `listen_addresses = '*'` | File-specific format and auth methods |

**Advantage:** Catches nuanced, context-dependent issues that generic patterns miss.

---

## Proposed Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Configuration Scanner                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  LAYER 1: Universal Detectors (Format-Agnostic)            │ │
│  │  ────────────────────────────────────────────────────────  │ │
│  │  • Secrets Scanner (entropy + regex patterns)              │ │
│  │  • Network Exposure (0.0.0.0, permissive CIDRs)           │ │
│  │  • TLS/SSL Weakness (version strings, weak ciphers)       │ │
│  │  • Debug Mode Detector (dev/debug keywords)               │ │
│  │  • Privileged User Detector (root, admin, uid 0)          │ │
│  │                                                            │ │
│  │  ✓ Works on ANY text file                                  │ │
│  │  ✓ No parsing required                                     │ │
│  │  ✓ High coverage, some false positives                     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  LAYER 2: Format-Aware Parsers                             │ │
│  │  ────────────────────────────────────────────────────────  │ │
│  │  • YAML Parser (k8s, docker-compose, CI/CD, cloud)        │ │
│  │  • JSON Parser (package.json, IAM policies, configs)      │ │
│  │  • INI/TOML Parser (php.ini, my.cnf, pyproject.toml)      │ │
│  │  • Nginx-style Parser (nginx.conf, block directives)      │ │
│  │  • Dockerfile Parser (instruction-based)                   │ │
│  │                                                            │ │
│  │  ✓ Understands structure                                   │ │
│  │  ✓ Can apply context-aware rules                           │ │
│  │  ✓ Reduces false positives                                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  LAYER 3: Application-Specific Rule Sets                   │ │
│  │  ────────────────────────────────────────────────────────  │ │
│  │  • rules/nginx.yaml      - nginx-specific checks          │ │
│  │  • rules/kubernetes.yaml - k8s security best practices    │ │
│  │  • rules/docker.yaml     - Dockerfile/compose checks      │ │
│  │  • rules/aws-iam.yaml    - IAM policy analysis            │ │
│  │  • rules/postgresql.yaml - PostgreSQL hardening           │ │
│  │  • rules/apache.yaml     - Apache/httpd checks            │ │
│  │                                                            │ │
│  │  ✓ Deep, context-aware analysis                            │ │
│  │  ✓ Application-specific best practices                     │ │
│  │  ✓ Lowest false positive rate                              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **File Discovery** → Identify config files by name/extension/path
2. **Layer 1 Scan** → Run universal detectors on raw text
3. **Format Detection** → Identify file format (YAML, JSON, INI, nginx, etc.)
4. **Layer 2 Parse** → Parse into structured representation
5. **Layer 3 Rules** → Apply application-specific rules based on detected app
6. **Report Generation** → Aggregate findings with severity and remediation

---

## Implementation Recommendation

### Phase 1: Universal Detectors (Layer 1)

Start with format-agnostic scanners that provide immediate value across all config files:

#### 1.1 Secrets Scanner
**High Value, Broad Coverage**

Detect hardcoded credentials using:
- **Pattern matching**: Known secret key names (`password`, `secret`, `api_key`, `token`, `AWS_SECRET_ACCESS_KEY`, etc.)
- **Entropy analysis**: High-entropy strings that look like keys/tokens
- **Known formats**: AWS keys (`AKIA...`), GitHub tokens (`ghp_...`), Stripe keys (`sk_live_...`)

```
Patterns to detect:
- password\s*[=:]\s*["']?[^"'\s]+
- api[_-]?key\s*[=:]\s*["']?[^"'\s]+
- secret\s*[=:]\s*["']?[^"'\s]+
- AWS_SECRET_ACCESS_KEY
- AKIA[0-9A-Z]{16}  (AWS Access Key ID)
- ghp_[a-zA-Z0-9]{36}  (GitHub Personal Access Token)
- sk_live_[a-zA-Z0-9]+  (Stripe Secret Key)
```

#### 1.2 Network Exposure Scanner
**Catches Dangerous Bindings**

Detect services bound to all interfaces when they shouldn't be:
- `0.0.0.0` or `*` as listen address
- `0.0.0.0/0` in allow rules (allows entire internet)
- Dangerous ports (databases, caches) exposed

```
Patterns to detect:
- listen\s+(\*|0\.0\.0\.0)[:\s]
- bind[_-]?address\s*[=:]\s*["']?(0\.0\.0\.0|\*)
- host:\s*["']?(0\.0\.0\.0|\*)
- 0\.0\.0\.0/0
```

**Phase 1 vs Phase 2/3 Coverage:**

| Config Type | Phase 1 (Regex) | Phase 2/3 (Parsed) |
|-------------|-----------------|-------------------|
| nginx `listen 0.0.0.0:80` | ✅ Catches `0.0.0.0` | ✅ Knows it's a `listen` directive |
| docker `ports: "0.0.0.0:80:80"` | ✅ Catches `0.0.0.0` | ✅ Understands port mapping in YAML |
| k8s `hostPort: 80` | ❌ No `0.0.0.0` string | ✅ Understands `hostPort` exposes to host |
| k8s `hostNetwork: true` | ❌ No `0.0.0.0` string | ✅ Knows this exposes all ports |
| Comment `# listen 0.0.0.0` | ⚠️ False positive | ✅ Ignores comments |

#### 1.3 TLS Weakness Scanner
**Identifies Weak Crypto**

Detect insecure TLS/SSL configurations:
- TLS 1.0, TLS 1.1, SSLv3, SSLv2 enabled
- Weak cipher suites
- Missing modern TLS

```
Patterns to detect:
- TLSv1[^.]
- TLSv1\.0
- TLSv1\.1
- SSLv[23]
- ssl_protocols.*TLSv1[^.2]
- RC4|DES|3DES|MD5|NULL|EXPORT|anon
```

**Phase 1 vs Phase 2/3 Coverage:**

| Config Type | Phase 1 (Regex) | Phase 2/3 (Parsed) |
|-------------|-----------------|-------------------|
| nginx `ssl_protocols TLSv1 TLSv1.1` | ✅ Catches `TLSv1` | ✅ Knows it's active config |
| Apache `SSLProtocol all -SSLv3` | ⚠️ Catches `SSLv3` (false positive—it's disabled) | ✅ Understands `-` means disabled |
| HAProxy `ssl-min-ver TLSv1.0` | ✅ Catches `TLSv1.0` | ✅ Knows it's minimum version |
| Comment `# TLSv1 is insecure` | ⚠️ False positive | ✅ Ignores comments |
| Missing TLS config entirely | ❌ Nothing to match | ✅ Can flag missing hardening |

#### 1.4 Debug Mode Scanner
**Catches Dev Configs in Production**

Detect development/debug settings that shouldn't be in production:

```
Patterns to detect:
- debug\s*[=:]\s*["']?(true|1|yes|on)
- DEBUG[_-]?MODE\s*[=:]\s*["']?(true|1|yes|on)
- environment\s*[=:]\s*["']?development
- NODE_ENV\s*[=:]\s*["']?development
- display_errors\s*[=:]\s*["']?(on|1|true)
```

#### Phase 1 Summary

| Scanner | Phase 1 Coverage | Enhanced by Phase 2/3 |
|---------|------------------|----------------------|
| **Secrets** | ~90% — Most secrets have identifiable patterns | Comment filtering, context validation |
| **Network Exposure** | ~70% — Catches explicit `0.0.0.0` bindings | Semantic understanding (`hostPort`, `hostNetwork`) |
| **TLS Weakness** | ~60% — Catches version strings | Understands enabled vs disabled (`-SSLv3`), missing configs |
| **Debug Mode** | ~80% — Keyword matching works well | Reduces false positives in comments/strings |

**Phase 1 delivers immediate value** with broad coverage. **Phase 2/3 adds precision** by understanding config structure and semantics.

### Phase 2: High-Value Vertical Rules (Layer 3)

After Layer 1, add application-specific rules for the most impactful targets. These rules **build on Phase 1** by adding semantic understanding:

| Application | Phase 1 Catches | Phase 2 Adds |
|-------------|-----------------|--------------|
| **Kubernetes** | Secrets in YAML, `0.0.0.0` bindings | `privileged: true`, `hostNetwork`, `hostPID`, missing `securityContext`, `hostPort` exposure |
| **Docker** | Secrets in Dockerfile/compose, exposed ports | `USER root`, `--privileged`, capability additions, missing health checks |
| **nginx** | `0.0.0.0` listen, weak TLS strings | `proxy_pass` SSRF, `alias` path traversal, missing security headers, `server_tokens on` |
| **AWS IAM** | Hardcoded credentials | `"Effect": "Allow"` + `"Resource": "*"` + `"Action": "*"` overly permissive policies |

**Priority order:**
1. **Kubernetes** — Very common, high-impact misconfigs, well-defined YAML structure
2. **Docker** — Dockerfile and docker-compose security issues
3. **nginx** — Web server hardening, proxy misconfigs
4. **AWS IAM** — Overly permissive policies

### Phase 3: Format-Aware Parsing (Layer 2)

Add parsers as needed to reduce false positives and enable deeper analysis:
- YAML parser for Kubernetes/Docker Compose
- JSON parser for IAM policies
- nginx config parser for block-aware rules

---

## Severity Levels

| Severity | Description | Examples |
|----------|-------------|----------|
| 🔴 **Critical** | Immediate exploitation risk | Hardcoded production credentials, `privileged: true` in k8s |
| 🟠 **High** | Significant security weakness | TLS 1.0 enabled, database exposed on 0.0.0.0 |
| 🟡 **Medium** | Security best practice violation | Missing security headers, debug mode enabled |
| 🔵 **Low** | Informational, minor issues | Server version disclosure, verbose logging |

---

## Output Format

```json
{
  "file": "nginx.conf",
  "findings": [
    {
      "rule": "secrets/hardcoded-password",
      "severity": "critical",
      "line": 42,
      "message": "Hardcoded password detected",
      "match": "password = 's3cr3t'",
      "remediation": "Use environment variables or a secrets manager"
    },
    {
      "rule": "network/bind-all-interfaces", 
      "severity": "high",
      "line": 15,
      "message": "Service bound to all interfaces (0.0.0.0)",
      "match": "listen 0.0.0.0:80",
      "remediation": "Bind to specific interface or localhost if not public"
    }
  ]
}
```

---

## Testing

### Test Fixtures

Test fixtures are located in `test-configs/` directory, organized by scanner type:

```
test-configs/
├── secrets/
│   ├── bad/                    # Hardcoded secrets (SHOULD alert)
│   │   ├── nginx-hardcoded.conf
│   │   ├── docker-compose-secrets.yml
│   │   └── env-file.env
│   └── good/                   # Using env vars/secrets (should NOT alert)
│       ├── nginx-env-vars.conf
│       └── docker-compose-safe.yml
├── network/
│   ├── bad/                    # Dangerous exposure (SHOULD alert)
│   │   ├── nginx-exposed.conf
│   │   ├── docker-compose-exposed.yml
│   │   └── kubernetes-hostnetwork.yaml
│   └── good/                   # Properly secured (should NOT alert)
│       ├── nginx-localhost.conf
│       └── docker-compose-internal.yml
├── tls/
│   ├── bad/                    # Weak TLS/SSL (SHOULD alert)
│   │   ├── nginx-weak-tls.conf
│   │   └── haproxy-weak-tls.cfg
│   └── good/                   # Modern TLS only (should NOT alert)
│       └── nginx-modern-tls.conf
├── debug/
│   ├── bad/                    # Debug enabled (SHOULD alert)
│   │   ├── nginx-debug.conf
│   │   ├── php-debug.ini
│   │   └── app-debug.env
│   └── good/                   # Production settings (should NOT alert)
│       ├── nginx-production.conf
│       └── app-production.env
└── false-positives/            # Should NOT trigger alerts
    ├── comments-nginx.conf     # Values in comments
    ├── disabled-apache.conf    # Explicitly disabled settings
    ├── documentation.md        # Examples in docs
    └── placeholder-values.yml  # Obvious placeholders
```

### Test Expectations

| Scanner | Bad Files Should | Good Files Should | False Positives Should |
|---------|------------------|-------------------|------------------------|
| **Secrets** | Alert ≥1 per file | No alerts | No alerts |
| **Network** | Alert ≥1 per file | No alerts | No alerts |
| **TLS** | Alert ≥1 per file | No alerts | No alerts |
| **Debug** | Alert ≥1 per file | No alerts | No alerts |

### CI/CD Tests

Tests are automated in `.github/workflows/test.yml`:

```yaml
# Example test structure
test-config-scanner-secrets:
  name: Test Secrets Scanner
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    # Test bad configs are detected
    - name: Scan bad configs (should find issues)
      run: |
        result=$(node config-scanner.js test-configs/secrets/bad/)
        if [ $(echo "$result" | jq '.findings | length') -eq 0 ]; then
          echo "::error::Expected to find secrets in bad configs"
          exit 1
        fi
    
    # Test good configs pass
    - name: Scan good configs (should be clean)
      run: |
        result=$(node config-scanner.js test-configs/secrets/good/)
        if [ $(echo "$result" | jq '.findings | length') -gt 0 ]; then
          echo "::error::False positive in good configs"
          exit 1
        fi
```

### Running Tests Locally

```bash
# Test all scanners against bad configs (should find issues)
node config-scanner.js test-configs/secrets/bad/
node config-scanner.js test-configs/network/bad/
node config-scanner.js test-configs/tls/bad/
node config-scanner.js test-configs/debug/bad/

# Test against good configs (should be clean)
node config-scanner.js test-configs/secrets/good/
node config-scanner.js test-configs/network/good/
node config-scanner.js test-configs/tls/good/
node config-scanner.js test-configs/debug/good/

# Test false positive handling
node config-scanner.js test-configs/false-positives/
```

### Adding New Test Cases

1. Create file in appropriate `bad/` or `good/` directory
2. Add comment at top: `# SHOULD TRIGGER ALERTS` or `# SHOULD NOT TRIGGER`
3. Include realistic but obvious test patterns
4. Run test suite to verify behavior

---

## See Also

- [UC Software Scan Action](../README.md)
- [YARA Rules](../rules/) - Pattern-based malware detection
- [License Compliance](./LICENSE-COMPLIANCE.md)
- [Test Fixtures README](../test-configs/README.md)
