# Configuration Scanner Test Fixtures

This directory contains test fixtures for validating the configuration misconfiguration scanner.

## Directory Structure

```
test-configs/
├── secrets/
│   ├── bad/                    # Configs with hardcoded secrets (SHOULD alert)
│   │   ├── nginx-hardcoded.conf
│   │   ├── docker-compose-secrets.yml
│   │   └── env-file.env
│   └── good/                   # Configs using env vars/secrets (should NOT alert)
│       ├── nginx-env-vars.conf
│       └── docker-compose-safe.yml
│
├── network/
│   ├── bad/                    # Dangerous network exposure (SHOULD alert)
│   │   ├── nginx-exposed.conf
│   │   ├── docker-compose-exposed.yml
│   │   └── kubernetes-hostnetwork.yaml
│   └── good/                   # Properly secured networking (should NOT alert)
│       ├── nginx-localhost.conf
│       └── docker-compose-internal.yml
│
├── tls/
│   ├── bad/                    # Weak TLS/SSL settings (SHOULD alert)
│   │   ├── nginx-weak-tls.conf
│   │   └── haproxy-weak-tls.cfg
│   └── good/                   # Modern TLS only (should NOT alert)
│       └── nginx-modern-tls.conf
│
├── debug/
│   ├── bad/                    # Debug mode enabled (SHOULD alert)
│   │   ├── nginx-debug.conf
│   │   ├── php-debug.ini
│   │   └── app-debug.env
│   └── good/                   # Production settings (should NOT alert)
│       ├── nginx-production.conf
│       └── app-production.env
│
└── false-positives/            # Should NOT trigger alerts
    ├── comments-nginx.conf     # Dangerous values in comments
    ├── disabled-apache.conf    # Explicitly disabled settings
    ├── documentation.md        # Examples in documentation
    └── placeholder-values.yml  # Obvious placeholder values
```

## Test Expectations

### Phase 1 (Regex-based) Tests

| Scanner | Bad Files | Expected Alerts | Good Files | Expected Alerts |
|---------|-----------|-----------------|------------|-----------------|
| Secrets | `secrets/bad/*` | ≥1 per file | `secrets/good/*` | 0 |
| Network | `network/bad/*` | ≥1 per file | `network/good/*` | 0 |
| TLS | `tls/bad/*` | ≥1 per file | `tls/good/*` | 0 |
| Debug | `debug/bad/*` | ≥1 per file | `debug/good/*` | 0 |

### False Positive Tests

All files in `false-positives/` should produce **zero alerts** (or be flagged as low-confidence).

## Running Tests

```bash
# Test that bad configs are detected
node config-scanner.js test-configs/secrets/bad/
# Expected: alerts for each file

# Test that good configs pass
node config-scanner.js test-configs/secrets/good/
# Expected: no alerts

# Test false positive handling
node config-scanner.js test-configs/false-positives/
# Expected: no alerts (or low-confidence only)
```

## Adding New Test Cases

1. Create a new file in the appropriate `bad/` or `good/` directory
2. Add a comment at the top explaining what should/shouldn't trigger
3. Update this README if adding a new category
4. Run the test suite to verify behavior
