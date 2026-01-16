# Security Configuration Guide

This document explains what NOT to do.

## Bad Examples (Do NOT use these)

### Hardcoded Secrets
Never put secrets directly in config files:
```
# BAD - Don't do this!
password = "secret123"
API_KEY = "sk_live_xxx"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG"
```

### Network Exposure
Never bind to all interfaces unless necessary:
```
# BAD - Exposes to internet
listen 0.0.0.0:80;
bind_address = 0.0.0.0
```

### Weak TLS
Never enable old TLS versions:
```
# BAD - Weak encryption
ssl_protocols TLSv1 TLSv1.1;
SSLv3
```

## Good Examples

Use environment variables for secrets:
```
password = ${DB_PASSWORD}
```
