# WAF Configuration Documentation

## Overview
This directory contains custom ModSecurity configurations and security rules for the Web Application Firewall.

## Directory Structure

```
waf/
├── config/                      # Main configuration files
│   ├── modsecurity-custom.conf  # Core ModSecurity settings
│   └── crs-setup-custom.conf    # OWASP CRS customizations
├── rules/                       # Custom security rules
│   ├── custom-sqli-rules.conf   # SQL Injection protection
│   ├── custom-xss-rules.conf    # XSS protection
│   ├── custom-csrf-rules.conf   # CSRF protection
│   ├── custom-additional-rules.conf  # LFI, RFI, RCE, XXE, SSRF
│   └── rule-exclusions.conf     # Rule whitelisting and exceptions
├── scripts/                     # Testing and validation scripts
│   ├── test-waf-attacks.sh      # Attack vector testing
│   ├── validate-config.sh       # Configuration validation
│   └── performance-test.sh      # Performance benchmarking
└── logs/                        # WAF logs directory
```

## Configuration Files

### modsecurity-custom.conf
Core ModSecurity engine configuration including:
- Request/response body handling
- Logging configuration
- PCRE tuning
- Content-type enforcement
- Security headers

**Key Settings:**
- `SecRuleEngine On` - Enables blocking mode
- `SecRequestBodyLimit 13107200` - 12.5MB max request size
- `SecAuditEngine RelevantOnly` - Logs only relevant events
- `SecDebugLogLevel 3` - Production logging level

### crs-setup-custom.conf
OWASP CRS specific configurations:
- **Paranoia Level: 2** - Balanced security vs. false positives
- **Inbound Anomaly Threshold: 5** - Score required to block
- **Outbound Anomaly Threshold: 4** - Response blocking threshold
- HTTP policy enforcement
- Rate limiting settings

## Custom Security Rules

### SQL Injection Protection (9001000-9001999)
Detects and blocks:
- UNION-based attacks
- Boolean-based blind SQLi
- Time-based blind SQLi
- Stacked queries
- SQL comments and keywords
- Authentication bypass attempts
- Database enumeration
- Hex encoding evasion

### XSS Protection (9002000-9002999)
Covers:
- Script tag injection
- Event handler exploitation
- JavaScript protocol abuse
- Dangerous HTML tags (iframe, object, embed)
- HTML entity encoding
- DOM-based XSS patterns
- SVG-based XSS
- Template injection (AngularJS, etc.)

### CSRF Protection (9003000-9003999)
Implements:
- CSRF token validation
- Referer header checking
- Origin header validation
- Content-Type enforcement
- Double-submit cookie pattern
- SameSite cookie checks
- Custom header verification

### Additional Protections (9005000-9005999)
- **LFI/Path Traversal**: Directory traversal, absolute paths
- **RFI**: Remote file inclusion, PHP wrappers
- **RCE**: Command injection, shell metacharacters
- **XXE**: XML external entity attacks
- **SSRF**: Internal IP access, cloud metadata
- **Response Splitting**: CRLF injection
- **LDAP Injection**: Filter manipulation

## Rule Exclusions

The `rule-exclusions.conf` file allows whitelisting legitimate traffic:

### Common Exclusions
- Static assets (images, CSS, JS)
- API endpoints
- Health check endpoints
- File upload paths
- Admin panels (IP-restricted)
- Webhook callbacks

### Adding Custom Exclusions

```apache
SecRule REQUEST_URI "@beginsWith /your-path/" \
  "id:9004XXX,\
   phase:1,\
   pass,\
   nolog,\
   t:none,\
   ctl:ruleRemoveById=RULE-RANGE"
```

## Testing Scripts

### 1. validate-config.sh
Validates WAF configuration and setup:
- Container status check
- Configuration file validation
- Nginx syntax check
- SSL certificate verification
- Log directory checks
- Basic connectivity test

**Usage:**
```bash
./waf/scripts/validate-config.sh
```

### 2. test-waf-attacks.sh
Tests WAF against various attack vectors:
- 8 SQL injection tests
- 9 XSS tests
- 5 LFI tests
- 4 RFI tests
- 5 RCE tests
- 2 XXE tests
- 4 SSRF tests
- 2 Response splitting tests
- 2 LDAP injection tests

**Usage:**
```bash
./waf/scripts/test-waf-attacks.sh [URL]
# Example: ./waf/scripts/test-waf-attacks.sh https://project.work.gd
```

**Output:** Generates test report in `waf/logs/test-results/`

### 3. performance-test.sh
Benchmarks WAF performance:
- Baseline performance
- GET request throughput
- POST request handling
- JSON payload processing
- Large payload handling
- Sustained load testing

**Usage:**
```bash
./waf/scripts/performance-test.sh [URL] [CONCURRENCY] [REQUESTS]
# Example: ./waf/scripts/performance-test.sh https://localhost 10 1000
```

**Requirements:** Apache Bench (ab) - Install with:
```bash
apt-get install apache2-utils
```

## Docker Compose Configuration

The WAF is configured with enhanced settings:

```yaml
environment:
  - MODSEC_RULE_ENGINE=On              # Blocking mode enabled
  - PARANOIA=2                          # Elevated security
  - ANOMALYIN=5                         # Inbound threshold
  - ANOMALYOUT=4                        # Outbound threshold
  - BLOCKING_PARANOIA=2                 # Active blocking level
  - MAX_FILE_SIZE=10485760             # 10MB max file size
  - MODSEC_DEBUG_LOGLEVEL=3            # Production logging
```

**Mounted Volumes:**
- Custom configs: `./waf/config/` → `/etc/modsecurity.d/`
- Custom rules: `./waf/rules/` → `/etc/modsecurity.d/custom-rules/`
- Logs: `./waf/logs/` → `/var/log/modsec/`

## Deployment Steps

### 1. Initial Setup
```bash
# Ensure all files are in place
ls -la waf/config/
ls -la waf/rules/
ls -la waf/scripts/

# Validate structure
./waf/scripts/validate-config.sh
```

### 2. Start WAF
```bash
# Start in detection mode first (testing)
docker-compose up -d waf

# Check logs
docker logs -f waf-proxy

# Watch for issues
tail -f waf/logs/audit.log
```

### 3. Test Configuration
```bash
# Validate setup
./waf/scripts/validate-config.sh

# Test attack protection
./waf/scripts/test-waf-attacks.sh

# Benchmark performance
./waf/scripts/performance-test.sh
```

### 4. Enable Blocking Mode
Once validated, blocking is already enabled in docker-compose.yml:
```yaml
MODSEC_RULE_ENGINE=On
```

### 5. Monitor and Tune
```bash
# Watch real-time blocks
tail -f waf/logs/audit.log | grep "ModSecurity: Access denied"

# Review false positives
grep "id \"90" waf/logs/audit.log

# Adjust rules in rule-exclusions.conf as needed
```

## Paranoia Levels

| Level | Description | False Positives | Security |
|-------|-------------|-----------------|----------|
| 1 | Basic | Very Low | Basic |
| 2 | Elevated | Low | Good ✓ |
| 3 | High | Moderate | Strong |
| 4 | Maximum | High | Maximum |

**Current Setting: Level 2** (Balanced)

## Anomaly Scoring

The WAF uses anomaly scoring rather than immediate blocking:

- **Critical Anomaly: 5 points** (SQLi, XSS, RCE)
- **Error Anomaly: 4 points** (Protocol violations)
- **Warning Anomaly: 3 points** (Suspicious patterns)
- **Notice Anomaly: 2 points** (Informational)

**Blocking occurs when total score ≥ threshold:**
- Inbound: 5 points
- Outbound: 4 points

## Performance Optimization

### Current Optimizations
- PCRE match limit: 100,000
- Request body limit: 12.5MB
- Response body limit: 512KB
- Static asset bypass
- Stream inspection off
- Collection timeout: 600s

### Expected Performance
- Latency: < 50ms overhead
- Throughput: > 100 req/sec
- CPU Impact: < 20%
- Memory: ~256MB per container

## Logging

### Log Locations
- **Audit Log**: `waf/logs/audit.log` - Blocked requests
- **Debug Log**: `waf/logs/debug.log` - Detailed events
- **Nginx Access**: Docker logs - HTTP access
- **Nginx Error**: Docker logs - Server errors

### Log Formats
Audit logs use ModSecurity native format. To switch to JSON:
```apache
SecAuditLogFormat JSON
```

### Log Rotation
Implement log rotation to manage disk space:
```bash
# Add to crontab
0 0 * * * find /root/waf-lab/waf/logs -name "*.log" -mtime +7 -delete
```

## Compliance Alignment

### OWASP Top 10 Coverage
✅ A01:2021 - Broken Access Control (CSRF, Session Fixation)
✅ A02:2021 - Cryptographic Failures (SSL/TLS enforcement)
✅ A03:2021 - Injection (SQLi, XSS, LDAP, XXE, RCE)
✅ A04:2021 - Insecure Design (Rate limiting, validation)
✅ A05:2021 - Security Misconfiguration (Secure headers)
✅ A06:2021 - Vulnerable Components (CRS rules)
✅ A07:2021 - Authentication Failures (Login CSRF)
✅ A08:2021 - Software/Data Integrity (Response splitting)
✅ A09:2021 - Logging Failures (Comprehensive logging)
✅ A10:2021 - SSRF (Internal IP blocking)

### PCI DSS Requirements
- 6.6: WAF protecting web applications ✓
- 10.2: Audit logging enabled ✓
- 10.3: Audit trail includes user ID, events, etc. ✓
- 4.1: SSL/TLS encryption for transmission ✓

## Troubleshooting

### False Positives
1. Identify the rule ID in logs
2. Add exclusion in `rule-exclusions.conf`
3. Restart WAF: `docker-compose restart waf`

### Performance Issues
1. Check paranoia level (consider lowering to 1)
2. Review response body inspection settings
3. Add static asset exclusions
4. Increase container resources

### Rules Not Working
1. Validate config: `./waf/scripts/validate-config.sh`
2. Check rule loading: `docker logs waf-proxy | grep "custom-rules"`
3. Verify rule syntax: Look for parsing errors
4. Ensure rule IDs don't conflict

## Maintenance

### Regular Tasks
- **Daily**: Review blocked requests
- **Weekly**: Analyze false positives
- **Monthly**: Update CRS rules
- **Quarterly**: Performance testing
- **Annually**: Security audit

### Rule Updates
```bash
# Pull latest base image with updated CRS
docker-compose pull waf

# Restart with new image
docker-compose up -d waf
```

## Support and Resources

- **ModSecurity Reference**: https://github.com/SpiderLabs/ModSecurity/wiki
- **OWASP CRS**: https://coreruleset.org/docs/
- **CRS Rule Documentation**: https://coreruleset.org/docs/rules/
- **ModSecurity Handbook**: https://www.feistyduck.com/books/modsecurity-handbook/

## Security Contact

For security issues or questions:
- Review logs: `docker logs waf-proxy`
- Test configuration: `./waf/scripts/validate-config.sh`
- Check documentation: This README.md

---

**Version**: 1.0  
**Last Updated**: January 25, 2026  
**Author**: Spinnaker Analytics WAF Team
