# Security Rules Configuration Guide

## Document Information

| Item | Details |
|------|---------|
| Document Version | 1.0 |
| Last Updated | February 2026 |
| WAF Engine | ModSecurity 3.0.14 |
| Rule Set | OWASP CRS 3.3.8 |

---

## 1. Overview

This document details the security rule configuration for the WAF implementation, including OWASP CRS settings, custom rules, and tuning guidelines.

---

## 2. OWASP Core Rule Set (CRS) Configuration

### 2.1 CRS Version and Statistics

| Metric | Value |
|--------|-------|
| CRS Version | 3.3.8 |
| Total Rules | 849 |
| Rule Categories | 15 |
| Paranoia Level | 2 |
| Anomaly Mode | Enabled |

### 2.2 Rule Categories

| Category | Rule Range | Description | Status |
|----------|------------|-------------|--------|
| INITIALIZATION | 901-910 | CRS initialization and setup | ✅ Active |
| METHOD-ENFORCEMENT | 911 | HTTP method validation | ✅ Active |
| SCANNER-DETECTION | 913 | Security scanner detection | ✅ Active |
| PROTOCOL-ENFORCEMENT | 920 | HTTP protocol compliance | ✅ Active |
| PROTOCOL-ATTACK | 921 | HTTP protocol attacks | ✅ Active |
| LFI | 930 | Local file inclusion | ✅ Active |
| RFI | 931 | Remote file inclusion | ✅ Active |
| RCE | 932 | Remote code execution | ✅ Active |
| PHP-INJECTION | 933 | PHP-specific attacks | ✅ Active |
| NODEJS-INJECTION | 934 | Node.js attacks | ✅ Active |
| XSS | 941 | Cross-site scripting | ✅ Active |
| SQLI | 942 | SQL injection | ✅ Active |
| SESSION-FIXATION | 943 | Session attacks | ✅ Active |
| JAVA-ATTACK | 944 | Java-specific attacks | ✅ Active |
| BLOCKING-EVALUATION | 949 | Anomaly scoring evaluation | ✅ Active |

### 2.3 Paranoia Levels Explained

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           PARANOIA LEVEL COMPARISON                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  LEVEL 1: Minimal False Positives                                               │
│  ├── Basic attack detection                                                     │
│  ├── Low false positive rate                                                    │
│  ├── Suitable for: Legacy apps, minimal tuning time                            │
│  └── Rules: ~200 active                                                         │
│                                                                                  │
│  LEVEL 2: Balanced (CURRENT SETTING) ◄───────────────────────────────────────  │
│  ├── Extended attack detection                                                  │
│  ├── Moderate false positive rate                                               │
│  ├── Suitable for: Most production environments                                 │
│  └── Rules: ~400 active                                                         │
│                                                                                  │
│  LEVEL 3: Enhanced Security                                                      │
│  ├── Strict attack detection                                                    │
│  ├── Higher false positive rate                                                 │
│  ├── Suitable for: High-security applications                                   │
│  └── Rules: ~600 active                                                         │
│                                                                                  │
│  LEVEL 4: Maximum Security                                                       │
│  ├── Aggressive attack detection                                                │
│  ├── Highest false positive rate                                                │
│  ├── Suitable for: Critical applications with extensive tuning                  │
│  └── Rules: ~849 active (all rules)                                             │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.4 CRS Configuration File

Location: `/etc/modsecurity.d/owasp-crs/crs-setup-custom.conf`

```apache
# =============================================================================
# OWASP CRS CUSTOM CONFIGURATION
# =============================================================================

# -----------------------------------------------------------------------------
# PARANOIA LEVEL
# -----------------------------------------------------------------------------
# Level 1: Minimal rules, lowest false positives
# Level 2: Balanced (recommended for most deployments)
# Level 3: Enhanced security, more false positives
# Level 4: Maximum security, requires extensive tuning
SecAction \
    "id:900000,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:tx.paranoia_level=2"

SecAction \
    "id:900001,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:tx.executing_paranoia_level=2"

# -----------------------------------------------------------------------------
# ANOMALY SCORING THRESHOLDS
# -----------------------------------------------------------------------------
# Inbound threshold: Total score before blocking request
# Lower = more strict, Higher = more lenient
SecAction \
    "id:900110,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:tx.inbound_anomaly_score_threshold=5"

# Outbound threshold: Total score for response blocking
SecAction \
    "id:900111,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:tx.outbound_anomaly_score_threshold=4"

# -----------------------------------------------------------------------------
# BLOCKING PARANOIA LEVEL
# -----------------------------------------------------------------------------
SecAction \
    "id:900002,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    setvar:tx.blocking_paranoia_level=2"

# -----------------------------------------------------------------------------
# ENFORCEMENT MODE
# -----------------------------------------------------------------------------
# On = Block attacks
# DetectionOnly = Log only, don't block
SecRuleEngine On
```

---

## 3. Anomaly Scoring System

### 3.1 How Anomaly Scoring Works

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          ANOMALY SCORING FLOW                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   Request: GET /search?q=<script>alert('XSS')</script>                          │
│                                                                                  │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    RULE EVALUATION                                       │   │
│   ├─────────────────────────────────────────────────────────────────────────┤   │
│   │                                                                          │   │
│   │   Rule 941100: XSS Attack Detected via libinjection                     │   │
│   │   └── Severity: CRITICAL  └── Score Added: +5                           │   │
│   │                                                                          │   │
│   │   Rule 941110: XSS Filter - Category 1: Script Tag Vector              │   │
│   │   └── Severity: CRITICAL  └── Score Added: +5                           │   │
│   │                                                                          │   │
│   │   Rule 941120: XSS Filter - Category 2: Event Handler Vector           │   │
│   │   └── Severity: CRITICAL  └── Score Added: +5                           │   │
│   │                                                                          │   │
│   │   Rule 941130: XSS Filter - Category 3: Attribute Vector               │   │
│   │   └── Severity: CRITICAL  └── Score Added: +5                           │   │
│   │                                                                          │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                    SCORE CALCULATION                                     │   │
│   ├─────────────────────────────────────────────────────────────────────────┤   │
│   │                                                                          │   │
│   │   Accumulated Score:   5 + 5 + 5 + 5 = 20                               │   │
│   │   Threshold Setting:   5                                                 │   │
│   │                                                                          │   │
│   │   Score (20) > Threshold (5)  →  ❌ REQUEST BLOCKED                     │   │
│   │                                                                          │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│   Result: HTTP 403 Forbidden                                                     │
│   Logged: Full transaction in audit log                                          │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Severity Scores

| Severity | Score | Example Rules |
|----------|-------|---------------|
| CRITICAL | 5 | SQLi, XSS, RCE attacks |
| ERROR | 4 | Protocol violations |
| WARNING | 3 | Suspicious patterns |
| NOTICE | 2 | Anomalous behavior |

### 3.3 Current Threshold Configuration

| Threshold Type | Value | Effect |
|----------------|-------|--------|
| Inbound Anomaly | 5 | Single critical rule triggers block |
| Outbound Anomaly | 4 | Blocks data leakage attempts |

---

## 4. Attack Protection Details

### 4.1 SQL Injection (SQLi) Protection

**Rule Range:** 942000-942999

```apache
# Example Rules Active:

# 942100: SQL Injection Attack Detected via libinjection
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_BODY|ARGS|ARGS_NAMES \
    "@detectSQLi" \
    "id:942100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,\
    msg:'SQL Injection Attack Detected via libinjection',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

# Patterns Blocked:
# ' OR '1'='1
# ; DROP TABLE users--
# UNION SELECT * FROM
# 1' AND 'a'='a
# admin'--
```

**Test Command:**
```bash
curl -k "https://charles.work.gd/test?id=1'+OR+'1'='1"
# Expected: HTTP 403 Forbidden
```

### 4.2 Cross-Site Scripting (XSS) Protection

**Rule Range:** 941000-941999

```apache
# Example Rules Active:

# 941100: XSS Attack Detected via libinjection
SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_BODY|ARGS|ARGS_NAMES \
    "@detectXSS" \
    "id:941100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,\
    msg:'XSS Attack Detected via libinjection',\
    severity:'CRITICAL'"

# Patterns Blocked:
# <script>alert('XSS')</script>
# <img src=x onerror=alert(1)>
# javascript:alert(1)
# <svg onload=alert(1)>
# <body onload=alert(1)>
```

**Test Command:**
```bash
curl -k "https://charles.work.gd/test?q=<script>alert(1)</script>"
# Expected: HTTP 403 Forbidden
```

### 4.3 Local File Inclusion (LFI) Protection

**Rule Range:** 930000-930999

```apache
# Example Rules Active:

# 930100: Path Traversal Attack
SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES \
    "@rx (?:(?:^|[\\/])\.\.[\\/]|[\\/]\.\.(?:[\\/]|$))" \
    "id:930100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,\
    msg:'Path Traversal Attack (/../)',\
    severity:'CRITICAL'"

# Patterns Blocked:
# ../../../etc/passwd
# ..\..\windows\system32
# /etc/shadow
# /proc/self/environ
```

**Test Command:**
```bash
curl -k "https://charles.work.gd/test?file=../../../etc/passwd"
# Expected: HTTP 403 Forbidden
```

### 4.4 Remote Code Execution (RCE) Protection

**Rule Range:** 932000-932999

```apache
# Example Rules Active:

# 932100: Unix Command Injection
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES \
    "@rx (?:;|\||`|&|\$\()" \
    "id:932100,\
    phase:2,\
    block,\
    capture,\
    msg:'Remote Command Execution: Unix Command Injection',\
    severity:'CRITICAL'"

# Patterns Blocked:
# ; cat /etc/passwd
# | ls -la
# `whoami`
# $(id)
# ; rm -rf /
```

**Test Command:**
```bash
curl -k "https://charles.work.gd/test?cmd=;cat+/etc/passwd"
# Expected: HTTP 403 Forbidden
```

### 4.5 Remote File Inclusion (RFI) Protection

**Rule Range:** 931000-931999

```apache
# Patterns Blocked:
# http://evil.com/shell.php
# https://attacker.com/malware.txt
# ftp://bad.site/exploit.php
```

### 4.6 Protocol Enforcement

**Rule Range:** 920000-920999

```apache
# Rules Include:
# - HTTP version validation
# - Required headers check
# - Content-Type validation
# - Request body limits
# - URL encoding validation
```

---

## 5. Custom Rules

### 5.1 Custom Rules Directory

Location: `/root/waf-lab/waf/rules/`

### 5.2 Monitoring Subdomain Exclusion

File: `monitoring-exclusions.conf`

```apache
# =============================================================================
# MONITORING SUBDOMAIN EXCLUSION RULE
# =============================================================================
# Purpose: Disable WAF inspection for monitoring subdomain to prevent
#          false positives on Grafana's PromQL/LogQL queries
#
# Affected: monitoring.charles.work.gd
# =============================================================================

SecRule REQUEST_HEADERS:Host "@rx ^monitoring\.charles\.work\.gd$" \
    "id:9999001,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleEngine=Off"
```

### 5.3 Creating Custom Rules

#### Template for Custom Rules

```apache
# =============================================================================
# CUSTOM RULE: [Description]
# =============================================================================
# Rule ID:     [Unique ID in range 100000-199999]
# Author:      [Your Name]
# Created:     [Date]
# Purpose:     [Why this rule exists]
# =============================================================================

SecRule [VARIABLE] "[OPERATOR]" \
    "id:[RULE_ID],\
    phase:[1-5],\
    [ACTION],\
    t:none,\
    msg:'[Message for logs]',\
    logdata:'[Additional log data]',\
    tag:'custom-rule',\
    severity:'[CRITICAL|ERROR|WARNING|NOTICE]'"
```

#### Example: Block Specific User Agent

```apache
# Block known malicious bot
SecRule REQUEST_HEADERS:User-Agent "@contains BadBot/1.0" \
    "id:100001,\
    phase:1,\
    deny,\
    status:403,\
    t:none,\
    msg:'Blocked malicious bot: BadBot',\
    logdata:'User-Agent: %{REQUEST_HEADERS.User-Agent}',\
    tag:'custom-rule',\
    tag:'bot-blocking',\
    severity:'WARNING'"
```

#### Example: Block Access to Sensitive Paths

```apache
# Block access to backup files
SecRule REQUEST_URI "@rx \.(bak|backup|old|orig|save|swp|tmp)$" \
    "id:100002,\
    phase:1,\
    deny,\
    status:403,\
    t:none,t:lowercase,\
    msg:'Blocked access to backup file',\
    logdata:'Requested URI: %{REQUEST_URI}',\
    tag:'custom-rule',\
    tag:'file-protection',\
    severity:'WARNING'"
```

#### Example: Rate Limiting

```apache
# Rate limit login attempts (requires ip collection)
SecAction \
    "id:100010,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    initcol:ip=%{REMOTE_ADDR}"

SecRule REQUEST_URI "@streq /login.php" \
    "id:100011,\
    phase:2,\
    pass,\
    t:none,\
    nolog,\
    setvar:ip.login_count=+1,\
    expirevar:ip.login_count=60"

SecRule IP:LOGIN_COUNT "@gt 5" \
    "id:100012,\
    phase:2,\
    deny,\
    status:429,\
    t:none,\
    msg:'Login rate limit exceeded',\
    logdata:'IP: %{REMOTE_ADDR}, Count: %{IP.LOGIN_COUNT}',\
    tag:'custom-rule',\
    tag:'rate-limiting',\
    severity:'WARNING'"
```

### 5.4 Deploying Custom Rules

1. Create rule file in `/root/waf-lab/waf/rules/`
2. Restart WAF container:
   ```bash
   docker compose restart waf-proxy
   ```
3. Test the rule:
   ```bash
   docker exec waf-proxy nginx -t
   ```
4. Verify in logs:
   ```bash
   docker logs waf-proxy --tail 50
   ```

---

## 6. Rule Tuning

### 6.1 Handling False Positives

When legitimate traffic is blocked, you have several options:

#### Option 1: Rule Exclusion (Recommended)

```apache
# Exclude specific rule for specific parameter
SecRuleUpdateTargetById 942100 "!ARGS:search_query"

# Exclude rule for specific URL
SecRule REQUEST_URI "@beginsWith /api/search" \
    "id:1000001,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=942100"
```

#### Option 2: Whitelist Specific Values

```apache
# Whitelist specific parameter value
SecRule ARGS:api_key "@streq known-safe-value" \
    "id:1000002,\
    phase:2,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=942100"
```

#### Option 3: Increase Anomaly Threshold

```apache
# In crs-setup-custom.conf
# Change from 5 to 10 (less strict)
setvar:tx.inbound_anomaly_score_threshold=10
```

### 6.2 False Positive Analysis Process

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     FALSE POSITIVE ANALYSIS WORKFLOW                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  1. IDENTIFY                                                                     │
│     └── Check audit log for blocked request                                     │
│         $ docker exec waf-proxy tail -f /var/log/modsec_audit.log              │
│                                                                                  │
│  2. ANALYZE                                                                      │
│     └── Extract key information:                                                │
│         • Rule ID that triggered                                                │
│         • Matched variable (ARGS, COOKIES, etc.)                                │
│         • Matched data (what triggered the rule)                                │
│         • Request URI and parameters                                            │
│                                                                                  │
│  3. VERIFY                                                                       │
│     └── Confirm this is legitimate traffic:                                     │
│         • Expected from application functionality?                               │
│         • Matches known user behavior?                                          │
│         • Not actually an attack attempt?                                       │
│                                                                                  │
│  4. REMEDIATE                                                                    │
│     └── Choose appropriate action:                                              │
│         • Exclude rule for specific parameter                                   │
│         • Whitelist specific IP/path                                            │
│         • Modify application to avoid trigger                                   │
│         • Adjust threshold (last resort)                                        │
│                                                                                  │
│  5. TEST                                                                         │
│     └── Verify fix works without weakening security:                            │
│         • Legitimate request now allowed                                        │
│         • Attack variants still blocked                                         │
│         • No new false positives introduced                                     │
│                                                                                  │
│  6. DOCUMENT                                                                     │
│     └── Record the tuning decision:                                             │
│         • Why rule was excluded                                                 │
│         • What legitimate functionality required it                              │
│         • Risk assessment                                                        │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Audit Logging

### 7.1 Audit Log Configuration

```apache
# Audit log settings in modsecurity.conf

# Log relevant status codes (not 404)
SecAuditLogRelevantStatus "^(?:5|4(?!04))"

# Audit log parts to include
SecAuditLogParts ABIJDEFHZ

# A = Audit log header
# B = Request headers
# C = Request body (if present)
# D = Reserved
# E = Response body
# F = Response headers
# G = Reserved
# H = Audit log trailer (rule matches)
# I = Compact request body (alternative to C)
# J = Uploaded files information
# K = All matched rules
# Z = Final boundary
```

### 7.2 Log Locations

| Log Type | Location | Purpose |
|----------|----------|---------|
| Audit Log | `/var/log/modsec_audit.log` | Full transaction details |
| Debug Log | `/var/log/modsec_debug.log` | Rule processing details |
| Nginx Access | Docker stdout | Request/response summary |
| Nginx Error | Docker stderr | Nginx errors |

### 7.3 Reading Audit Logs

```bash
# View recent blocked requests
docker exec waf-proxy tail -100 /var/log/modsec_audit.log | grep -A 20 "403"

# Search for specific rule
docker exec waf-proxy grep "942100" /var/log/modsec_audit.log

# Extract attack summary
docker exec waf-proxy grep "msg:" /var/log/modsec_audit.log | tail -20
```

---

## 8. Rule Updates

### 8.1 Checking Current Version

```bash
# Check CRS version
docker exec waf-proxy cat /etc/modsecurity.d/owasp-crs/CHANGES | head -20

# Count active rules
docker exec waf-proxy grep -r "SecRule" /etc/modsecurity.d/owasp-crs/rules/ | wc -l
```

### 8.2 Updating CRS

```bash
# Pull latest WAF image (includes updated CRS)
docker compose pull waf-proxy

# Restart with new image
docker compose up -d waf-proxy

# Verify new version
docker exec waf-proxy cat /etc/modsecurity.d/owasp-crs/CHANGES | head -5
```

### 8.3 Update Schedule Recommendation

| Component | Frequency | Reason |
|-----------|-----------|--------|
| OWASP CRS | Monthly | New attack signatures |
| ModSecurity | Quarterly | Security patches |
| Nginx | Quarterly | Security patches |
| Custom Rules | As needed | Application changes |

---

## 9. Security Testing

### 9.1 Automated Test Script

```bash
#!/bin/bash
# File: test-waf-attacks.sh

echo "=== WAF Security Test Suite ==="

# SQL Injection Tests
echo -e "\n[1] SQL Injection Tests"
echo -n "  Basic SQLi: "
curl -sk -o /dev/null -w "%{http_code}" "https://charles.work.gd/test?id=1'+OR+'1'='1"
echo " (expect 403)"

echo -n "  Union SQLi: "
curl -sk -o /dev/null -w "%{http_code}" "https://charles.work.gd/test?id=1+UNION+SELECT+*+FROM+users"
echo " (expect 403)"

# XSS Tests
echo -e "\n[2] XSS Tests"
echo -n "  Script Tag: "
curl -sk -o /dev/null -w "%{http_code}" "https://charles.work.gd/test?q=<script>alert(1)</script>"
echo " (expect 403)"

echo -n "  Event Handler: "
curl -sk -o /dev/null -w "%{http_code}" "https://charles.work.gd/test?q=<img+src=x+onerror=alert(1)>"
echo " (expect 403)"

# LFI Tests
echo -e "\n[3] LFI Tests"
echo -n "  Path Traversal: "
curl -sk -o /dev/null -w "%{http_code}" "https://charles.work.gd/test?file=../../../etc/passwd"
echo " (expect 403)"

# RCE Tests
echo -e "\n[4] RCE Tests"
echo -n "  Command Injection: "
curl -sk -o /dev/null -w "%{http_code}" "https://charles.work.gd/test?cmd=;cat+/etc/passwd"
echo " (expect 403)"

# Legitimate Request
echo -e "\n[5] Legitimate Request Test"
echo -n "  Normal Request: "
curl -sk -o /dev/null -w "%{http_code}" "https://charles.work.gd/"
echo " (expect 200/302)"

echo -e "\n=== Tests Complete ==="
```

### 9.2 Running Tests

```bash
# Run all tests
./waf/scripts/test-waf-attacks.sh

# Expected output: All attacks return 403, legitimate request returns 200/302
```

---

## 10. Quick Reference

### 10.1 Common Commands

```bash
# Check WAF status
docker exec waf-proxy nginx -t

# View recent blocks
docker logs waf-proxy 2>&1 | grep "403"

# Count blocked requests
docker logs waf-proxy 2>&1 | grep -c "403"

# Reload configuration
docker exec waf-proxy nginx -s reload

# View active rules count
docker exec waf-proxy grep -r "SecRule" /etc/modsecurity.d/ | wc -l
```

### 10.2 Rule ID Ranges

| Range | Purpose |
|-------|---------|
| 1-99999 | Reserved for CRS |
| 100000-199999 | Custom rules |
| 200000-299999 | Exclusion rules |
| 9999000-9999999 | Emergency bypass rules |

### 10.3 Severity Reference

| Level | Score | Use Case |
|-------|-------|----------|
| CRITICAL | 5 | Confirmed attacks |
| ERROR | 4 | High confidence threats |
| WARNING | 3 | Suspicious activity |
| NOTICE | 2 | Anomalies worth logging |

---

**Document End**
