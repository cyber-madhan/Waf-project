# Training Materials

## Document Information

| Item | Details |
|------|---------|
| Document Version | 1.0 |
| Last Updated | February 2026 |
| Target Audience | Security Analysts, Operations, Administrators |

---

## 1. Introduction

### 1.1 Purpose

This document provides training materials for personnel responsible for operating, monitoring, and maintaining the WAF (Web Application Firewall) solution. It includes user guides, best practices, and troubleshooting procedures.

### 1.2 Training Objectives

After completing this training, you will be able to:
- Understand WAF architecture and components
- Monitor security events using Grafana dashboards
- Interpret ModSecurity logs and alerts
- Perform routine maintenance tasks
- Troubleshoot common issues
- Apply security rule tuning

---

## 2. WAF Fundamentals

### 2.1 What is a WAF?

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         WEB APPLICATION FIREWALL                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   A WAF protects web applications by filtering and monitoring HTTP traffic      │
│   between a web application and the Internet.                                   │
│                                                                                  │
│                                                                                  │
│      Attacker                                                                   │
│         │                                                                        │
│         │  Malicious                                                            │
│         │  Request                                                              │
│         ▼                                                                        │
│   ┌─────────────┐     Legitimate     ┌─────────────────┐                        │
│   │             │     Request        │                 │                        │
│   │     WAF     │ ─────────────────► │   Application   │                        │
│   │             │                    │                 │                        │
│   └─────────────┘                    └─────────────────┘                        │
│         │                                                                        │
│         │  BLOCKED                                                              │
│         ▼                                                                        │
│      403 Forbidden                                                              │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 How ModSecurity Works

ModSecurity processes requests in 5 phases:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    MODSECURITY PROCESSING PHASES                                 │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   REQUEST FLOW                                                                  │
│   ────────────────────────────────────────────────────────                      │
│                                                                                  │
│   Phase 1: REQUEST HEADERS                                                      │
│   │   • URL parameters                                                          │
│   │   • HTTP headers                                                            │
│   │   • Cookies                                                                 │
│   ▼                                                                              │
│   Phase 2: REQUEST BODY                                                         │
│   │   • POST data                                                               │
│   │   • File uploads                                                            │
│   │   • JSON/XML payloads                                                       │
│   ▼                                                                              │
│   ═══════════════════════════════════════════════════                           │
│               REQUEST SENT TO APPLICATION                                        │
│   ═══════════════════════════════════════════════════                           │
│   ▼                                                                              │
│   Phase 3: RESPONSE HEADERS                                                     │
│   │   • Server headers                                                          │
│   │   • Content-Type                                                            │
│   ▼                                                                              │
│   Phase 4: RESPONSE BODY                                                        │
│   │   • HTML content                                                            │
│   │   • Data leakage detection                                                  │
│   ▼                                                                              │
│   Phase 5: LOGGING                                                              │
│       • Final scoring                                                           │
│       • Audit logging                                                           │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 OWASP Core Rule Set (CRS)

The CRS provides protection against:

| Attack Category | Rule Range | Description |
|-----------------|------------|-------------|
| SQL Injection | 942xxx | Database attacks |
| XSS | 941xxx | Cross-site scripting |
| LFI/RFI | 930xxx-931xxx | File inclusion |
| RCE | 932xxx | Remote code execution |
| Session Fixation | 943xxx | Session hijacking |
| Scanner Detection | 913xxx | Automated tools |
| Protocol Attacks | 920xxx-921xxx | HTTP violations |

---

## 3. Monitoring Dashboard Guide

### 3.1 Accessing Grafana

1. Open browser to: https://monitoring.project.work.gd
2. Login with credentials:
   - Username: `admin`
   - Password: `WafAdmin123!`
3. Navigate to: **Dashboards** → **WAF Security Dashboard**

### 3.2 Dashboard Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         WAF SECURITY DASHBOARD                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   ┌─────────────┬─────────────┬─────────────┬─────────────┬─────────────┐      │
│   │   Total     │   Success   │   Blocked   │   Rate      │   Status    │      │
│   │   Requests  │   Requests  │   Requests  │   (req/s)   │   Codes     │      │
│   │    1,234    │    1,200    │      34     │    0.5      │   [chart]   │      │
│   │             │             │   ⚠️ ALERT  │             │             │      │
│   └─────────────┴─────────────┴─────────────┴─────────────┴─────────────┘      │
│                                                                                  │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │                      REQUEST RATE OVER TIME                              │  │
│   │   [                     Graph showing traffic patterns                 ] │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
│   ┌────────────────────────────────┬────────────────────────────────────────┐  │
│   │     WAF BLOCKED REQUESTS       │        WAF SUCCESS REQUESTS            │  │
│   │                                │                                        │  │
│   │  [Recent blocked log entries]  │   [Recent successful log entries]     │  │
│   │                                │                                        │  │
│   └────────────────────────────────┴────────────────────────────────────────┘  │
│                                                                                  │
│   ┌─────────────────────────────────────────────────────────────────────────┐  │
│   │                      SYSTEM METRICS (CPU, Memory, Network)               │  │
│   │   [                     System performance graphs                      ] │  │
│   └─────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Key Metrics to Monitor

| Metric | Normal Range | Alert Threshold | Action |
|--------|--------------|-----------------|--------|
| Blocked Requests | 0-5 per hour | > 20 per hour | Investigate |
| Request Rate | 0.1-10 req/s | > 100 req/s | Check for DDoS |
| CPU Usage | < 50% | > 80% | Scale resources |
| Memory Usage | < 70% | > 85% | Check for leaks |
| P95 Latency | < 100ms | > 500ms | Investigate |

### 3.4 Time Range Selection

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│   TIME RANGE OPTIONS                                                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   Quick Ranges:                                                                 │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐             │
│   │ Last 5m  │ │ Last 1h  │ │ Last 6h  │ │ Last 24h │ │ Last 7d  │             │
│   └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘             │
│                                                                                  │
│   Use Last 1h for:  Real-time monitoring                                       │
│   Use Last 24h for: Daily review                                               │
│   Use Last 7d for:  Weekly trend analysis                                      │
│                                                                                  │
│   Auto-Refresh Options:                                                        │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐                                       │
│   │   5s     │ │   30s    │ │   Off    │                                       │
│   └──────────┘ └──────────┘ └──────────┘                                       │
│                                                                                  │
│   Use 5s refresh for: Active incident investigation                           │
│   Use 30s refresh for: Normal monitoring                                       │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Log Analysis

### 4.1 Understanding ModSecurity Logs

**Sample Blocked Request Log:**
```
[2026/02/01 15:30:45] [error] 533#533: *123 
[client 192.168.1.100] 
ModSecurity: Access denied with code 403 (phase 2). 
Matched "Operator `Rx' with parameter `(?i)(\b(union|select|insert|update|delete|drop)\b)' 
against variable `ARGS:id' 
(Value: `1' OR '1'='1' --') 
[file "/etc/modsecurity/coreruleset/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] 
[line "1234"] 
[id "942100"] 
[msg "SQL Injection Attack Detected"] 
[severity "CRITICAL"] 
[tag "attack-sqli"]
```

**How to Read:**

| Field | Value | Meaning |
|-------|-------|---------|
| Date | 2026/02/01 15:30:45 | When it happened |
| Client | 192.168.1.100 | Attacker's IP |
| Code | 403 | Access denied |
| Phase | 2 | Request body phase |
| Variable | ARGS:id | URL parameter "id" |
| Value | 1' OR '1'='1' -- | Malicious input |
| Rule ID | 942100 | SQL injection rule |
| Severity | CRITICAL | High priority |

### 4.2 Using Grafana Explore

1. Click **Explore** in left menu
2. Select **Loki** data source
3. Use these common queries:

**All Blocked Requests:**
```logql
{container="waf-proxy"} |= "403 Forbidden"
```

**SQL Injection Attempts:**
```logql
{container="waf-proxy"} |= "SQL Injection"
```

**XSS Attempts:**
```logql
{container="waf-proxy"} |= "XSS"
```

**Requests from Specific IP:**
```logql
{container="waf-proxy"} |= "192.168.1.100"
```

### 4.3 Audit Log Investigation

```bash
# View recent blocks
docker exec waf-proxy tail -100 /var/log/modsec_audit.log

# Search for specific rule
docker exec waf-proxy grep "942100" /var/log/modsec_audit.log

# Count blocks by rule
docker exec waf-proxy grep -o "id \"[0-9]*\"" /var/log/modsec_audit.log | sort | uniq -c | sort -rn | head -10
```

---

## 5. Security Operations Procedures

### 5.1 Daily Monitoring Tasks

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    DAILY MONITORING CHECKLIST                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   Morning Shift (Start of Day)                                                  │
│   ────────────────────────────────────                                          │
│   □ Check WAF dashboard for overnight alerts                                    │
│   □ Review blocked request count (compare to baseline)                          │
│   □ Verify all containers are running                                           │
│   □ Check SSL certificate expiration                                            │
│                                                                                  │
│   Afternoon Shift (Mid-Day)                                                     │
│   ────────────────────────────────────                                          │
│   □ Review any open security incidents                                          │
│   □ Check system resource utilization                                           │
│   □ Verify log shipping is functioning                                          │
│                                                                                  │
│   Evening Shift (End of Day)                                                    │
│   ────────────────────────────────────                                          │
│   □ Document any incidents from the day                                         │
│   □ Review and acknowledge alerts                                               │
│   □ Prepare handoff notes for next shift                                        │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Incident Response Workflow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    INCIDENT RESPONSE FLOWCHART                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│                          ┌───────────────────┐                                  │
│                          │   Alert Received  │                                  │
│                          └─────────┬─────────┘                                  │
│                                    │                                             │
│                                    ▼                                             │
│                    ┌───────────────────────────────┐                            │
│                    │   Is this a real attack?      │                            │
│                    │   Check logs and patterns     │                            │
│                    └───────────────┬───────────────┘                            │
│                                    │                                             │
│                    ┌───────────────┴───────────────┐                            │
│                    │                               │                            │
│                    ▼                               ▼                            │
│        ┌───────────────────┐           ┌───────────────────┐                   │
│        │   Real Attack     │           │   False Positive  │                   │
│        └─────────┬─────────┘           └─────────┬─────────┘                   │
│                  │                               │                              │
│                  ▼                               ▼                              │
│   ┌──────────────────────────┐    ┌──────────────────────────┐                 │
│   │ 1. Document attack       │    │ 1. Identify rule         │                 │
│   │ 2. Block attacking IP    │    │ 2. Create exclusion      │                 │
│   │ 3. Notify stakeholders   │    │ 3. Test fix              │                 │
│   │ 4. Collect evidence      │    │ 4. Deploy change         │                 │
│   │ 5. Write incident report │    │ 5. Document tuning       │                 │
│   └──────────────────────────┘    └──────────────────────────┘                 │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 5.3 Attack Investigation Steps

1. **Identify the Attack:**
   ```bash
   # Check recent blocked requests
   docker exec waf-proxy tail -50 /var/log/modsec_audit.log | grep "403"
   ```

2. **Get Attack Details:**
   ```bash
   # Find full request details
   docker exec waf-proxy grep -A 20 "942100" /var/log/modsec_audit.log | tail -25
   ```

3. **Check Attack Source:**
   ```bash
   # Count requests from IP
   docker exec waf-proxy grep "192.168.1.100" /var/log/nginx/access.log | wc -l
   ```

4. **Document Findings:**
   - Record timestamp, source IP, attack type
   - Save relevant log excerpts
   - Note any patterns

5. **Take Action:**
   - Block IP if necessary
   - Escalate if sophisticated attack
   - Update monitoring

---

## 6. Rule Tuning Guide

### 6.1 Identifying False Positives

**Signs of False Positive:**
- Legitimate users reporting access issues
- Normal application features being blocked
- Same rule triggering for many different users

**Investigation Steps:**
```bash
# Find the rule ID
docker exec waf-proxy grep "Access denied" /var/log/modsec_audit.log | grep -o "id \"[0-9]*\"" | sort | uniq -c

# Get details for specific rule
docker exec waf-proxy grep "942100" /var/log/modsec_audit.log | head -5
```

### 6.2 Creating Rule Exclusions

**Method 1: Disable Rule Completely**
```apache
# waf/rules/RULES-AFTER-CRS.conf
# WARNING: Only do this after careful analysis
SecRuleRemoveById 942100
```

**Method 2: Exclude for Specific URL**
```apache
# More targeted - recommended approach
SecRule REQUEST_URI "@beginsWith /api/search" \
    "id:10100,phase:1,pass,nolog,\
    ctl:ruleRemoveById=942100"
```

**Method 3: Exclude Specific Parameter**
```apache
# Exclude just the 'query' parameter
SecRuleUpdateTargetById 942100 "!ARGS:query"
```

### 6.3 Testing Rule Changes

```bash
# 1. Apply changes to config file

# 2. Test configuration
docker exec waf-proxy nginx -t

# 3. Reload configuration
docker exec waf-proxy nginx -s reload

# 4. Test the specific scenario
curl -v "https://your-domain.com/api/search?query=test"

# 5. Verify in logs
docker exec waf-proxy tail -10 /var/log/modsec_audit.log
```

---

## 7. Maintenance Procedures

### 7.1 Routine Maintenance Tasks

| Task | Frequency | Procedure |
|------|-----------|-----------|
| Check container health | Daily | `docker ps` |
| Review blocked requests | Daily | Grafana dashboard |
| Verify log shipping | Daily | Check Loki in Grafana |
| SSL certificate check | Weekly | `./manage-ssl.sh verify` |
| Rule updates | Monthly | `./manage-waf.sh update-rules` |
| Backup configuration | Weekly | `./backup.sh` |
| Disk space check | Weekly | `df -h` |
| Performance review | Monthly | Check latency metrics |

### 7.2 SSL Certificate Renewal

```bash
# Check certificate expiration
./waf/scripts/manage-ssl.sh verify

# Renew if needed (Let's Encrypt auto-renews)
./waf/scripts/manage-ssl.sh renew

# Restart to apply new certificate
docker compose restart waf-proxy
```

### 7.3 Container Updates

```bash
# Pull latest images
docker compose pull

# Recreate containers with new images
docker compose up -d --force-recreate

# Verify all running
docker compose ps

# Run tests
./waf/scripts/test-waf-attacks.sh
```

---

## 8. Troubleshooting Runbook

### 8.1 Common Issues and Solutions

#### Issue: WAF Container Not Starting

```bash
# Check logs
docker compose logs waf-proxy

# Common causes:
# 1. Port conflict
netstat -tlnp | grep -E "80|443"
# Solution: Stop conflicting service

# 2. Certificate issues
ls -la certs/
# Solution: Regenerate certificates

# 3. Configuration error
docker exec waf-proxy nginx -t
# Solution: Fix configuration syntax
```

#### Issue: Legitimate Traffic Being Blocked

```bash
# 1. Find the blocking rule
docker exec waf-proxy grep "403" /var/log/modsec_audit.log | tail -10

# 2. Identify rule ID
# Look for [id "XXXXXX"]

# 3. Create targeted exclusion
# Add to waf/rules/RULES-AFTER-CRS.conf

# 4. Reload
docker compose restart waf-proxy

# 5. Verify fix
curl -v "https://your-domain.com/affected-path"
```

#### Issue: High Latency

```bash
# 1. Check system resources
docker stats

# 2. Check Nginx connections
docker exec waf-proxy curl localhost:8080/stub_status

# 3. Check backend health
docker exec waf-proxy curl -I http://backend:80

# 4. Review slow rules
# Consider disabling expensive rules if needed
```

#### Issue: Dashboard Shows No Data

```bash
# 1. Check Prometheus targets
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[].health'

# 2. Check Loki
curl http://localhost:3100/ready

# 3. Check Promtail
docker logs promtail --tail 20

# 4. Verify data sources in Grafana
# Settings → Data Sources → Test
```

### 8.2 Emergency Procedures

#### Disable WAF (Emergency Only)

```bash
# Switch to detection-only mode (still logs but doesn't block)
docker exec waf-proxy sed -i 's/SecRuleEngine On/SecRuleEngine DetectionOnly/' /etc/nginx/modsecurity.d/modsecurity.conf
docker exec waf-proxy nginx -s reload

# To re-enable:
docker exec waf-proxy sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsecurity.d/modsecurity.conf
docker exec waf-proxy nginx -s reload
```

#### Block Attacking IP

```bash
# Add to nginx configuration
docker exec waf-proxy bash -c 'echo "deny 192.168.1.100;" >> /etc/nginx/conf.d/blocked-ips.conf'
docker exec waf-proxy nginx -s reload
```

#### Rollback to Previous Configuration

```bash
# Stop current deployment
docker compose down

# Restore from backup
tar -xzvf /opt/backups/waf-20260201.tar.gz -C /opt/waf-lab

# Restart
docker compose up -d
```

---

## 9. Best Practices

### 9.1 Security Best Practices

| Practice | Description |
|----------|-------------|
| Least Privilege | Use minimum necessary Grafana role |
| Password Security | Use strong, unique passwords |
| Log Review | Review logs daily for anomalies |
| Keep Updated | Apply security updates promptly |
| Backup Regularly | Weekly config backups minimum |
| Test Changes | Test rule changes before production |
| Document Everything | Keep records of all changes |

### 9.2 Monitoring Best Practices

| Practice | Description |
|----------|-------------|
| Baseline Traffic | Know normal traffic patterns |
| Alert Thresholds | Set meaningful, actionable alerts |
| Dashboard Refresh | Use appropriate refresh rates |
| Time Ranges | Use correct time ranges for analysis |
| Investigate Anomalies | Don't ignore unusual patterns |

### 9.3 Operational Best Practices

| Practice | Description |
|----------|-------------|
| Change Management | Document all changes |
| Testing | Test in staging before production |
| Monitoring | Monitor after any change |
| Communication | Notify team of significant changes |
| Runbooks | Follow documented procedures |

---

## 10. Quick Reference Card

### 10.1 Essential Commands

```bash
# Check WAF status
docker compose ps

# View WAF logs
docker compose logs -f waf-proxy

# Check blocked requests
docker exec waf-proxy tail -50 /var/log/modsec_audit.log

# Test WAF config
docker exec waf-proxy nginx -t

# Reload WAF config
docker exec waf-proxy nginx -s reload

# Restart WAF
docker compose restart waf-proxy

# Check SSL certificate
./waf/scripts/manage-ssl.sh verify

# Run attack tests
./waf/scripts/test-waf-attacks.sh
```

### 10.2 Key URLs

| Service | URL |
|---------|-----|
| Application | https://project.work.gd |
| Grafana | https://monitoring.project.work.gd |
| Prometheus | http://localhost:9090 |

### 10.3 Emergency Contacts

| Role | Contact | When to Contact |
|------|---------|-----------------|
| WAF Admin | [Your contact] | Configuration issues |
| Security Team | [Your contact] | Security incidents |
| On-Call | [Your contact] | After-hours emergencies |

---

## 11. Glossary

| Term | Definition |
|------|------------|
| CRS | Core Rule Set - OWASP's ModSecurity rules |
| ModSecurity | Open-source WAF engine |
| False Positive | Legitimate request incorrectly blocked |
| Paranoia Level | Security strictness level (1-4) |
| Anomaly Score | Cumulative score from rule matches |
| Phase | ModSecurity processing stage (1-5) |
| Rule ID | Unique identifier for each rule |
| LFI | Local File Inclusion attack |
| RFI | Remote File Inclusion attack |
| RCE | Remote Code Execution attack |
| XSS | Cross-Site Scripting attack |
| SQLi | SQL Injection attack |

---

## 12. Appendix: Training Assessment

### 12.1 Knowledge Check Questions

1. What are the 5 phases of ModSecurity processing?
2. What is the default paranoia level for the WAF?
3. How do you access the Grafana dashboard?
4. What LogQL query would you use to find SQL injection attempts?
5. How do you create a rule exclusion for a false positive?
6. What is the emergency procedure to disable WAF blocking?
7. How often should SSL certificates be checked?
8. What command tests Nginx configuration before reload?

### 12.2 Practical Exercises

1. **Log Analysis:** Find all blocked requests from the last hour using Grafana
2. **Rule Tuning:** Create an exclusion for a specific URL path
3. **Troubleshooting:** Diagnose why a container isn't starting
4. **Monitoring:** Set up a new alert for high blocked request rate
5. **Maintenance:** Perform a full backup of WAF configuration

---

**Document End**
