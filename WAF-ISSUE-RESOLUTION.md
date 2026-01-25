# WAF Issue Resolution - January 25, 2026

## Problem
The waf-proxy container was continuously restarting with the error:
```
Failed to start DebugLog: Failed to open file: /var/log/modsec_debug.log
```

## Root Cause
The ModSecurity configuration was trying to write log files to `/var/log/modsec_debug.log` and `/var/log/modsec_audit.log`, but the container didn't have the necessary permissions to create these files at startup.

## Solution Applied

### 1. Created Entrypoint Wrapper Script
Created `/root/waf-lab/waf/scripts/docker-entrypoint-wrapper.sh` that:
- Creates log files before ModSecurity starts
- Sets proper permissions (666) for log files
- Executes the original entrypoint

### 2. Updated Docker Compose Configuration
Modified `/root/waf-lab/docker-compose.yml` to:
- Use the custom entrypoint wrapper
- Mount the scripts directory
- Removed conflicting modsecurity-custom.conf mount (base image config works fine)
- Keep only CRS setup customization and custom rules

### 3. Simplified Configuration Approach
- Let the base image handle core ModSecurity configuration
- Only override CRS setup (paranoia level, thresholds)
- Add custom security rules without touching base config

## Current Status
✅ **WAF is running successfully**
- Container status: **Up and healthy**
- ModSecurity engine: **On** (blocking mode)
- Rules loaded: **933 rules** (OWASP CRS + custom rules)
- Paranoia level: **2**
- Responding to requests: **Yes** (HTTP 302 redirect working)

## Verification Commands

```bash
# Check container status
docker ps | grep waf

# View logs
docker logs waf-proxy | tail -20

# Test WAF response
curl -k -I https://localhost/

# Test SQL injection blocking
curl -k "https://localhost/?id=1' OR '1'='1"
# Should return 403 Forbidden

# Run full test suite
./waf/scripts/validate-config.sh
./waf/scripts/test-waf-attacks.sh https://localhost
```

## Files Modified

1. **docker-compose.yml**
   - Added custom entrypoint
   - Added scripts volume mount
   - Removed modsecurity-custom.conf mount

2. **waf/scripts/docker-entrypoint-wrapper.sh** (NEW)
   - Pre-creates log files with proper permissions

3. **waf/config/modsecurity-custom.conf**
   - Removed logging configuration to avoid conflicts

## WAF Configuration Summary

| Setting | Value |
|---------|-------|
| ModSecurity Engine | **On** (Blocking) |
| Paranoia Level | **2** |
| Inbound Threshold | **5** |
| Outbound Threshold | **4** |
| Max File Size | **10MB** |
| Rules Loaded | **933** |
| Custom Rules | **50+** (SQLi, XSS, CSRF, LFI, RFI, RCE, XXE, SSRF) |

## Custom Rules Active

- SQL Injection Protection (Rule IDs: 9001000-9001999)
- XSS Protection (Rule IDs: 9002000-9002999)
- CSRF Protection (Rule IDs: 9003000-9003999)
- Additional Threats (Rule IDs: 9005000-9005999)
  - LFI/RFI, RCE, XXE, SSRF, Response Splitting, LDAP Injection

## Next Steps

1. Run validation: `./waf/scripts/validate-config.sh`
2. Test attack protection: `./waf/scripts/test-waf-attacks.sh`
3. Performance benchmark: `./waf/scripts/performance-test.sh`
4. Monitor logs: `docker logs -f waf-proxy`

---

**Resolution Time**: ~30 minutes
**Status**: ✅ **RESOLVED**
**WAF**: ✅ **OPERATIONAL**
