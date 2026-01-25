#!/bin/bash

# ========================================
# WAF Configuration Validation Script
# ========================================
# Validates ModSecurity configuration and rules

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}WAF Configuration Validation${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if WAF container is running
echo -e "${YELLOW}Checking WAF container status...${NC}"
if docker ps | grep -q "waf-proxy"; then
    echo -e "${GREEN}✓ WAF container is running${NC}"
else
    echo -e "${RED}✗ WAF container is not running${NC}"
    echo "Start the container with: docker-compose up -d waf"
    exit 1
fi
echo ""

# Check ModSecurity configuration
echo -e "${YELLOW}Validating ModSecurity configuration...${NC}"

# Get ModSecurity status
MODSEC_STATUS=$(docker exec waf-proxy sh -c "grep -r 'SecRuleEngine' /etc/modsecurity.d/ 2>/dev/null | grep -v '#' | tail -1" || echo "Not found")
echo "ModSecurity Engine Status: $MODSEC_STATUS"

# Check if custom config files are loaded
if docker exec waf-proxy test -f /etc/modsecurity.d/modsecurity-custom.conf; then
    echo -e "${GREEN}✓ Custom ModSecurity config found${NC}"
else
    echo -e "${RED}✗ Custom ModSecurity config not found${NC}"
fi

if docker exec waf-proxy test -f /etc/modsecurity.d/owasp-crs/crs-setup-custom.conf; then
    echo -e "${GREEN}✓ Custom CRS setup found${NC}"
else
    echo -e "${RED}✗ Custom CRS setup not found${NC}"
fi
echo ""

# Check custom rules
echo -e "${YELLOW}Checking custom security rules...${NC}"

RULE_FILES=(
    "custom-sqli-rules.conf"
    "custom-xss-rules.conf"
    "custom-csrf-rules.conf"
    "custom-additional-rules.conf"
    "rule-exclusions.conf"
)

for rule_file in "${RULE_FILES[@]}"; do
    if docker exec waf-proxy test -f "/etc/modsecurity.d/custom-rules/$rule_file"; then
        echo -e "${GREEN}✓ $rule_file loaded${NC}"
    else
        echo -e "${RED}✗ $rule_file not found${NC}"
    fi
done
echo ""

# Check Nginx configuration
echo -e "${YELLOW}Validating Nginx configuration...${NC}"
if docker exec waf-proxy nginx -t 2>&1 | grep -q "successful"; then
    echo -e "${GREEN}✓ Nginx configuration is valid${NC}"
else
    echo -e "${RED}✗ Nginx configuration has errors${NC}"
    docker exec waf-proxy nginx -t
fi
echo ""

# Check SSL certificates
echo -e "${YELLOW}Checking SSL certificates...${NC}"
if docker exec waf-proxy test -f /etc/nginx/conf/fullchain.pem; then
    echo -e "${GREEN}✓ SSL certificate found${NC}"
    # Check certificate expiration
    CERT_EXPIRY=$(docker exec waf-proxy openssl x509 -in /etc/nginx/conf/fullchain.pem -noout -enddate 2>/dev/null | cut -d= -f2)
    echo "Certificate expires: $CERT_EXPIRY"
else
    echo -e "${RED}✗ SSL certificate not found${NC}"
fi
echo ""

# Check log directories
echo -e "${YELLOW}Checking log configuration...${NC}"
if [ -d "./waf/logs" ]; then
    echo -e "${GREEN}✓ Log directory exists${NC}"
    LOG_COUNT=$(find ./waf/logs -type f 2>/dev/null | wc -l)
    echo "Log files found: $LOG_COUNT"
else
    echo -e "${RED}✗ Log directory not found${NC}"
fi
echo ""

# Test basic connectivity
echo -e "${YELLOW}Testing WAF connectivity...${NC}"
HTTP_RESPONSE=$(curl -k -s -o /dev/null -w "%{http_code}" https://localhost/ --max-time 5 2>/dev/null || echo "000")

if [ "$HTTP_RESPONSE" == "200" ] || [ "$HTTP_RESPONSE" == "302" ] || [ "$HTTP_RESPONSE" == "301" ]; then
    echo -e "${GREEN}✓ WAF is responding (HTTP $HTTP_RESPONSE)${NC}"
else
    echo -e "${RED}✗ WAF is not responding properly (HTTP $HTTP_RESPONSE)${NC}"
fi
echo ""

# Check environment variables
echo -e "${YELLOW}Checking WAF environment configuration...${NC}"
docker exec waf-proxy env | grep -E "MODSEC|PARANOIA|ANOMALY|BACKEND" | while read line; do
    echo "  $line"
done
echo ""

# Test rule effectiveness
echo -e "${YELLOW}Testing rule effectiveness...${NC}"
echo "Testing SQL injection detection..."
TEST_RESPONSE=$(curl -k -s -o /dev/null -w "%{http_code}" "https://localhost/?id=1' OR '1'='1" --max-time 5 2>/dev/null || echo "000")

if [ "$TEST_RESPONSE" == "403" ] || [ "$TEST_RESPONSE" == "406" ]; then
    echo -e "${GREEN}✓ SQL injection blocked (HTTP $TEST_RESPONSE)${NC}"
else
    echo -e "${YELLOW}⚠ SQL injection not blocked (HTTP $TEST_RESPONSE)${NC}"
    echo "  This might be expected if you're in DetectionOnly mode"
fi
echo ""

# Check ModSecurity audit log
echo -e "${YELLOW}Checking recent WAF activity...${NC}"
if docker exec waf-proxy test -f /var/log/modsec/audit.log; then
    RECENT_BLOCKS=$(docker exec waf-proxy tail -n 100 /var/log/modsec/audit.log 2>/dev/null | grep -c "ModSecurity" || echo "0")
    echo "Recent ModSecurity events: $RECENT_BLOCKS"
else
    echo -e "${YELLOW}⚠ Audit log not found or empty${NC}"
fi
echo ""

# Resource usage
echo -e "${YELLOW}Container resource usage...${NC}"
docker stats waf-proxy --no-stream --format "  CPU: {{.CPUPerc}}\n  Memory: {{.MemUsage}}"
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Validation Complete${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "  1. Review logs: docker logs waf-proxy"
echo "  2. Test attacks: ./waf/scripts/test-waf-attacks.sh"
echo "  3. Monitor live traffic: tail -f ./waf/logs/audit.log"
echo "  4. Adjust paranoia level in docker-compose.yml if needed"
echo ""

exit 0
