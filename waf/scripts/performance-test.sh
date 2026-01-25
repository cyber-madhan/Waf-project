#!/bin/bash

# ========================================
# WAF Performance Testing Script
# ========================================
# Tests WAF latency and throughput

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TARGET_URL="${1:-https://localhost}"
CONCURRENCY="${2:-10}"
REQUESTS="${3:-1000}"
OUTPUT_DIR="./waf/logs/performance"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}WAF Performance Testing${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Target: $TARGET_URL"
echo "Concurrency: $CONCURRENCY"
echo "Total Requests: $REQUESTS"
echo ""

# Check if ApacheBench is installed
if ! command -v ab &> /dev/null; then
    echo -e "${RED}Error: ApacheBench (ab) is not installed${NC}"
    echo "Install with: sudo apt-get install apache2-utils"
    exit 1
fi

# Function to run performance test
run_test() {
    local test_name="$1"
    local url="$2"
    local output_file="$OUTPUT_DIR/${test_name}-${TIMESTAMP}.txt"
    
    echo -e "${YELLOW}Running test: $test_name${NC}"
    
    ab -n "$REQUESTS" -c "$CONCURRENCY" -k -g "$OUTPUT_DIR/${test_name}-${TIMESTAMP}.tsv" "$url" > "$output_file" 2>&1
    
    # Extract key metrics
    local requests_per_sec=$(grep "Requests per second" "$output_file" | awk '{print $4}')
    local time_per_request=$(grep "Time per request" "$output_file" | grep -m1 "mean" | awk '{print $4}')
    local failed_requests=$(grep "Failed requests" "$output_file" | awk '{print $3}')
    local transfer_rate=$(grep "Transfer rate" "$output_file" | awk '{print $3}')
    
    echo -e "${GREEN}Results:${NC}"
    echo "  Requests per second: $requests_per_sec"
    echo "  Time per request: $time_per_request ms"
    echo "  Failed requests: $failed_requests"
    echo "  Transfer rate: $transfer_rate Kbytes/sec"
    echo ""
    
    sleep 2
}

# Test 1: Baseline performance (without WAF processing)
echo -e "${BLUE}Test 1: Baseline Performance${NC}"
run_test "baseline" "$TARGET_URL/"

# Test 2: GET requests
echo -e "${BLUE}Test 2: GET Requests${NC}"
run_test "get-requests" "$TARGET_URL/index.php"

# Test 3: POST requests
echo -e "${BLUE}Test 3: POST Requests (with simple data)${NC}"
ab -n "$REQUESTS" -c "$CONCURRENCY" -p /dev/stdin -T "application/x-www-form-urlencoded" "$TARGET_URL/login.php" <<EOF > "$OUTPUT_DIR/post-requests-${TIMESTAMP}.txt" 2>&1
username=test&password=test
EOF

POST_RPS=$(grep "Requests per second" "$OUTPUT_DIR/post-requests-${TIMESTAMP}.txt" | awk '{print $4}')
echo -e "${GREEN}POST Requests per second: $POST_RPS${NC}"
echo ""

# Test 4: JSON payloads
echo -e "${BLUE}Test 4: JSON Payloads${NC}"
ab -n "$REQUESTS" -c "$CONCURRENCY" -p /dev/stdin -T "application/json" "$TARGET_URL/api/test" <<EOF > "$OUTPUT_DIR/json-requests-${TIMESTAMP}.txt" 2>&1
{"test":"data","number":123}
EOF

JSON_RPS=$(grep "Requests per second" "$OUTPUT_DIR/json-requests-${TIMESTAMP}.txt" | awk '{print $4}')
echo -e "${GREEN}JSON Requests per second: $JSON_RPS${NC}"
echo ""

# Test 5: Large payloads
echo -e "${BLUE}Test 5: Large Payloads${NC}"
LARGE_DATA=$(python3 -c "print('a' * 10000)")
ab -n 100 -c 5 -p /dev/stdin -T "application/x-www-form-urlencoded" "$TARGET_URL/upload.php" <<EOF > "$OUTPUT_DIR/large-payload-${TIMESTAMP}.txt" 2>&1
data=$LARGE_DATA
EOF

LARGE_RPS=$(grep "Requests per second" "$OUTPUT_DIR/large-payload-${TIMESTAMP}.txt" | awk '{print $4}')
echo -e "${GREEN}Large payload Requests per second: $LARGE_RPS${NC}"
echo ""

# Test 6: Sustained load test
echo -e "${BLUE}Test 6: Sustained Load (60 seconds)${NC}"
SUSTAINED_REQUESTS=$((CONCURRENCY * 60))
ab -n "$SUSTAINED_REQUESTS" -c "$CONCURRENCY" -t 60 "$TARGET_URL/" > "$OUTPUT_DIR/sustained-load-${TIMESTAMP}.txt" 2>&1

SUSTAINED_RPS=$(grep "Requests per second" "$OUTPUT_DIR/sustained-load-${TIMESTAMP}.txt" | awk '{print $4}')
echo -e "${GREEN}Sustained Requests per second: $SUSTAINED_RPS${NC}"
echo ""

# Generate summary report
REPORT_FILE="$OUTPUT_DIR/performance-summary-${TIMESTAMP}.txt"

cat > "$REPORT_FILE" <<EOF
========================================
WAF Performance Testing Summary
========================================
Date: $(date)
Target: $TARGET_URL
Concurrency Level: $CONCURRENCY
Total Requests per Test: $REQUESTS

========================================
Test Results
========================================

1. Baseline Performance
   - Requests/sec: $(grep "Requests per second" "$OUTPUT_DIR/baseline-${TIMESTAMP}.txt" | awk '{print $4}')
   - Time/request: $(grep "Time per request" "$OUTPUT_DIR/baseline-${TIMESTAMP}.txt" | grep -m1 "mean" | awk '{print $4}') ms

2. GET Requests
   - Requests/sec: $(grep "Requests per second" "$OUTPUT_DIR/get-requests-${TIMESTAMP}.txt" | awk '{print $4}')
   - Time/request: $(grep "Time per request" "$OUTPUT_DIR/get-requests-${TIMESTAMP}.txt" | grep -m1 "mean" | awk '{print $4}') ms

3. POST Requests
   - Requests/sec: $POST_RPS

4. JSON Payloads
   - Requests/sec: $JSON_RPS

5. Large Payloads (10KB)
   - Requests/sec: $LARGE_RPS

6. Sustained Load (60s)
   - Requests/sec: $SUSTAINED_RPS

========================================
Performance Analysis
========================================

Latency Impact: $(awk "BEGIN {printf \"%.2f%%\", (($(grep "Time per request" "$OUTPUT_DIR/get-requests-${TIMESTAMP}.txt" | grep -m1 "mean" | awk '{print $4}') / $(grep "Time per request" "$OUTPUT_DIR/baseline-${TIMESTAMP}.txt" | grep -m1 "mean" | awk '{print $4}') - 1) * 100)}")

Throughput Capacity: $(grep "Requests per second" "$OUTPUT_DIR/get-requests-${TIMESTAMP}.txt" | awk '{print $4}') req/sec

========================================
Recommendations
========================================

- If latency > 50ms: Consider increasing WAF resources
- If throughput < 100 req/sec: Review rule complexity
- If failure rate > 1%: Check error logs

Full test data available in: $OUTPUT_DIR/

EOF

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Performance Testing Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
cat "$REPORT_FILE"
echo ""
echo "Detailed results saved to: $OUTPUT_DIR/"

exit 0
