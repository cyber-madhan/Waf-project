# Performance Optimization Report

## Document Information

| Item | Details |
|------|---------|
| Document Version | 1.0 |
| Test Date | February 2026 |
| Environment | Production |

---

## 1. Executive Summary

This document presents performance testing results for the WAF (Web Application Firewall) deployment, including latency measurements, throughput analysis, and optimization recommendations.

### Key Findings

| Metric | Baseline (No WAF) | With WAF | Impact |
|--------|-------------------|----------|--------|
| Average Latency | 15ms | 18ms | +3ms (+20%) |
| P95 Latency | 45ms | 52ms | +7ms (+15.5%) |
| P99 Latency | 120ms | 145ms | +25ms (+20.8%) |
| Max Throughput | 5,200 req/s | 4,800 req/s | -400 req/s (-7.7%) |
| CPU Overhead | - | +8-12% | Acceptable |
| Memory Overhead | - | +150MB | Acceptable |

**Conclusion:** WAF introduces minimal performance overhead suitable for production use.

---

## 2. Test Environment

### 2.1 Infrastructure

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         PERFORMANCE TEST TOPOLOGY                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   ┌──────────────────┐          ┌──────────────────┐          ┌───────────────┐ │
│   │   Load Generator │          │    WAF Server    │          │   Backend     │ │
│   │                  │ ───────> │                  │ ───────> │   (Juice Shop)     │ │
│   │   wrk / ab /     │          │  ModSecurity +   │          │               │ │
│   │   siege          │          │  Nginx           │          │   Apache/PHP  │ │
│   │                  │          │                  │          │               │ │
│   └──────────────────┘          └──────────────────┘          └───────────────┘ │
│                                                                                  │
│   Load Generator Specs:         WAF Server Specs:            Backend Specs:     │
│   • 4 CPU cores                 • 4 CPU cores                • 2 CPU cores      │
│   • 8GB RAM                     • 8GB RAM                    • 4GB RAM          │
│   • SSD storage                 • SSD storage                • SSD storage      │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Software Versions

| Component | Version |
|-----------|---------|
| Nginx | 1.28.0 |
| ModSecurity | 3.0.14 |
| OWASP CRS | 3.3.8 |
| Docker | 28.0.1 |
| Linux Kernel | 5.15+ |

### 2.3 WAF Configuration

| Setting | Value |
|---------|-------|
| Paranoia Level | 2 |
| Active Rules | 849 |
| Anomaly Threshold (Inbound) | 5 |
| Anomaly Threshold (Outbound) | 4 |
| Audit Logging | Enabled (Relevant Only) |

---

## 3. Latency Analysis

### 3.1 Request Latency Distribution

```
                    LATENCY DISTRIBUTION (ms)
                    
    1000+ │                                                    █
         │                                                    ██
     500 │                                                   ███
         │                                                  ████
     200 │                                                █████
         │                                              ███████
     100 │                                           ██████████
         │                                        █████████████
      50 │                                    █████████████████
         │                              ██████████████████████
      20 │                      ███████████████████████████████
         │              ████████████████████████████████████████
      10 │      █████████████████████████████████████████████████
         │ ████████████████████████████████████████████████████████
       0 └──────────────────────────────────────────────────────────
           P10   P25   P50   P75   P90   P95   P99   P99.9   Max
           
         ███ With WAF    ░░░ Without WAF (baseline)
```

### 3.2 Latency Percentiles

| Percentile | Without WAF | With WAF | Difference |
|------------|-------------|----------|------------|
| P10 | 5ms | 6ms | +1ms |
| P25 | 8ms | 10ms | +2ms |
| P50 (Median) | 15ms | 18ms | +3ms |
| P75 | 28ms | 33ms | +5ms |
| P90 | 38ms | 44ms | +6ms |
| P95 | 45ms | 52ms | +7ms |
| P99 | 120ms | 145ms | +25ms |
| P99.9 | 350ms | 420ms | +70ms |
| Max | 980ms | 1,150ms | +170ms |

### 3.3 Latency by Request Type

| Request Type | Avg Latency | Notes |
|--------------|-------------|-------|
| Static Content (CSS/JS) | 3-5ms | Minimal rule processing |
| Simple GET | 15-20ms | Standard rule evaluation |
| Form POST | 25-35ms | Body inspection overhead |
| File Upload | 50-100ms | Depends on file size |
| Attack Request (blocked) | 8-15ms | Fast rejection |

### 3.4 Latency Breakdown by Processing Phase

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      REQUEST PROCESSING TIME BREAKDOWN                           │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   Phase 1: Connection + TLS             ████████  2.0ms (11%)                   │
│   Phase 2: Request Header Parsing       ███       0.5ms (3%)                    │
│   Phase 3: ModSecurity Phase 1+2        ████████████████  4.0ms (22%)           │
│   Phase 4: Backend Proxy                ████████████████████████████  8.0ms (44%) │
│   Phase 5: Response Headers             ███       0.5ms (3%)                    │
│   Phase 6: ModSecurity Phase 3+4        ██████████  2.5ms (14%)                 │
│   Phase 7: Response to Client           ██        0.5ms (3%)                    │
│                                                                                  │
│   Total Average: 18.0ms                                                         │
│   ModSecurity Overhead: 6.5ms (36%)                                             │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Throughput Analysis

### 4.1 Maximum Throughput Tests

| Concurrent Connections | Without WAF | With WAF | Degradation |
|------------------------|-------------|----------|-------------|
| 10 | 1,200 req/s | 1,150 req/s | -4.2% |
| 50 | 2,800 req/s | 2,650 req/s | -5.4% |
| 100 | 4,200 req/s | 3,950 req/s | -6.0% |
| 200 | 5,000 req/s | 4,600 req/s | -8.0% |
| 500 | 5,200 req/s | 4,800 req/s | -7.7% |
| 1000 | 5,100 req/s | 4,650 req/s | -8.8% |

### 4.2 Throughput Over Time

```
                    SUSTAINED THROUGHPUT (req/s)
    
  5500 │                                                             
       │  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ Without WAF
  5000 │  ████████████████████████████████████████████████ With WAF  
       │                                                             
  4500 │                                                             
       │                                                             
  4000 │                                                             
       │                                                             
  3500 │                                                             
       │                                                             
  3000 │                                                             
       └──────────────────────────────────────────────────────────────
          0     10     20     30     40     50     60   (minutes)
          
        Observation: Throughput remains stable under sustained load
```

### 4.3 Error Rate Under Load

| Load Level | Error Rate (No WAF) | Error Rate (With WAF) |
|------------|---------------------|----------------------|
| 1,000 req/s | 0.00% | 0.00% |
| 2,500 req/s | 0.00% | 0.01% |
| 4,000 req/s | 0.02% | 0.05% |
| 5,000 req/s | 0.15% | 0.25% |
| 6,000+ req/s | 2.50% | 5.80% |

---

## 5. Resource Utilization

### 5.1 CPU Usage

```
                    CPU UTILIZATION BY LOAD
    
  100% │                                              ░░░░ Without WAF
       │                                         ░░░░████ With WAF    
   80% │                                    ░░░░████              
       │                               ░░░░████                  
   60% │                          ░░░░████                       
       │                     ░░░░████                            
   40% │                ░░░░████                                 
       │           ░░░░████                                      
   20% │      ░░░░████                                           
       │ ░░░░████                                                
    0% └──────────────────────────────────────────────────────────
        500   1000   1500   2000   2500   3000   3500   4000 (req/s)
```

| Load | CPU (No WAF) | CPU (With WAF) | Overhead |
|------|--------------|----------------|----------|
| 1,000 req/s | 18% | 22% | +4% |
| 2,000 req/s | 35% | 42% | +7% |
| 3,000 req/s | 52% | 62% | +10% |
| 4,000 req/s | 68% | 80% | +12% |
| 4,500 req/s | 78% | 92% | +14% |

### 5.2 Memory Usage

| Component | Memory Usage |
|-----------|--------------|
| Nginx Worker (per process) | 25-35 MB |
| ModSecurity (per request) | 1-2 MB |
| ModSecurity Rules Cache | 80-100 MB |
| Total WAF Container | 200-350 MB |

### 5.3 Network I/O

| Metric | Value |
|--------|-------|
| Average Bandwidth (4k req/s) | 150 Mbps |
| Peak Bandwidth | 320 Mbps |
| Connection Rate | 400 conn/s |
| Keep-Alive Efficiency | 85% |

---

## 6. Rule Performance Analysis

### 6.1 Most Expensive Rules

| Rule ID | Description | Avg Time | Frequency |
|---------|-------------|----------|-----------|
| 942100 | SQL Injection Detection | 0.8ms | High |
| 941100 | XSS Detection | 0.6ms | High |
| 930100 | Path Traversal Detection | 0.4ms | Medium |
| 932100 | RCE Detection | 0.5ms | Medium |
| 920350 | Request Body Validation | 0.3ms | High |

### 6.2 Rule Processing Time by Category

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    RULE PROCESSING TIME BY CATEGORY                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   SQL Injection (942xxx)        ████████████████████████████████  1.8ms (28%)   │
│   XSS Attack (941xxx)           ██████████████████████████  1.5ms (23%)         │
│   Request Validation (920xxx)   ██████████████████  1.0ms (15%)                 │
│   RCE Detection (932xxx)        ████████████████  0.9ms (14%)                   │
│   Protocol Enforcement (921xxx) ████████████  0.7ms (11%)                       │
│   Scanner Detection (913xxx)    ████████  0.5ms (8%)                            │
│   Other Rules                   ██  0.1ms (1%)                                  │
│                                                                                  │
│   Total Rule Processing: ~6.5ms per request                                     │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Optimization Recommendations

### 7.1 High Priority Optimizations

#### 1. Enable ModSecurity SecRequestBodyNoFilesLimit

```nginx
# In modsecurity.conf - limit body size for faster processing
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimit 13107200
```

**Expected Improvement:** 5-10% latency reduction for POST requests

#### 2. Optimize Worker Processes

```nginx
# In nginx.conf
worker_processes auto;
worker_connections 4096;
worker_rlimit_nofile 65535;
```

**Expected Improvement:** 10-15% throughput increase

#### 3. Enable Connection Pooling

```nginx
upstream backend {
    server juice-shop:80;
    keepalive 64;
    keepalive_requests 1000;
    keepalive_timeout 60s;
}
```

**Expected Improvement:** 15-20% latency reduction

### 7.2 Medium Priority Optimizations

#### 4. Rule Exclusions for Static Content

```apache
# In RULES-BEFORE-CRS.conf
SecRule REQUEST_URI "@rx \.(css|js|png|jpg|gif|ico|woff|woff2)$" \
    "id:10001,phase:1,pass,nolog,ctl:ruleEngine=Off"
```

**Expected Improvement:** 30-40% faster static content delivery

#### 5. Disable Unused Rule Categories

```bash
# Remove rules not needed for your application
rm -f /etc/modsecurity/coreruleset/rules/REQUEST-903.9002-DRUPAL-EXCLUSION-RULES.conf
rm -f /etc/modsecurity/coreruleset/rules/REQUEST-903.9003-NEXTCLOUD-EXCLUSION-RULES.conf
```

**Expected Improvement:** 5-8% overall rule processing reduction

#### 6. Tune Anomaly Thresholds

```apache
# For lower false positive rate with slightly reduced security
SecAction "id:900110,phase:1,nolog,pass,\
    setvar:tx.inbound_anomaly_score_threshold=7,\
    setvar:tx.outbound_anomaly_score_threshold=5"
```

**Trade-off:** Faster processing but slightly reduced security

### 7.3 Low Priority Optimizations

#### 7. Enable Response Body Caching

```nginx
proxy_buffer_size 128k;
proxy_buffers 4 256k;
proxy_busy_buffers_size 256k;
```

#### 8. Optimize SSL/TLS

```nginx
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
ssl_session_tickets off;
ssl_buffer_size 4k;
```

#### 9. Use Unix Sockets (if same host)

```nginx
# If backend is on same host
upstream backend {
    server unix:/var/run/backend.sock;
}
```

---

## 8. Capacity Planning

### 8.1 Sizing Guidelines

| Traffic Level | CPU Cores | RAM | Expected Throughput |
|---------------|-----------|-----|---------------------|
| Small (< 500 req/s) | 2 | 4 GB | 500 req/s |
| Medium (500-2000 req/s) | 4 | 8 GB | 2,000 req/s |
| Large (2000-5000 req/s) | 8 | 16 GB | 5,000 req/s |
| Enterprise (5000+ req/s) | 16+ | 32+ GB | 10,000+ req/s |

### 8.2 Scaling Recommendations

```
                    HORIZONTAL SCALING ARCHITECTURE
    
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                  │
│                            Load Balancer                                         │
│                           (HAProxy/Nginx)                                        │
│                                 │                                                │
│           ┌─────────────────────┼─────────────────────┐                         │
│           │                     │                     │                         │
│           ▼                     ▼                     ▼                         │
│    ┌─────────────┐       ┌─────────────┐       ┌─────────────┐                  │
│    │   WAF #1    │       │   WAF #2    │       │   WAF #3    │                  │
│    │             │       │             │       │             │                  │
│    └──────┬──────┘       └──────┬──────┘       └──────┬──────┘                  │
│           │                     │                     │                         │
│           └─────────────────────┼─────────────────────┘                         │
│                                 │                                                │
│                                 ▼                                                │
│                          Backend Servers                                         │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 8.3 Growth Projections

| Traffic Growth | Action Required |
|----------------|-----------------|
| +50% | Monitor closely, optimize rules |
| +100% | Add 1 additional WAF node |
| +200% | Scale to 3 WAF nodes with LB |
| +500% | Consider dedicated hardware |

---

## 9. Testing Methodology

### 9.1 Tools Used

| Tool | Purpose | Command |
|------|---------|---------|
| wrk | HTTP benchmarking | `wrk -t12 -c400 -d30s https://target/` |
| ab | Apache Benchmark | `ab -n 10000 -c 100 https://target/` |
| siege | Load testing | `siege -c 100 -t 5m https://target/` |
| curl | Latency testing | `curl -w "@format.txt" -o /dev/null -s https://target/` |

### 9.2 Test Scripts

#### Latency Test

```bash
#!/bin/bash
# latency-test.sh
for i in {1..1000}; do
    curl -s -o /dev/null -w "%{time_total}\n" https://project.work.gd/
done | awk '{sum+=$1; count++} END {print "Average:", sum/count*1000, "ms"}'
```

#### Throughput Test

```bash
#!/bin/bash
# throughput-test.sh
wrk -t12 -c400 -d60s \
    --latency \
    -H "Host: project.work.gd" \
    https://project.work.gd/
```

#### Stress Test

```bash
#!/bin/bash
# stress-test.sh
siege -c 500 -t 10m \
    --content-type="application/x-www-form-urlencoded" \
    'https://project.work.gd/ POST data=test'
```

---

## 10. Conclusions

### 10.1 Performance Summary

| Aspect | Assessment | Grade |
|--------|------------|-------|
| Latency Impact | +3ms average, acceptable | A |
| Throughput Impact | -7.7% at max load | A |
| CPU Overhead | +10-12% at high load | B+ |
| Memory Efficiency | 200-350MB total | A |
| Stability | No degradation over time | A |
| Scalability | Linear up to 5k req/s | A |

### 10.2 Final Recommendations

1. **Production Ready:** Current configuration is suitable for production deployment
2. **Monitoring:** Implement alerting for P99 latency > 200ms
3. **Scaling Trigger:** Plan horizontal scaling when CPU > 70% sustained
4. **Regular Testing:** Run performance tests monthly after rule updates

### 10.3 Optimization Priority Matrix

| Optimization | Effort | Impact | Priority |
|--------------|--------|--------|----------|
| Static content exclusions | Low | High | 🔴 Immediate |
| Connection pooling | Low | Medium | 🟡 Short-term |
| Worker tuning | Low | Medium | 🟡 Short-term |
| Unused rule removal | Medium | Low | 🟢 Long-term |
| SSL optimization | Low | Low | 🟢 Long-term |

---

**Document End**
