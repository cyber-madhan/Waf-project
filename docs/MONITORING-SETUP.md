# Monitoring & Dashboard Setup Guide

## Document Information

| Item | Details |
|------|---------|
| Document Version | 1.0 |
| Last Updated | February 2026 |
| Stack | Prometheus + Grafana + Loki |

---

## 1. Overview

This document provides comprehensive instructions for the WAF monitoring stack, including setup, configuration, and usage of all monitoring components.

---

## 2. Monitoring Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           MONITORING DATA FLOW                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   ┌─────────────────┐                                                           │
│   │   WAF Proxy     │                                                           │
│   │   Container     │                                                           │
│   └────────┬────────┘                                                           │
│            │                                                                     │
│   ┌────────┴────────────────────────────────────────────────────────────┐       │
│   │                              │                                       │       │
│   ▼                              ▼                                       ▼       │
│ ┌──────────────┐    ┌──────────────────┐    ┌──────────────────────────────┐   │
│ │ stub_status  │    │   Docker Logs    │    │    ModSecurity Audit Log     │   │
│ │  (metrics)   │    │   (stdout/err)   │    │   (/var/log/modsec_audit)    │   │
│ │   :8080      │    │                  │    │                              │   │
│ └──────┬───────┘    └────────┬─────────┘    └──────────────────────────────┘   │
│        │                     │                                                   │
│        ▼                     ▼                                                   │
│ ┌──────────────┐    ┌──────────────────┐                                        │
│ │ Nginx        │    │    Promtail      │                                        │
│ │ Exporter     │    │                  │                                        │
│ │   :9113      │    │  (log shipper)   │                                        │
│ └──────┬───────┘    └────────┬─────────┘                                        │
│        │                     │                                                   │
│        │                     ▼                                                   │
│        │            ┌──────────────────┐                                        │
│        │            │      Loki        │                                        │
│        │            │  (log storage)   │                                        │
│        │            │     :3100        │                                        │
│        │            └────────┬─────────┘                                        │
│        │                     │                                                   │
│        ▼                     ▼                                                   │
│ ┌──────────────────────────────────────────────────────────────────────────┐    │
│ │                         PROMETHEUS                                        │    │
│ │                         (metrics DB)                                      │    │
│ │                            :9090                                          │    │
│ │                                                                           │    │
│ │  Scrape Targets:                                                          │    │
│ │  • nginx-exporter:9113  (WAF metrics)                                    │    │
│ │  • node-exporter:9100   (System metrics)                                 │    │
│ │  • cadvisor:8080        (Container metrics)                              │    │
│ │  • grafana:3000         (Dashboard metrics)                              │    │
│ │  • prometheus:9090      (Self-monitoring)                                │    │
│ └────────────────────────────────────┬─────────────────────────────────────┘    │
│                                      │                                           │
│                                      ▼                                           │
│                      ┌──────────────────────────────────────┐                   │
│                      │            GRAFANA                    │                   │
│                      │         (Visualization)               │                   │
│                      │             :3000                     │                   │
│                      │                                       │                   │
│                      │  Datasources:                         │                   │
│                      │  • Prometheus (metrics)              │                   │
│                      │  • Loki (logs)                       │                   │
│                      │                                       │                   │
│                      │  Dashboards:                          │                   │
│                      │  • WAF Security Dashboard            │                   │
│                      └──────────────────────────────────────┘                   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Configuration

### 3.1 Prometheus Configuration

File: `monitoring/prometheus/prometheus.yml`

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alerts.yml"

scrape_configs:
  # Self-monitoring
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  # WAF Nginx metrics
  - job_name: 'nginx-waf'
    static_configs:
      - targets: ['nginx-exporter:9113']

  # Host system metrics
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  # Container metrics
  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']

  # Grafana metrics
  - job_name: 'grafana'
    static_configs:
      - targets: ['grafana:3000']
```

### 3.2 Loki Configuration

File: `monitoring/loki/loki-config.yml`

```yaml
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

common:
  instance_addr: 127.0.0.1
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100

schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

storage_config:
  tsdb_shipper:
    active_index_directory: /loki/tsdb-index
    cache_location: /loki/tsdb-cache

limits_config:
  retention_period: 744h  # 31 days
  allow_structured_metadata: false

compactor:
  working_directory: /loki/compactor
  delete_request_store: filesystem
```

### 3.3 Promtail Configuration

File: `monitoring/promtail/promtail-config.yml`

```yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: containers
    static_configs:
      - targets:
          - localhost
        labels:
          job: containerlogs
          __path__: /var/lib/docker/containers/*/*log.json
    pipeline_stages:
      - json:
          expressions:
            log: log
            stream: stream
            container_id: attrs.container_id
      - labels:
          stream:
      - output:
          source: log
    relabel_configs:
      - source_labels: ['__path__']
        regex: '/var/lib/docker/containers/(.{12}).*'
        target_label: 'container'
```

### 3.4 Grafana Datasources

File: `monitoring/grafana/provisioning/datasources/datasources.yml`

```yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true

  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    editable: true
```

---

## 4. Dashboard Guide

### 4.1 Accessing the Dashboard

| Method | URL | Notes |
|--------|-----|-------|
| Domain | https://monitoring.project.work.gd | Production access |
| Direct IP | http://[SERVER_IP]:3000 | Development/testing |

**Credentials:**
- Username: `admin`
- Password: `WafAdmin123!`

### 4.2 Dashboard Panels

#### Top Row: Request Statistics

```
┌────────────────┬────────────────┬────────────────┬────────────────┬────────────────┐
│ Total Requests │ Success Reqs   │ Blocked Reqs   │ Request Rate   │ Status Codes   │
│                │                │                │                │                │
│     [123]      │     [115]      │      [8]       │  [0.5 req/s]   │   [PIE CHART]  │
│                │                │                │                │                │
│  (blue)        │   (green)      │  (orange/red)  │    (gauge)     │  200/302/403   │
└────────────────┴────────────────┴────────────────┴────────────────┴────────────────┘
```

| Panel | Data Source | Query |
|-------|-------------|-------|
| Total Requests | Loki | `sum(count_over_time({container="waf-proxy"} \|~ "project.work.gd" [$__range]))` |
| Success Requests | Loki | `sum(count_over_time({container="waf-proxy"} \|~ "project.work.gd" \|~ "\" (200\|301\|302\|304) " [$__range]))` |
| Blocked Requests | Loki | `sum(count_over_time({container="waf-proxy"} \|= "403 Forbidden" [$__range]))` |
| Request Rate | Prometheus | `rate(nginx_http_requests_total[$__rate_interval])` |
| HTTP Status Codes | Loki | Per-status count queries |

#### Middle Row: Request Rate Over Time

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          Request Rate Over Time                                  │
│                                                                                  │
│  2.0 │                    ╭─╮                                                   │
│      │                   ╭╯ ╰╮                                                  │
│  1.5 │                  ╭╯   ╰╮                                                 │
│      │      ╭──╮       ╭╯     ╰╮                                                │
│  1.0 │     ╭╯  ╰╮     ╭╯       ╰──╮                                             │
│      │    ╭╯    ╰─╮  ╭╯           ╰─╮                                           │
│  0.5 │───╯        ╰──╯              ╰──────────────────────                     │
│      │                                                                          │
│  0.0 └──────────────────────────────────────────────────────────────────────────│
│       14:00    14:15    14:30    14:45    15:00    15:15    15:30               │
│                                                                                  │
│       ─── Total Requests                                                        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### Log Panels: Recent Activity

```
┌──────────────────────────────────────────┬──────────────────────────────────────────┐
│       WAF Blocked Requests (Recent)       │       WAF Success Requests (Recent)       │
│                                          │                                          │
│ 2026-02-01 19:52:54 ERROR [error] 533#   │ 2026-02-01 19:50:12 GET /login.php 302   │
│ 2026-02-01 19:38:45 ERROR [error] 532#   │ 2026-02-01 19:48:33 GET /index.php 200   │
│ 2026-02-01 19:13:17 ERROR [error] 531#   │ 2026-02-01 19:45:21 GET /style.css 200   │
│ 2026-02-01 19:13:16 ERROR [error] 531#   │ 2026-02-01 19:42:10 GET /images/logo.png │
│                                          │                                          │
└──────────────────────────────────────────┴──────────────────────────────────────────┘
```

#### Bottom Row: System Metrics

```
┌─────────────────────────────┬─────────────────────────────┬─────────────────────────────┐
│      System CPU Usage        │      System Memory Usage    │       Network Traffic       │
│                             │                             │                             │
│  100% │                     │  100% │                     │  10M │    ╭──╮              │
│       │     ╭─╮             │       │ ────────────────    │      │   ╭╯  ╰╮   ── RX     │
│   50% │ ───╯ ╰───           │   50% │                     │   5M │ ──╯    ╰── ── TX     │
│       │                     │       │                     │      │                       │
│    0% └───────────────      │    0% └───────────────      │   0M └───────────────       │
└─────────────────────────────┴─────────────────────────────┴─────────────────────────────┘
```

### 4.3 Dashboard Time Controls

| Control | Location | Function |
|---------|----------|----------|
| Time Range | Top right | Select viewing period (5m, 1h, 6h, 24h, etc.) |
| Refresh | Top right | Set auto-refresh interval (5s, 10s, 30s, etc.) |
| Zoom | Click + drag | Zoom into specific time period |
| Reset | Double-click | Reset to original time range |

### 4.4 Creating Custom Panels

1. Click **"Add panel"** in dashboard
2. Select **visualization type**
3. Choose **data source** (Prometheus or Loki)
4. Write **query**
5. Configure **display options**
6. **Save** dashboard

**Example: Custom Blocked Attacks Panel**

```
Data Source: Loki
Query: {container="waf-proxy"} |= "ModSecurity" |= "Attack"
Visualization: Logs
Title: ModSecurity Attack Detections
```

---

## 5. Alerting Configuration

### 5.1 Prometheus Alerts

File: `monitoring/prometheus/alerts.yml`

```yaml
groups:
  - name: waf_alerts
    rules:
      # High blocked request rate
      - alert: HighBlockedRequestRate
        expr: sum(rate(nginx_http_requests_total{status="403"}[5m])) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High rate of blocked requests"
          description: "More than 10 requests/sec being blocked for 2+ minutes"

      # WAF service down
      - alert: WAFServiceDown
        expr: up{job="nginx-waf"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "WAF service is down"
          description: "WAF nginx-exporter is not responding"

      # High error rate
      - alert: HighErrorRate
        expr: sum(rate(nginx_http_requests_total{status=~"5.."}[5m])) / sum(rate(nginx_http_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High 5xx error rate"
          description: "More than 5% of requests returning 5xx errors"

      # High CPU usage
      - alert: HighCPUUsage
        expr: 100 - (avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage above 80% for 5+ minutes"

      # High memory usage
      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage above 85% for 5+ minutes"

      # Disk space low
      - alert: LowDiskSpace
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100 < 15
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space"
          description: "Less than 15% disk space remaining"
```

### 5.2 Viewing Alerts

1. Access Prometheus: http://localhost:9090
2. Navigate to **Alerts** tab
3. View **Pending** and **Firing** alerts

### 5.3 Grafana Alert Notifications

Configure in Grafana UI:
1. Go to **Alerting** > **Contact points**
2. Add notification channel (Email, Slack, PagerDuty, etc.)
3. Configure **Notification policies**

---

## 6. Log Analysis

### 6.1 Loki Query Language (LogQL)

**Basic Queries:**

```logql
# All WAF logs
{container="waf-proxy"}

# Filter by domain
{container="waf-proxy"} |~ "project.work.gd"

# Only blocked requests
{container="waf-proxy"} |= "403 Forbidden"

# ModSecurity denials
{container="waf-proxy"} |= "ModSecurity" |= "denied"

# SQL injection attempts
{container="waf-proxy"} |= "SQL Injection"

# XSS attempts
{container="waf-proxy"} |= "XSS"

# Exclude health checks
{container="waf-proxy"} != "/stub_status"
```

**Aggregation Queries:**

```logql
# Count requests per minute
sum(count_over_time({container="waf-proxy"}[1m]))

# Blocked requests over time
sum(count_over_time({container="waf-proxy"} |= "403" [5m]))

# Top attacking IPs (requires parsing)
topk(10, sum by (remote_addr) (count_over_time({container="waf-proxy"} |= "403" [1h])))
```

### 6.2 Grafana Explore

1. Click **Explore** in left menu
2. Select **Loki** data source
3. Enter LogQL query
4. View logs with syntax highlighting

### 6.3 Log Retention

| Component | Retention | Storage |
|-----------|-----------|---------|
| Loki | 31 days | ~20GB |
| Prometheus | 30 days | ~10GB |
| ModSecurity Audit | 7 days | ~5GB |

---

## 7. Metrics Reference

### 7.1 Nginx Metrics (nginx-exporter)

| Metric | Type | Description |
|--------|------|-------------|
| `nginx_http_requests_total` | Counter | Total HTTP requests |
| `nginx_connections_active` | Gauge | Current active connections |
| `nginx_connections_accepted` | Counter | Total accepted connections |
| `nginx_connections_handled` | Counter | Total handled connections |
| `nginx_connections_reading` | Gauge | Connections reading request |
| `nginx_connections_writing` | Gauge | Connections writing response |
| `nginx_connections_waiting` | Gauge | Idle connections |

### 7.2 Node Metrics (node-exporter)

| Metric | Type | Description |
|--------|------|-------------|
| `node_cpu_seconds_total` | Counter | CPU time by mode |
| `node_memory_MemTotal_bytes` | Gauge | Total memory |
| `node_memory_MemAvailable_bytes` | Gauge | Available memory |
| `node_filesystem_size_bytes` | Gauge | Filesystem size |
| `node_filesystem_avail_bytes` | Gauge | Available disk space |
| `node_network_receive_bytes_total` | Counter | Network bytes received |
| `node_network_transmit_bytes_total` | Counter | Network bytes transmitted |

### 7.3 Container Metrics (cAdvisor)

| Metric | Type | Description |
|--------|------|-------------|
| `container_cpu_usage_seconds_total` | Counter | Container CPU usage |
| `container_memory_usage_bytes` | Gauge | Container memory usage |
| `container_network_receive_bytes_total` | Counter | Container network RX |
| `container_network_transmit_bytes_total` | Counter | Container network TX |

---

## 8. Troubleshooting

### 8.1 Common Issues

#### Dashboard Shows "No Data"

```bash
# Check Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'

# Check Loki is receiving logs
curl -s http://localhost:3100/ready

# Check Promtail is shipping logs
docker logs promtail --tail 20
```

#### Grafana Login Failed

```bash
# Reset admin password
docker exec grafana grafana-cli admin reset-admin-password NewPassword123!

# Check Grafana logs
docker logs grafana --tail 50
```

#### Metrics Missing

```bash
# Verify nginx-exporter is scraping
curl http://localhost:9113/metrics | head -20

# Check stub_status is accessible
docker exec waf-proxy curl http://localhost:8080/stub_status
```

### 8.2 Health Checks

```bash
# Check all monitoring containers
docker ps | grep -E "prometheus|grafana|loki|promtail|exporter|cadvisor"

# Check Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[].health'

# Check Loki ready
curl http://localhost:3100/ready

# Check Grafana health
curl http://localhost:3000/api/health
```

### 8.3 Log Locations

| Service | Log Access |
|---------|------------|
| Prometheus | `docker logs prometheus` |
| Grafana | `docker logs grafana` |
| Loki | `docker logs loki` |
| Promtail | `docker logs promtail` |

---

## 9. Maintenance

### 9.1 Backup Procedures

```bash
# Backup Grafana dashboards
docker exec grafana grafana-cli plugins backup

# Backup Prometheus data
docker exec prometheus promtool tsdb snapshot /prometheus

# Backup configuration files
tar -czvf monitoring-backup-$(date +%Y%m%d).tar.gz monitoring/
```

### 9.2 Cleanup Procedures

```bash
# Clean old Prometheus data (handled by retention)
# Check disk usage
docker exec prometheus df -h /prometheus

# Clean Loki chunks (handled by retention)
docker exec loki du -sh /loki/chunks

# Prune unused Docker resources
docker system prune -f
```

### 9.3 Update Procedures

```bash
# Pull latest images
docker compose -f docker-compose-monitoring.yml pull

# Rolling restart
docker compose -f docker-compose-monitoring.yml up -d

# Verify all healthy
docker ps | grep -E "prometheus|grafana|loki"
```

---

## 10. Quick Reference

### 10.1 Access URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | https://monitoring.project.work.gd | admin / WafAdmin123! |
| Prometheus | http://localhost:9090 | None |
| Loki | http://localhost:3100 | None |

### 10.2 Common Commands

```bash
# Start monitoring stack
docker compose -f docker-compose-monitoring.yml up -d

# Stop monitoring stack
docker compose -f docker-compose-monitoring.yml down

# View logs
docker compose -f docker-compose-monitoring.yml logs -f

# Restart specific service
docker compose -f docker-compose-monitoring.yml restart grafana

# Check status
./waf/scripts/manage-monitoring.sh status
```

### 10.3 Useful PromQL Queries

```promql
# Request rate
rate(nginx_http_requests_total[5m])

# CPU usage percentage
100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# Memory usage percentage
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100

# Disk usage percentage
(1 - (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"})) * 100

# Network throughput
rate(node_network_receive_bytes_total[5m]) + rate(node_network_transmit_bytes_total[5m])
```

---

**Document End**
