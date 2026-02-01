# WAF Security Implementation Project

[![ModSecurity](https://img.shields.io/badge/ModSecurity-3.0.14-green)](https://github.com/SpiderLabs/ModSecurity)
[![OWASP CRS](https://img.shields.io/badge/OWASP%20CRS-3.3.8-blue)](https://coreruleset.org/)
[![Nginx](https://img.shields.io/badge/Nginx-1.28.0-brightgreen)](https://nginx.org/)
[![License](https://img.shields.io/badge/License-Open%20Source-orange)]()

A comprehensive Web Application Firewall (WAF) implementation using ModSecurity with OWASP Core Rule Set, featuring real-time monitoring, logging, and security analytics.

## 🏗️ Architecture Overview

```
                                    ┌─────────────────────────────────────────────────────────────┐
                                    │                     MONITORING STACK                        │
                                    │  ┌───────────┐  ┌──────┐  ┌─────────┐  ┌──────────────────┐ │
                                    │  │ Prometheus│  │ Loki │  │ Grafana │  │ Node/cAdvisor    │ │
                                    │  │  :9090    │  │:3100 │  │  :3000  │  │ Exporters        │ │
                                    │  └─────┬─────┘  └──┬───┘  └────┬────┘  └────────┬─────────┘ │
                                    │        │          │           │                │           │
                                    │        └──────────┴─────┬─────┴────────────────┘           │
                                    │                         │                                   │
                                    └─────────────────────────┼───────────────────────────────────┘
                                                              │
                                                              │ Metrics/Logs
                                                              ▼
┌─────────────┐     HTTPS (443)     ┌─────────────────────────────────────────────────────────────┐
│             │ ──────────────────► │                      WAF PROXY (Nginx + ModSecurity)        │
│   Internet  │                     │  ┌─────────────────────────────────────────────────────────┐│
│   Clients   │ ◄────────────────── │  │  ModSecurity 3.0.14 + OWASP CRS 3.3.8 (849 Rules)      ││
│             │     Response        │  │  • SQL Injection Protection                             ││
└─────────────┘                     │  │  • XSS Protection                                       ││
                                    │  │  • LFI/RFI Protection                                   ││
                                    │  │  • RCE Protection                                       ││
                                    │  │  • Anomaly Scoring (Inbound: 5, Outbound: 4)           ││
                                    │  │  • Paranoia Level 2                                     ││
                                    │  └─────────────────────────────────────────────────────────┘│
                                    │                           │                                  │
                                    │               ┌───────────┴───────────┐                     │
                                    │               ▼                       ▼                     │
                                    │    ┌─────────────────────┐  ┌─────────────────────┐        │
                                    │    │  charles.work.gd    │  │monitoring.charles.  │        │
                                    │    │      → bWAPP        │  │  work.gd → Grafana  │        │
                                    │    └─────────────────────┘  └─────────────────────┘        │
                                    └─────────────────────────────────────────────────────────────┘
                                                              │
                                                              ▼
                                    ┌─────────────────────────────────────────────────────────────┐
                                    │                     BACKEND APPLICATION                     │
                                    │                                                             │
                                    │                    bWAPP (Vulnerable App)                   │
                                    │                         :80                                 │
                                    │                                                             │
                                    └─────────────────────────────────────────────────────────────┘
```

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [Monitoring](#-monitoring)
- [Security Rules](#-security-rules)
- [Testing](#-testing)
- [Management Scripts](#-management-scripts)
- [Documentation](#-documentation)
- [Troubleshooting](#-troubleshooting)

## ✨ Features

### Security
- **ModSecurity 3.0.14** - Industry-standard open-source WAF engine
- **OWASP CRS 3.3.8** - Comprehensive rule set with 849 security rules
- **Multi-layer Protection**:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Local/Remote File Inclusion (LFI/RFI)
  - Remote Code Execution (RCE)
  - CSRF Protection
  - Protocol Enforcement
- **Anomaly Scoring Mode** - Reduces false positives
- **Paranoia Level 2** - Balanced security/performance

### Monitoring & Analytics
- **Grafana** - Real-time security dashboards
- **Prometheus** - Metrics collection and alerting
- **Loki** - Centralized log aggregation
- **Promtail** - Log shipping from containers
- **Custom Dashboard** with:
  - Request counters (Total/Success/Blocked)
  - HTTP Status Code distribution
  - WAF blocked request logs
  - System metrics (CPU/Memory/Network)

### Infrastructure
- **Docker-based Deployment** - Portable and reproducible
- **Let's Encrypt SSL** - Automated certificate management
- **Multi-domain Support** - WAF and monitoring on separate subdomains
- **High Availability Ready** - Containerized architecture

## 🚀 Quick Start

### Prerequisites
- Docker Engine 20.10+
- Docker Compose v2+
- Domain name with DNS configured
- Ports 80, 443 available

### 1. Clone and Configure

```bash
cd /root/waf-lab

# Review and update environment variables
cp .env.example .env
nano .env
```

### 2. Start WAF Stack

```bash
# Start the main WAF stack
docker compose up -d

# Verify WAF is running
docker ps | grep waf-proxy
```

### 3. Start Monitoring Stack

```bash
# Start monitoring services
docker compose -f docker-compose-monitoring.yml up -d

# Verify all services
docker ps
```

### 4. Generate SSL Certificates

```bash
# Generate Let's Encrypt certificates
./waf/scripts/manage-ssl.sh generate
```

### 5. Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| Protected App | https://charles.work.gd | N/A |
| Grafana Dashboard | https://monitoring.charles.work.gd | admin / WafAdmin123! |
| Prometheus | http://localhost:9090 | N/A |

## 📁 Project Structure

```
waf-lab/
├── docker-compose.yml              # Main WAF stack
├── docker-compose-monitoring.yml   # Monitoring stack
├── README.md                       # This file
├── QUICKSTART.md                   # Quick reference guide
│
├── nginx/
│   ├── default.conf                # Nginx configuration
│   └── default.conf.template       # Template with env vars
│
├── waf/
│   ├── logs/                       # WAF audit logs
│   ├── rules/                      # Custom ModSecurity rules
│   │   └── monitoring-exclusions.conf
│   └── scripts/
│       ├── docker-entrypoint-wrapper.sh
│       ├── manage-ssl.sh           # SSL certificate management
│       ├── manage-monitoring.sh    # Monitoring control
│       ├── test-waf-attacks.sh     # Attack testing
│       ├── validate-config.sh      # Config validation
│       └── performance-test.sh     # Performance testing
│
├── certs/
│   ├── fullchain.pem               # SSL certificate
│   └── privkey.pem                 # SSL private key
│
├── monitoring/
│   ├── prometheus/
│   │   ├── prometheus.yml          # Prometheus config
│   │   └── alerts.yml              # Alert rules
│   ├── grafana/
│   │   ├── provisioning/
│   │   │   └── datasources/
│   │   └── dashboards/
│   │       └── waf-security-dashboard.json
│   ├── loki/
│   │   └── loki-config.yml
│   └── promtail/
│       └── promtail-config.yml
│
└── docs/                           # Documentation
    ├── ARCHITECTURE.md
    ├── SECURITY-RULES.md
    ├── MONITORING-SETUP.md
    ├── PERFORMANCE-REPORT.md
    ├── AUTHENTICATION-RBAC.md
    ├── COMPLIANCE-CHECKLIST.md
    ├── DEPLOYMENT-GUIDE.md
    └── TRAINING-MATERIALS.md
```

## ⚙️ Configuration

### ModSecurity Settings

| Setting | Value | Description |
|---------|-------|-------------|
| SecRuleEngine | On | Rules are active and blocking |
| Paranoia Level | 2 | Balanced security (1-4 scale) |
| Inbound Threshold | 5 | Anomaly score to trigger block |
| Outbound Threshold | 4 | Response anomaly threshold |
| Audit Log | Enabled | Full transaction logging |

### Nginx Configuration

The WAF proxy handles two domains:
- `charles.work.gd` → Backend application (bWAPP)
- `monitoring.charles.work.gd` → Grafana dashboard

See [nginx/default.conf](nginx/default.conf) for full configuration.

## 📊 Monitoring

### Grafana Dashboard

Access: https://monitoring.charles.work.gd

**Dashboard Panels:**
- Total Requests - All requests to the WAF
- Success Requests - HTTP 2xx/3xx responses
- Blocked Requests - HTTP 403 (WAF blocks)
- HTTP Status Codes - Distribution pie chart
- Request Rate - Real-time req/s gauge
- WAF Blocked Logs - Recent attack attempts
- WAF Success Logs - Legitimate traffic
- System Metrics - CPU, Memory, Network

### Prometheus Targets

| Target | Endpoint | Metrics |
|--------|----------|---------|
| prometheus | :9090 | Self-monitoring |
| nginx-waf | :8080 | Request counts |
| node-exporter | :9100 | System metrics |
| cadvisor | :8080 | Container metrics |
| grafana | :3000 | Dashboard metrics |

### Alerting Rules

Pre-configured alerts in `monitoring/prometheus/alerts.yml`:
- High blocked request rate
- WAF service down
- High error rate
- Resource exhaustion

## 🛡️ Security Rules

### OWASP CRS Coverage

| Category | Rule Files | Description |
|----------|------------|-------------|
| 901-910 | Initialization | CRS setup and variables |
| 911-913 | Method Enforcement | HTTP method validation |
| 920 | Protocol Enforcement | HTTP protocol compliance |
| 930 | LFI | Local file inclusion |
| 931 | RFI | Remote file inclusion |
| 932 | RCE | Remote code execution |
| 933 | PHP Injection | PHP-specific attacks |
| 934 | Node.js Injection | Node.js attacks |
| 941 | XSS | Cross-site scripting |
| 942 | SQLi | SQL injection |
| 943 | Session Fixation | Session attacks |
| 944 | Java Attacks | Java-specific vulnerabilities |

### Custom Rules

Add custom rules to `waf/rules/`:

```apache
# Example: Block specific user agent
SecRule REQUEST_HEADERS:User-Agent "@contains BadBot" \
    "id:100001,phase:1,deny,status:403,msg:'Bad bot blocked'"
```

## 🧪 Testing

### Test Attack Protection

```bash
# Run automated attack tests
./waf/scripts/test-waf-attacks.sh

# Manual tests
# SQL Injection
curl -k "https://charles.work.gd/test?id=1' OR '1'='1"

# XSS
curl -k "https://charles.work.gd/test?q=<script>alert(1)</script>"

# LFI
curl -k "https://charles.work.gd/test?file=../../../etc/passwd"

# RCE
curl -k "https://charles.work.gd/test?cmd=;cat /etc/passwd"
```

Expected: All attacks return HTTP 403

### Performance Testing

```bash
# Run performance benchmarks
./waf/scripts/performance-test.sh
```

## 🔧 Management Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `manage-ssl.sh` | SSL certificate management | `./manage-ssl.sh [generate\|renew\|status]` |
| `manage-monitoring.sh` | Monitoring stack control | `./manage-monitoring.sh [start\|stop\|status]` |
| `test-waf-attacks.sh` | Security testing | `./test-waf-attacks.sh` |
| `validate-config.sh` | Configuration validation | `./validate-config.sh` |
| `performance-test.sh` | Performance benchmarks | `./performance-test.sh` |

## 📚 Documentation

Detailed documentation available in the `docs/` folder:

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture and design |
| [SECURITY-RULES.md](docs/SECURITY-RULES.md) | Security rule configuration |
| [MONITORING-SETUP.md](docs/MONITORING-SETUP.md) | Monitoring stack setup |
| [PERFORMANCE-REPORT.md](docs/PERFORMANCE-REPORT.md) | Performance optimization |
| [AUTHENTICATION-RBAC.md](docs/AUTHENTICATION-RBAC.md) | Access control setup |
| [COMPLIANCE-CHECKLIST.md](docs/COMPLIANCE-CHECKLIST.md) | OWASP/PCI DSS compliance |
| [DEPLOYMENT-GUIDE.md](docs/DEPLOYMENT-GUIDE.md) | Installation instructions |
| [TRAINING-MATERIALS.md](docs/TRAINING-MATERIALS.md) | Administrator training |

## 🔍 Troubleshooting

### Common Issues

**WAF container restarting:**
```bash
# Check logs
docker logs waf-proxy

# Verify log file permissions
docker exec waf-proxy ls -la /var/log/
```

**403 errors on legitimate traffic:**
```bash
# Check ModSecurity audit log
docker exec waf-proxy tail -f /var/log/modsec_audit.log

# Reduce paranoia level if needed
# Edit: waf/rules/crs-setup-custom.conf
```

**Grafana dashboard not loading:**
```bash
# Check Grafana logs
docker logs grafana

# Verify network connectivity
docker network ls
```

### Log Locations

| Log | Location | Purpose |
|-----|----------|---------|
| Nginx Access | `docker logs waf-proxy` | Request logs |
| ModSecurity Audit | `/var/log/modsec_audit.log` | Security events |
| Grafana | `docker logs grafana` | Dashboard logs |
| Prometheus | `docker logs prometheus` | Metrics logs |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project uses open-source software:
- ModSecurity: Apache 2.0 License
- OWASP CRS: Apache 2.0 License
- Nginx: BSD License
- Grafana: AGPL 3.0 License
- Prometheus: Apache 2.0 License

## 📞 Support

For issues and questions:
1. Check [Troubleshooting](#-troubleshooting) section
2. Review documentation in `docs/`
3. Check container logs
4. Open an issue with detailed information
