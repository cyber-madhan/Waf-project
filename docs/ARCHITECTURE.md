# WAF Architecture & Deployment Plan

## Document Information

| Item | Details |
|------|---------|
| Document Version | 1.0 |
| Last Updated | February 2026 |
| Author | WAF Implementation Team |
| Classification | Internal |

---

## 1. Executive Summary

This document outlines the architecture and deployment plan for the Web Application Firewall (WAF) implementation protecting web applications against common security threats. The solution uses ModSecurity 3.0 with OWASP Core Rule Set deployed on Nginx, with comprehensive monitoring via Prometheus, Grafana, and Loki.

---

## 2. Architecture Overview

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                    INTERNET                                          │
│                                                                                       │
│                              ┌──────────────────┐                                    │
│                              │   DNS Provider   │                                    │
│                              │                  │                                    │
│                              │ project.work.gd  │                                    │
│                              │ monitoring.*     │                                    │
│                              └────────┬─────────┘                                    │
│                                       │                                              │
└───────────────────────────────────────┼──────────────────────────────────────────────┘
                                        │
                                        ▼ Port 443 (HTTPS)
┌───────────────────────────────────────────────────────────────────────────────────────┐
│                                 HOST SERVER                                            │
│                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              DOCKER ENGINE                                        │ │
│  │                                                                                   │ │
│  │  ┌─────────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                         WAF NETWORK (waf-net)                                │ │ │
│  │  │                                                                              │ │ │
│  │  │   ┌───────────────────────────────────────────────────────────────────────┐ │ │ │
│  │  │   │                    WAF-PROXY CONTAINER                                │ │ │ │
│  │  │   │  ┌─────────────────────────────────────────────────────────────────┐  │ │ │ │
│  │  │   │  │                      NGINX 1.28.0                               │  │ │ │ │
│  │  │   │  │                                                                 │  │ │ │ │
│  │  │   │  │  ┌─────────────────────────────────────────────────────────┐   │  │ │ │ │
│  │  │   │  │  │              ModSecurity 3.0.14                         │   │  │ │ │ │
│  │  │   │  │  │                                                         │   │  │ │ │ │
│  │  │   │  │  │  ┌─────────────────────────────────────────────────┐   │   │  │ │ │ │
│  │  │   │  │  │  │          OWASP CRS 3.3.8 (849 Rules)            │   │   │  │ │ │ │
│  │  │   │  │  │  │  • SQL Injection Rules (942xxx)                 │   │   │  │ │ │ │
│  │  │   │  │  │  │  • XSS Rules (941xxx)                           │   │   │  │ │ │ │
│  │  │   │  │  │  │  • LFI/RFI Rules (930xxx, 931xxx)              │   │   │  │ │ │ │
│  │  │   │  │  │  │  • RCE Rules (932xxx)                           │   │   │  │ │ │ │
│  │  │   │  │  │  │  • Protocol Enforcement (920xxx)                │   │   │  │ │ │ │
│  │  │   │  │  │  └─────────────────────────────────────────────────┘   │   │  │ │ │ │
│  │  │   │  │  └─────────────────────────────────────────────────────────┘   │  │ │ │ │
│  │  │   │  └─────────────────────────────────────────────────────────────────┘  │ │ │ │
│  │  │   │                           │                    │                       │ │ │ │
│  │  │   │               Ports: 80, 443, 8080                                    │ │ │ │
│  │  │   └───────────────────────────┼────────────────────┼───────────────────────┘ │ │ │
│  │  │                               │                    │                          │ │ │
│  │  │                   ┌───────────┘                    └───────────┐              │ │ │
│  │  │                   ▼                                            ▼              │ │ │
│  │  │   ┌─────────────────────────────┐          ┌─────────────────────────────┐   │ │ │
│  │  │   │      Juice Shop CONTAINER        │          │      GRAFANA CONTAINER      │   │ │ │
│  │  │   │                             │          │                             │   │ │ │
│  │  │   │   Vulnerable Web App        │          │   Monitoring Dashboard      │   │ │ │
│  │  │   │   (Apache + PHP + MySQL)    │          │   Port: 3000                │   │ │ │
│  │  │   │   Port: 80                  │          │                             │   │ │ │
│  │  │   └─────────────────────────────┘          └─────────────────────────────┘   │ │ │
│  │  │                                                                               │ │ │
│  │  └───────────────────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                                     │ │
│  │  ┌───────────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                    MONITORING NETWORK (monitoring-net)                         │ │ │
│  │  │                                                                                │ │ │
│  │  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────┐│ │ │
│  │  │  │ Prometheus │  │    Loki    │  │  Promtail  │  │  cAdvisor  │  │  Node    ││ │ │
│  │  │  │   :9090    │  │   :3100    │  │            │  │   :8080    │  │ Exporter ││ │ │
│  │  │  │            │  │            │  │            │  │            │  │  :9100   ││ │ │
│  │  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘  └──────────┘│ │ │
│  │  │                                                                                │ │ │
│  │  └────────────────────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                                      │ │
│  └──────────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                            │
│  Storage Volumes:                                                                          │
│  ├── /root/waf-lab/certs        → SSL Certificates                                        │
│  ├── /root/waf-lab/waf/logs     → ModSecurity Audit Logs                                  │
│  ├── prometheus-data            → Metrics Storage (30 days)                               │
│  ├── grafana-data               → Dashboard Configurations                                │
│  └── loki-data                  → Log Storage (31 days)                                   │
│                                                                                            │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Network Architecture

```
                    ┌─────────────────────────────────────────┐
                    │            EXTERNAL NETWORK             │
                    │                                         │
                    │  Source: Any (0.0.0.0/0)               │
                    │  Destination: Server Public IP          │
                    │  Ports: 80 (HTTP), 443 (HTTPS)         │
                    │                                         │
                    └─────────────────┬───────────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────────┐
                    │          HOST NETWORK INTERFACE         │
                    │                                         │
                    │  Public IP: [Server IP]                 │
                    │  Bound Ports: 80, 443                   │
                    │                                         │
                    └─────────────────┬───────────────────────┘
                                      │
                    ┌─────────────────┼───────────────────────┐
                    │                 │                       │
                    │    DOCKER BRIDGE NETWORKS               │
                    │                 │                       │
        ┌───────────┴──────────┐     │     ┌─────────────────┴─────────────────┐
        │                      │     │     │                                   │
        ▼                      │     │     ▼                                   │
┌───────────────────┐         │     │     ┌────────────────────────────────────┐
│    waf-net        │         │     │     │         monitoring-net             │
│  172.24.0.0/16    │         │     │     │         172.25.0.0/16              │
│                   │         │     │     │                                    │
│  ┌─────────────┐  │         │     │     │  ┌────────────┐  ┌──────────────┐ │
│  │  waf-proxy  │◄─┼─────────┘     │     │  │ prometheus │  │    loki      │ │
│  │ 172.24.0.10 │  │               │     │  │172.25.0.10 │  │ 172.25.0.11  │ │
│  └──────┬──────┘  │               │     │  └────────────┘  └──────────────┘ │
│         │         │               │     │                                    │
│         ▼         │               │     │  ┌────────────┐  ┌──────────────┐ │
│  ┌─────────────┐  │               │     │  │  promtail  │  │   grafana    │ │
│  │    juice-shop    │  │               │     │  │172.25.0.12 │  │ 172.25.0.13  │ │
│  │ 172.24.0.20 │  │               │     │  └────────────┘  └──────────────┘ │
│  └─────────────┘  │               │     │                                    │
│                   │               │     │  ┌────────────┐  ┌──────────────┐ │
└───────────────────┘               │     │  │  cadvisor  │  │node-exporter │ │
                                    │     │  │172.25.0.14 │  │ 172.25.0.15  │ │
                            Connected│     │  └────────────┘  └──────────────┘ │
                                    │     │                                    │
                                    └─────┤  ┌────────────┐                   │
                                          │  │nginx-export│                   │
                                          │  │172.25.0.16 │                   │
                                          │  └────────────┘                   │
                                          └────────────────────────────────────┘
```

### 2.3 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              REQUEST FLOW (Legitimate Traffic)                           │
└─────────────────────────────────────────────────────────────────────────────────────────┘

     ┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐
     │  Client  │      │   TLS    │      │  Nginx   │      │ModSecurity│     │  Backend │
     │ Browser  │      │Termination│     │  Proxy   │      │   WAF     │     │  Juice Shop   │
     └────┬─────┘      └────┬─────┘      └────┬─────┘      └────┬─────┘     └────┬─────┘
          │                 │                 │                 │                │
          │ 1. HTTPS Request│                 │                 │                │
          │────────────────►│                 │                 │                │
          │                 │                 │                 │                │
          │                 │ 2. Decrypt TLS  │                 │                │
          │                 │────────────────►│                 │                │
          │                 │                 │                 │                │
          │                 │                 │ 3. ModSecurity  │                │
          │                 │                 │    Phase 1-2    │                │
          │                 │                 │────────────────►│                │
          │                 │                 │                 │                │
          │                 │                 │                 │ 4. Anomaly     │
          │                 │                 │                 │    Score: 0    │
          │                 │                 │◄────────────────│ (PASS)         │
          │                 │                 │                 │                │
          │                 │                 │ 5. Proxy Request│                │
          │                 │                 │─────────────────┼───────────────►│
          │                 │                 │                 │                │
          │                 │                 │ 6. Response     │                │
          │                 │                 │◄────────────────┼────────────────│
          │                 │                 │                 │                │
          │                 │                 │ 7. ModSecurity  │                │
          │                 │                 │    Phase 3-4    │                │
          │                 │                 │────────────────►│                │
          │                 │                 │                 │                │
          │                 │                 │◄────────────────│ 8. PASS        │
          │                 │                 │                 │                │
          │                 │ 9. Encrypt TLS  │                 │                │
          │◄────────────────│                 │                 │                │
          │                 │                 │                 │                │
          │ 10. HTTPS Response               │                 │                │
          │ (200 OK)        │                 │                 │                │
          │                 │                 │                 │                │
     └────┴─────┘      └────┴─────┘      └────┴─────┘      └────┴─────┘     └────┴─────┘


┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              REQUEST FLOW (Attack Blocked)                               │
└─────────────────────────────────────────────────────────────────────────────────────────┘

     ┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐
     │ Attacker │      │   TLS    │      │  Nginx   │      │ModSecurity│     │  Backend │
     │          │      │Termination│     │  Proxy   │      │   WAF     │     │  Juice Shop   │
     └────┬─────┘      └────┬─────┘      └────┬─────┘      └────┬─────┘     └────┬─────┘
          │                 │                 │                 │                │
          │ 1. HTTPS Request│                 │                 │                │
          │  ?id=1' OR '1=1│                 │                 │                │
          │────────────────►│                 │                 │                │
          │                 │                 │                 │                │
          │                 │ 2. Decrypt TLS  │                 │                │
          │                 │────────────────►│                 │                │
          │                 │                 │                 │                │
          │                 │                 │ 3. ModSecurity  │                │
          │                 │                 │    Phase 1-2    │                │
          │                 │                 │────────────────►│                │
          │                 │                 │                 │                │
          │                 │                 │                 │ 4. SQL Injection│
          │                 │                 │                 │    Detected!   │
          │                 │                 │                 │    Score: 25   │
          │                 │                 │                 │    Threshold: 5│
          │                 │                 │◄────────────────│                │
          │                 │                 │  5. BLOCK       │                │
          │                 │                 │                 │                │
          │                 │                 │ 6. Log Attack   │                │
          │                 │                 │    to Audit Log │                │
          │                 │                 │────────────────►│                │
          │                 │                 │                 │                │
          │                 │ 7. Return 403   │                 │    X           │
          │◄────────────────│    Forbidden    │                 │    │           │
          │                 │                 │                 │    │           │
          │ 8. 403 Forbidden│                 │                 │    │           │
          │                 │                 │                 │    │ Request   │
          │                 │                 │                 │    │ Never     │
          │                 │                 │                 │    │ Reaches   │
          │                 │                 │                 │    │ Backend   │
          │                 │                 │                 │    ▼           │
     └────┴─────┘      └────┴─────┘      └────┴─────┘      └────┴─────┘     └────┴─────┘
```

---

## 3. Component Specifications

### 3.1 WAF Proxy Container

| Specification | Details |
|---------------|---------|
| Base Image | owasp/modsecurity-crs:nginx-alpine |
| Nginx Version | 1.28.0 |
| ModSecurity Version | 3.0.14 |
| OWASP CRS Version | 3.3.8 |
| Total Rules | 849 |
| Memory Limit | 512MB (recommended) |
| CPU Limit | 1 core (recommended) |

### 3.2 Monitoring Stack

| Component | Version | Purpose | Port |
|-----------|---------|---------|------|
| Prometheus | Latest | Metrics collection | 9090 |
| Grafana | 12.3.2 | Visualization | 3000 |
| Loki | Latest | Log aggregation | 3100 |
| Promtail | Latest | Log shipping | N/A |
| Node Exporter | Latest | System metrics | 9100 |
| cAdvisor | Latest | Container metrics | 8080 |
| Nginx Exporter | Latest | WAF metrics | 9113 |

### 3.3 Storage Requirements

| Volume | Size | Retention | Purpose |
|--------|------|-----------|---------|
| prometheus-data | ~10GB | 30 days | Time-series metrics |
| grafana-data | ~1GB | Permanent | Dashboard configs |
| loki-data | ~20GB | 31 days | Log storage |
| waf/logs | ~5GB | 7 days | Audit logs |
| certs | ~10KB | Until expiry | SSL certificates |

---

## 4. Deployment Environments

### 4.1 Development Environment

```
┌─────────────────────────────────────────────────────────────┐
│                    DEVELOPMENT SETUP                         │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                   Developer Machine                     │ │
│  │                                                         │ │
│  │   Docker Desktop / Docker Engine                        │ │
│  │   ├── waf-proxy container                              │ │
│  │   ├── juice-shop container                                  │ │
│  │   └── monitoring stack (optional)                      │ │
│  │                                                         │ │
│  │   Access: http://localhost                              │ │
│  │   Self-signed certificates                              │ │
│  │                                                         │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  Characteristics:                                            │
│  • Single machine deployment                                 │
│  • Self-signed SSL certificates                             │
│  • Paranoia Level 1 (reduced false positives)               │
│  • No external access required                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Production Environment (Current)

```
┌─────────────────────────────────────────────────────────────┐
│                    PRODUCTION SETUP                          │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                 Cloud VPS / Dedicated Server            │ │
│  │                                                         │ │
│  │   Public IP: [Assigned by provider]                     │ │
│  │   Domain: project.work.gd                               │ │
│  │   Monitoring: monitoring.project.work.gd                │ │
│  │                                                         │ │
│  │   Docker Engine                                          │ │
│  │   ├── WAF Stack (docker-compose.yml)                    │ │
│  │   └── Monitoring Stack (docker-compose-monitoring.yml)  │ │
│  │                                                         │ │
│  │   Let's Encrypt SSL certificates                        │ │
│  │   Paranoia Level 2                                       │ │
│  │                                                         │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  Characteristics:                                            │
│  • Single server deployment                                  │
│  • Valid SSL from Let's Encrypt                             │
│  • Paranoia Level 2 (balanced)                              │
│  • Public internet access                                    │
│  • Full monitoring enabled                                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 4.3 High Availability Environment (Future)

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           HIGH AVAILABILITY SETUP                                    │
│                                                                                      │
│   ┌─────────────────┐                                                               │
│   │  Load Balancer  │   (AWS ALB / Nginx / HAProxy)                                │
│   │   (External)    │                                                               │
│   └────────┬────────┘                                                               │
│            │                                                                         │
│   ┌────────┴────────────────────────────────────────────────────────────────────┐  │
│   │                                                                              │  │
│   ▼                            ▼                            ▼                    │  │
│  ┌────────────────┐   ┌────────────────┐   ┌────────────────┐                   │  │
│  │   WAF Node 1   │   │   WAF Node 2   │   │   WAF Node 3   │                   │  │
│  │   (Active)     │   │   (Active)     │   │   (Active)     │                   │  │
│  │                │   │                │   │                │                   │  │
│  │ waf-proxy      │   │ waf-proxy      │   │ waf-proxy      │                   │  │
│  │ + juice-shop        │   │ + juice-shop        │   │ + juice-shop        │                   │  │
│  └───────┬────────┘   └───────┬────────┘   └───────┬────────┘                   │  │
│          │                    │                    │                             │  │
│          └────────────────────┼────────────────────┘                             │  │
│                               │                                                   │  │
│                               ▼                                                   │  │
│                    ┌─────────────────────┐                                       │  │
│                    │   Shared Database   │   (If required by backend)            │  │
│                    │   (MySQL Cluster)   │                                       │  │
│                    └─────────────────────┘                                       │  │
│                                                                                   │  │
│   Centralized Monitoring:                                                         │  │
│   ┌───────────────────────────────────────────────────────────────────────────┐  │  │
│   │  Prometheus (Federated) │ Grafana │ Loki │ Central Logging                │  │  │
│   └───────────────────────────────────────────────────────────────────────────┘  │  │
│                                                                                   │  │
└───────────────────────────────────────────────────────────────────────────────────┘  │
                                                                                       │
│  Characteristics:                                                                    │
│  • Multi-node deployment (3+ nodes recommended)                                     │
│  • External load balancer                                                           │
│  • Shared configuration management                                                  │
│  • Centralized logging and monitoring                                               │
│  • Auto-scaling capable                                                             │
│  • Zero-downtime deployments                                                        │
│                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Security Architecture

### 5.1 Defense in Depth Layers

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                                                                  │
│   Layer 1: Network Security                                                      │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │  • Firewall rules (iptables/cloud security groups)                       │  │
│   │  • Rate limiting at network level                                        │  │
│   │  • DDoS protection (if cloud-based)                                      │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                           │                                      │
│                                           ▼                                      │
│   Layer 2: TLS/SSL Encryption                                                    │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │  • TLS 1.2/1.3 only                                                      │  │
│   │  • Strong cipher suites                                                  │  │
│   │  • Let's Encrypt certificates (auto-renewed)                             │  │
│   │  • HSTS enabled (1 year)                                                 │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                           │                                      │
│                                           ▼                                      │
│   Layer 3: Web Application Firewall (WAF)                                        │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │  • ModSecurity 3.0.14 with OWASP CRS 3.3.8                               │  │
│   │  • SQL Injection protection                                              │  │
│   │  • XSS protection                                                        │  │
│   │  • LFI/RFI protection                                                    │  │
│   │  • RCE protection                                                        │  │
│   │  • Protocol enforcement                                                  │  │
│   │  • Anomaly scoring with configurable thresholds                          │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                           │                                      │
│                                           ▼                                      │
│   Layer 4: Application Security Headers                                          │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │  • Strict-Transport-Security (HSTS)                                      │  │
│   │  • X-Frame-Options: SAMEORIGIN                                           │  │
│   │  • X-Content-Type-Options: nosniff                                       │  │
│   │  • X-XSS-Protection: 1; mode=block                                       │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                           │                                      │
│                                           ▼                                      │
│   Layer 5: Application Layer                                                     │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │  • Backend application security                                          │  │
│   │  • Input validation                                                      │  │
│   │  • Output encoding                                                       │  │
│   │  • Session management                                                    │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 ModSecurity Rule Processing

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        MODSECURITY PROCESSING PHASES                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   PHASE 1: REQUEST HEADERS                                                       │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │  Triggered: After request headers received                               │  │
│   │  Inspects:  Method, URI, Protocol, Headers, Cookies                      │  │
│   │  Rules:     Protocol enforcement, Method validation, Header checks       │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                           │                                      │
│                                           ▼                                      │
│   PHASE 2: REQUEST BODY                                                          │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │  Triggered: After request body received                                  │  │
│   │  Inspects:  POST data, JSON, XML, File uploads                           │  │
│   │  Rules:     SQLi, XSS, Command injection, File upload validation         │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                           │                                      │
│                        [Request forwarded to backend if allowed]                 │
│                                           │                                      │
│                                           ▼                                      │
│   PHASE 3: RESPONSE HEADERS                                                      │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │  Triggered: After response headers received from backend                 │  │
│   │  Inspects:  Status code, Response headers                                │  │
│   │  Rules:     Information leakage detection                                │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                           │                                      │
│                                           ▼                                      │
│   PHASE 4: RESPONSE BODY                                                         │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │  Triggered: After response body received from backend                    │  │
│   │  Inspects:  HTML content, Error messages, Sensitive data                 │  │
│   │  Rules:     Data leakage prevention, Error message filtering             │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                           │                                      │
│                                           ▼                                      │
│   PHASE 5: LOGGING                                                               │
│   ┌──────────────────────────────────────────────────────────────────────────┐  │
│   │  Triggered: After transaction complete                                   │  │
│   │  Actions:   Audit logging, Alert generation, Metrics update              │  │
│   └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Deployment Procedures

### 6.1 Initial Deployment Checklist

```
□ Server Provisioning
  □ Provision server with 2+ CPU, 4GB+ RAM
  □ Install Docker Engine and Docker Compose
  □ Configure firewall (ports 80, 443)
  □ Set up DNS records (A record for domain)

□ SSL Certificate Setup
  □ Verify domain DNS propagation
  □ Run certbot for Let's Encrypt
  □ Configure certificate auto-renewal

□ WAF Deployment
  □ Clone/copy project files to server
  □ Configure environment variables
  □ Start WAF stack with docker compose
  □ Verify WAF container is healthy
  □ Test attack blocking functionality

□ Monitoring Deployment
  □ Start monitoring stack
  □ Verify all containers running
  □ Access Grafana dashboard
  □ Confirm metrics collection
  □ Verify log aggregation working

□ Post-Deployment Verification
  □ Run automated security tests
  □ Check dashboard panels showing data
  □ Verify alerts are configured
  □ Document any customizations
```

### 6.2 Update Procedures

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            WAF UPDATE PROCEDURE                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  1. PREPARATION                                                                  │
│     □ Backup current configuration                                              │
│     □ Review release notes for breaking changes                                 │
│     □ Test updates in development environment                                   │
│     □ Schedule maintenance window                                               │
│                                                                                  │
│  2. BACKUP                                                                       │
│     $ cp -r /root/waf-lab /root/waf-lab.backup.$(date +%Y%m%d)                 │
│     $ docker compose -f docker-compose.yml -f docker-compose-monitoring.yml \   │
│       exec prometheus promtool tsdb snapshot /prometheus/snapshots              │
│                                                                                  │
│  3. PULL NEW IMAGES                                                              │
│     $ docker compose pull                                                        │
│     $ docker compose -f docker-compose-monitoring.yml pull                      │
│                                                                                  │
│  4. APPLY UPDATES (Zero-downtime approach)                                       │
│     $ docker compose up -d --no-deps waf-proxy                                  │
│     # Wait for health check                                                      │
│     $ docker compose ps                                                          │
│                                                                                  │
│  5. VERIFY                                                                       │
│     $ ./waf/scripts/test-waf-attacks.sh                                         │
│     $ curl -k https://project.work.gd/                                          │
│                                                                                  │
│  6. ROLLBACK (if needed)                                                         │
│     $ docker compose down                                                        │
│     $ cp -r /root/waf-lab.backup.* /root/waf-lab                               │
│     $ docker compose up -d                                                       │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Capacity Planning

### 7.1 Resource Estimation

| Traffic Level | Requests/sec | WAF CPU | WAF RAM | Storage/day |
|---------------|--------------|---------|---------|-------------|
| Low | < 10 | 0.5 core | 256MB | 100MB |
| Medium | 10-100 | 1 core | 512MB | 500MB |
| High | 100-1000 | 2 cores | 1GB | 2GB |
| Very High | > 1000 | 4+ cores | 2GB+ | 5GB+ |

### 7.2 Scaling Guidelines

| Metric | Threshold | Action |
|--------|-----------|--------|
| CPU > 80% sustained | 5 minutes | Add WAF instance |
| Memory > 85% | Immediate | Increase RAM or add instance |
| Response time > 500ms | 5 minutes | Review rules, add resources |
| Request queue > 100 | Immediate | Add WAF instance |

---

## 8. Disaster Recovery

### 8.1 Recovery Time Objectives

| Scenario | RTO | RPO | Recovery Procedure |
|----------|-----|-----|-------------------|
| Container crash | < 1 min | 0 | Auto-restart via Docker |
| Server reboot | < 5 min | 0 | Docker auto-start |
| Configuration error | < 15 min | 24h | Restore from backup |
| Complete server failure | < 1 hour | 24h | Deploy to new server |

### 8.2 Backup Strategy

```
Daily Backups:
├── Configuration files (docker-compose, nginx, rules)
├── Grafana dashboards
├── Prometheus data (optional, can be regenerated)
└── SSL certificates

Weekly Backups:
└── Complete project directory snapshot

Backup Retention:
├── Daily: 7 days
├── Weekly: 4 weeks
└── Monthly: 12 months
```

---

## Appendix A: Container Specifications

```yaml
# WAF Proxy Container
waf-proxy:
  image: owasp/modsecurity-crs:nginx-alpine
  resources:
    limits:
      cpus: '1'
      memory: 512M
    reservations:
      cpus: '0.5'
      memory: 256M
  ports:
    - "80:80"
    - "443:443"
  healthcheck:
    test: ["CMD", "nginx", "-t"]
    interval: 30s
    timeout: 10s
    retries: 3
```

## Appendix B: Network Port Reference

| Port | Protocol | Service | Direction | Purpose |
|------|----------|---------|-----------|---------|
| 80 | TCP | HTTP | Inbound | Redirect to HTTPS |
| 443 | TCP | HTTPS | Inbound | Main application access |
| 3000 | TCP | Grafana | Internal | Dashboard (via proxy) |
| 3100 | TCP | Loki | Internal | Log aggregation |
| 8080 | TCP | Metrics | Internal | Nginx stub_status |
| 9090 | TCP | Prometheus | Internal | Metrics collection |
| 9100 | TCP | Node Exporter | Internal | System metrics |
| 9113 | TCP | Nginx Exporter | Internal | WAF metrics |

---

**Document End**
