# Deployment Guide

## Document Information

| Item | Details |
|------|---------|
| Document Version | 1.0 |
| Last Updated | February 2026 |
| Tested On | Ubuntu 22.04/24.04, Debian 12 |

---

## 1. Overview

This guide provides step-by-step instructions for deploying the WAF (Web Application Firewall) solution in various environments, including development, production, and high-availability configurations.

---

## 2. Prerequisites

### 2.1 System Requirements

| Component | Minimum | Recommended | High-Availability |
|-----------|---------|-------------|-------------------|
| CPU | 2 cores | 4 cores | 8+ cores |
| RAM | 4 GB | 8 GB | 16+ GB |
| Storage | 20 GB SSD | 50 GB SSD | 100+ GB SSD |
| Network | 100 Mbps | 1 Gbps | 10 Gbps |
| OS | Ubuntu 22.04+ / Debian 12+ | Ubuntu 24.04 | Ubuntu 24.04 |

### 2.2 Software Requirements

| Software | Version | Purpose |
|----------|---------|---------|
| Docker | 24.0+ | Container runtime |
| Docker Compose | 2.20+ | Container orchestration |
| Git | 2.40+ | Version control |
| curl | 7.80+ | HTTP testing |
| openssl | 3.0+ | Certificate management |

### 2.3 Network Requirements

| Port | Protocol | Purpose | Access |
|------|----------|---------|--------|
| 80 | TCP | HTTP (redirect) | Public |
| 443 | TCP | HTTPS | Public |
| 3000 | TCP | Grafana | Internal/VPN |
| 9090 | TCP | Prometheus | Internal only |
| 3100 | TCP | Loki | Internal only |

### 2.4 DNS Requirements

| Record | Type | Value | Purpose |
|--------|------|-------|---------|
| your-domain.com | A | Server IP | Main application |
| monitoring.your-domain.com | A | Server IP | Grafana dashboard |

---

## 3. Pre-Deployment Checklist

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     PRE-DEPLOYMENT CHECKLIST                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   Infrastructure                                                                │
│   □ Server provisioned with required specs                                      │
│   □ SSH access configured                                                       │
│   □ Firewall rules configured                                                   │
│   □ DNS records created                                                         │
│                                                                                  │
│   Software                                                                      │
│   □ Docker installed                                                            │
│   □ Docker Compose installed                                                    │
│   □ Git installed                                                               │
│                                                                                  │
│   Configuration                                                                 │
│   □ Domain name finalized                                                       │
│   □ Email for SSL certificates                                                  │
│   □ Backend application URL/IP                                                  │
│   □ Grafana admin password chosen                                               │
│                                                                                  │
│   Security                                                                      │
│   □ SSH keys configured                                                         │
│   □ Root login disabled                                                         │
│   □ Firewall enabled                                                            │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Quick Start Deployment

### 4.1 Clone Repository

```bash
# Clone the WAF project
git clone https://github.com/your-org/waf-lab.git
cd waf-lab
```

### 4.2 Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit configuration
nano .env
```

**Environment Variables:**
```bash
# .env file
DOMAIN=your-domain.com
MONITORING_DOMAIN=monitoring.your-domain.com
BACKEND_URL=http://your-backend:80
GRAFANA_ADMIN_PASSWORD=YourSecurePassword123!
SSL_EMAIL=admin@your-domain.com
```

### 4.3 Deploy WAF Stack

```bash
# Start WAF containers
docker compose up -d

# Verify deployment
docker compose ps
```

### 4.4 Deploy Monitoring Stack

```bash
# Start monitoring containers
docker compose -f docker-compose-monitoring.yml up -d

# Verify all services
docker ps
```

### 4.5 Obtain SSL Certificates

```bash
# Run SSL certificate script
./waf/scripts/manage-ssl.sh obtain

# Verify certificates
./waf/scripts/manage-ssl.sh verify
```

### 4.6 Verify Deployment

```bash
# Test WAF is working
curl -I https://your-domain.com

# Test monitoring access
curl -I https://monitoring.your-domain.com

# Run attack tests
./waf/scripts/test-waf-attacks.sh
```

---

## 5. Detailed Deployment Steps

### 5.1 Server Preparation

#### Install Docker

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install prerequisites
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

# Add Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Start Docker
sudo systemctl enable docker
sudo systemctl start docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify installation
docker --version
docker compose version
```

#### Configure Firewall

```bash
# Enable UFW
sudo ufw enable

# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow Grafana (internal network only)
sudo ufw allow from 10.0.0.0/8 to any port 3000

# Verify rules
sudo ufw status
```

### 5.2 Project Configuration

#### Directory Structure

```bash
# Create project directory
sudo mkdir -p /opt/waf-lab
cd /opt/waf-lab

# Clone or copy project files
git clone https://github.com/your-org/waf-lab.git .

# Set permissions
sudo chown -R $USER:$USER /opt/waf-lab
chmod -R 755 /opt/waf-lab
chmod -R 750 waf/scripts/
```

#### Configure Nginx

Edit `nginx/default.conf`:

```nginx
# Replace charles.work.gd with your domain
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL certificates (updated after obtaining)
    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    
    # Backend configuration
    location / {
        proxy_pass http://your-backend:80;
        # ... rest of proxy settings
    }
}
```

### 5.3 SSL Certificate Setup

#### Option A: Let's Encrypt (Recommended)

```bash
# Initial deployment without SSL
docker compose up -d

# Obtain certificates
docker run -it --rm \
  -v ./certs:/etc/letsencrypt \
  -p 80:80 \
  certbot/certbot certonly \
  --standalone \
  -d your-domain.com \
  -d monitoring.your-domain.com \
  --email admin@your-domain.com \
  --agree-tos \
  --non-interactive

# Restart with SSL
docker compose down
docker compose up -d
```

#### Option B: Existing Certificates

```bash
# Copy certificates
cp /path/to/your/cert.pem certs/fullchain.pem
cp /path/to/your/key.pem certs/privkey.pem

# Set permissions
chmod 644 certs/fullchain.pem
chmod 600 certs/privkey.pem
```

#### Option C: Self-Signed (Development Only)

```bash
# Generate self-signed certificates
./waf/scripts/manage-ssl.sh self-signed

# Note: Browsers will show security warnings
```

### 5.4 Start Services

```bash
# Start WAF stack
docker compose up -d

# Wait for services to initialize
sleep 30

# Check status
docker compose ps

# View logs
docker compose logs -f waf-proxy
```

### 5.5 Start Monitoring

```bash
# Start monitoring stack
docker compose -f docker-compose-monitoring.yml up -d

# Verify all containers
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Expected output:
# waf-proxy         Up 2 minutes    0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
# bwapp             Up 2 minutes    80/tcp
# grafana           Up 2 minutes    0.0.0.0:3000->3000/tcp
# prometheus        Up 2 minutes    0.0.0.0:9090->9090/tcp
# loki              Up 2 minutes    3100/tcp
# promtail          Up 2 minutes    9080/tcp
# nginx-exporter    Up 2 minutes    9113/tcp
# node-exporter     Up 2 minutes    9100/tcp
# cadvisor          Up 2 minutes    8080/tcp
```

---

## 6. Configuration Customization

### 6.1 WAF Tuning

#### Adjust Paranoia Level

Edit `waf/conf.d/crs-setup.conf`:

```apache
# Level 1: Minimal false positives
# Level 2: Balanced (recommended)
# Level 3: High security
# Level 4: Maximum security

SecAction "id:900000,phase:1,nolog,pass,\
    setvar:tx.paranoia_level=2"
```

#### Adjust Anomaly Thresholds

```apache
SecAction "id:900110,phase:1,nolog,pass,\
    setvar:tx.inbound_anomaly_score_threshold=5,\
    setvar:tx.outbound_anomaly_score_threshold=4"
```

### 6.2 Custom Rules

Create `waf/rules/RULES-BEFORE-CRS.conf`:

```apache
# Skip ModSecurity for static content
SecRule REQUEST_URI "@rx \.(css|js|png|jpg|gif|ico)$" \
    "id:10001,phase:1,pass,nolog,ctl:ruleEngine=Off"

# Skip ModSecurity for health checks
SecRule REQUEST_URI "@streq /health" \
    "id:10002,phase:1,pass,nolog,ctl:ruleEngine=Off"

# Block specific IP ranges
SecRule REMOTE_ADDR "@ipMatch 192.168.100.0/24" \
    "id:10003,phase:1,deny,status:403,msg:'Blocked IP range'"
```

### 6.3 Grafana Customization

#### Change Admin Password

```bash
# Via CLI
docker exec grafana grafana-cli admin reset-admin-password YourNewPassword123!

# Or via environment variable
# Edit docker-compose-monitoring.yml
environment:
  - GF_SECURITY_ADMIN_PASSWORD=YourNewPassword123!
```

#### Add Custom Dashboards

```bash
# Copy dashboard JSON files
cp your-dashboard.json monitoring/grafana/dashboards/

# Restart Grafana
docker compose -f docker-compose-monitoring.yml restart grafana
```

---

## 7. Environment-Specific Configurations

### 7.1 Development Environment

```yaml
# docker-compose.override.yml
version: '3.8'
services:
  waf-proxy:
    environment:
      - MODSEC_RULE_ENGINE=DetectionOnly  # Log-only mode
    ports:
      - "8080:80"   # Alternative port
      - "8443:443"  # Alternative port
```

### 7.2 Production Environment

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  waf-proxy:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
    restart: always
    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "5"
```

### 7.3 High-Availability Configuration

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    HIGH-AVAILABILITY DEPLOYMENT                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│                        ┌─────────────────────┐                                  │
│                        │   Load Balancer     │                                  │
│                        │   (HAProxy/Nginx)   │                                  │
│                        └──────────┬──────────┘                                  │
│                                   │                                              │
│              ┌────────────────────┼────────────────────┐                        │
│              │                    │                    │                        │
│              ▼                    ▼                    ▼                        │
│       ┌─────────────┐      ┌─────────────┐      ┌─────────────┐                │
│       │   WAF #1    │      │   WAF #2    │      │   WAF #3    │                │
│       │  (Active)   │      │  (Active)   │      │  (Active)   │                │
│       └──────┬──────┘      └──────┬──────┘      └──────┬──────┘                │
│              │                    │                    │                        │
│              └────────────────────┼────────────────────┘                        │
│                                   │                                              │
│                                   ▼                                              │
│                        ┌─────────────────────┐                                  │
│                        │   Backend Pool      │                                  │
│                        └─────────────────────┘                                  │
│                                                                                  │
│   Monitoring: Centralized Grafana + Prometheus with Remote Write                │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Post-Deployment Tasks

### 8.1 Verification Checklist

```bash
#!/bin/bash
# post-deployment-verify.sh

echo "=== Post-Deployment Verification ==="

# Check containers
echo -n "WAF Container: "
docker ps | grep -q waf-proxy && echo "✓ Running" || echo "✗ Not running"

# Check HTTPS
echo -n "HTTPS Access: "
curl -s -o /dev/null -w "%{http_code}" https://your-domain.com | grep -q "200\|302" && echo "✓ Working" || echo "✗ Failed"

# Check WAF blocking
echo -n "WAF Blocking: "
RESULT=$(curl -s -o /dev/null -w "%{http_code}" "https://your-domain.com/?id=1'%20OR%20'1'='1")
[ "$RESULT" == "403" ] && echo "✓ Active" || echo "✗ Not blocking"

# Check Grafana
echo -n "Grafana: "
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health | grep -q "200" && echo "✓ Healthy" || echo "✗ Not responding"

# Check Prometheus
echo -n "Prometheus: "
curl -s http://localhost:9090/-/healthy | grep -q "Healthy" && echo "✓ Healthy" || echo "✗ Not responding"

# Check SSL certificate
echo -n "SSL Certificate: "
EXPIRY=$(echo | openssl s_client -servername your-domain.com -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)
echo "✓ Expires: $EXPIRY"

echo "=== Verification Complete ==="
```

### 8.2 Backup Configuration

```bash
# Create backup script
cat > /opt/waf-lab/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR=/opt/backups/waf-$(date +%Y%m%d)
mkdir -p $BACKUP_DIR

# Backup configurations
cp -r /opt/waf-lab/nginx $BACKUP_DIR/
cp -r /opt/waf-lab/waf $BACKUP_DIR/
cp -r /opt/waf-lab/monitoring $BACKUP_DIR/
cp -r /opt/waf-lab/certs $BACKUP_DIR/
cp /opt/waf-lab/docker-compose*.yml $BACKUP_DIR/

# Compress
tar -czvf $BACKUP_DIR.tar.gz $BACKUP_DIR
rm -rf $BACKUP_DIR

echo "Backup created: $BACKUP_DIR.tar.gz"
EOF

chmod +x /opt/waf-lab/backup.sh
```

### 8.3 Set Up Cron Jobs

```bash
# SSL certificate renewal (daily check)
echo "0 3 * * * /opt/waf-lab/waf/scripts/manage-ssl.sh renew" | crontab -

# Configuration backup (weekly)
echo "0 2 * * 0 /opt/waf-lab/backup.sh" | crontab -

# Log rotation (daily)
echo "0 4 * * * docker exec waf-proxy logrotate /etc/logrotate.conf" | crontab -

# Verify cron jobs
crontab -l
```

---

## 9. Upgrading

### 9.1 Update Procedure

```bash
# Backup current configuration
./backup.sh

# Pull latest images
docker compose pull
docker compose -f docker-compose-monitoring.yml pull

# Rolling restart (zero-downtime)
docker compose up -d --force-recreate
docker compose -f docker-compose-monitoring.yml up -d --force-recreate

# Verify services
docker compose ps
./post-deployment-verify.sh
```

### 9.2 CRS Rule Updates

```bash
# Check for updates
./waf/scripts/manage-waf.sh check-updates

# Apply updates
./waf/scripts/manage-waf.sh update-rules

# Restart WAF
docker compose restart waf-proxy

# Verify
./waf/scripts/test-waf-attacks.sh
```

---

## 10. Troubleshooting

### 10.1 Common Issues

#### Container Won't Start

```bash
# Check logs
docker compose logs waf-proxy

# Common fixes:
# - Check port conflicts: netstat -tlnp | grep -E "80|443"
# - Check certificate paths
# - Verify backend is accessible
```

#### 502 Bad Gateway

```bash
# Check backend connectivity
docker exec waf-proxy curl -I http://backend:80

# Check backend container
docker compose logs backend

# Verify proxy_pass configuration
docker exec waf-proxy cat /etc/nginx/conf.d/default.conf | grep proxy_pass
```

#### SSL Certificate Errors

```bash
# Verify certificate files exist
ls -la certs/

# Test certificate validity
openssl x509 -in certs/fullchain.pem -text -noout

# Renew if expired
./waf/scripts/manage-ssl.sh renew
```

#### ModSecurity Blocking Legitimate Traffic

```bash
# Check audit log for blocked requests
docker exec waf-proxy tail -f /var/log/modsec_audit.log

# Identify rule ID and create exclusion
# Add to waf/rules/RULES-AFTER-CRS.conf:
SecRuleRemoveById 942100
```

### 10.2 Health Check Commands

```bash
# Full health check
./waf/scripts/manage-waf.sh health

# Individual checks
docker exec waf-proxy nginx -t           # Nginx config test
docker exec waf-proxy curl localhost:8080/stub_status  # Nginx metrics
curl http://localhost:9090/-/healthy     # Prometheus health
curl http://localhost:3000/api/health    # Grafana health
curl http://localhost:3100/ready         # Loki health
```

---

## 11. Uninstallation

### 11.1 Stop Services

```bash
# Stop all containers
docker compose down
docker compose -f docker-compose-monitoring.yml down
```

### 11.2 Remove Data

```bash
# Remove volumes (WARNING: deletes all data)
docker volume rm waf-lab_prometheus_data waf-lab_grafana_data waf-lab_loki_data

# Remove images
docker rmi $(docker images | grep waf-lab | awk '{print $3}')
```

### 11.3 Clean Up

```bash
# Remove project directory
sudo rm -rf /opt/waf-lab

# Remove cron jobs
crontab -r

# Remove firewall rules
sudo ufw delete allow 80/tcp
sudo ufw delete allow 443/tcp
```

---

## 12. Quick Reference

### 12.1 Essential Commands

| Task | Command |
|------|---------|
| Start WAF | `docker compose up -d` |
| Stop WAF | `docker compose down` |
| Start Monitoring | `docker compose -f docker-compose-monitoring.yml up -d` |
| View Logs | `docker compose logs -f waf-proxy` |
| Restart WAF | `docker compose restart waf-proxy` |
| Test Config | `docker exec waf-proxy nginx -t` |
| Get SSL | `./waf/scripts/manage-ssl.sh obtain` |
| Test WAF | `./waf/scripts/test-waf-attacks.sh` |

### 12.2 Important Files

| File | Purpose |
|------|---------|
| docker-compose.yml | Main WAF stack |
| docker-compose-monitoring.yml | Monitoring stack |
| nginx/default.conf | Nginx configuration |
| waf/conf.d/crs-setup.conf | CRS settings |
| certs/ | SSL certificates |

### 12.3 Access URLs

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| Application | https://your-domain.com | - |
| Grafana | https://monitoring.your-domain.com | admin / WafAdmin123! |
| Prometheus | http://localhost:9090 | - |

---

**Document End**
