#!/bin/bash

# SSL Certificate Management Script for WAF Lab
# Generates wildcard SSL certificate for *.project.work.gd

set -e

DOMAIN="project.work.gd"
WILDCARD_DOMAIN="*.project.work.gd"
CERT_DIR="/root/waf-lab/certs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Backup existing certificates
backup_certs() {
    if [ -f "$CERT_DIR/fullchain.pem" ] || [ -f "$CERT_DIR/privkey.pem" ]; then
        log_warning "Existing certificates found. Creating backup..."
        backup_dir="$CERT_DIR/backup-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$backup_dir"
        cp "$CERT_DIR"/*.pem "$backup_dir/" 2>/dev/null || true
        log_success "Backup created at: $backup_dir"
    fi
}

# Generate wildcard certificate using DNS challenge
generate_wildcard_cert() {
    log_info "Generating wildcard SSL certificate for $WILDCARD_DOMAIN and $DOMAIN"
    log_warning "This requires DNS verification. You'll need to add a TXT record to your DNS."
    echo ""
    
    # Stop WAF to free port 80 if needed
    log_info "Stopping WAF to free port 80..."
    docker-compose -f /root/waf-lab/docker-compose.yml down 2>/dev/null || true
    
    # Generate certificate with manual DNS challenge
    certbot certonly \
        --manual \
        --preferred-challenges dns \
        --email admin@project.work.gd \
        --agree-tos \
        --no-eff-email \
        -d "$DOMAIN" \
        -d "$WILDCARD_DOMAIN"
    
    # Copy certificates to project directory
    log_info "Copying certificates to $CERT_DIR..."
    cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem "$CERT_DIR/"
    cp /etc/letsencrypt/live/$DOMAIN/privkey.pem "$CERT_DIR/"
    chmod 644 "$CERT_DIR"/*.pem
    
    log_success "Wildcard certificate generated successfully!"
    log_info "Certificate location: $CERT_DIR"
    
    # Show certificate info
    openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -text | grep -A2 "Subject Alternative Name" || true
}

# Renew existing certificates
renew_certs() {
    log_info "Renewing SSL certificates..."
    
    # Stop services
    docker-compose -f /root/waf-lab/docker-compose.yml down 2>/dev/null || true
    docker-compose -f /root/waf-lab/docker-compose-monitoring.yml down 2>/dev/null || true
    
    # Renew
    certbot renew
    
    # Copy renewed certificates
    if [ -d "/etc/letsencrypt/live/$DOMAIN" ]; then
        cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem "$CERT_DIR/"
        cp /etc/letsencrypt/live/$DOMAIN/privkey.pem "$CERT_DIR/"
        chmod 644 "$CERT_DIR"/*.pem
        log_success "Certificates renewed and copied to $CERT_DIR"
    fi
    
    # Restart services
    log_info "Restarting services..."
    docker-compose -f /root/waf-lab/docker-compose.yml up -d
    docker-compose -f /root/waf-lab/docker-compose-monitoring.yml up -d
}

# Check certificate expiration
check_expiry() {
    log_info "Checking certificate expiration..."
    
    if [ -f "$CERT_DIR/fullchain.pem" ]; then
        openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -dates
        
        expiry_date=$(openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -enddate | cut -d= -f2)
        expiry_epoch=$(date -d "$expiry_date" +%s)
        current_epoch=$(date +%s)
        days_left=$(( ($expiry_epoch - $current_epoch) / 86400 ))
        
        if [ $days_left -lt 30 ]; then
            log_warning "Certificate expires in $days_left days. Consider renewal."
        else
            log_success "Certificate valid for $days_left more days"
        fi
    else
        log_error "No certificate found at $CERT_DIR/fullchain.pem"
    fi
}

# Show certificate info
show_cert_info() {
    log_info "Certificate Information:"
    echo ""
    
    if [ -f "$CERT_DIR/fullchain.pem" ]; then
        openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -text | grep -E "(Subject:|Issuer:|Not Before|Not After|DNS:)" | head -20
    else
        log_error "No certificate found"
    fi
}

# Usage
show_usage() {
    cat << EOF
SSL Certificate Management for WAF Lab

Usage: $0 [COMMAND]

Commands:
    generate    Generate new wildcard certificate (*.project.work.gd)
    renew       Renew existing certificates
    check       Check certificate expiration
    info        Show detailed certificate information
    backup      Backup current certificates
    help        Show this help message

Examples:
    $0 generate
    $0 check
    $0 renew

Note: Wildcard certificate generation requires DNS verification.
You'll need access to your DNS provider to add TXT records.

EOF
}

# Main
main() {
    case "${1:-help}" in
        generate)
            backup_certs
            generate_wildcard_cert
            ;;
        renew)
            renew_certs
            ;;
        check)
            check_expiry
            ;;
        info)
            show_cert_info
            ;;
        backup)
            backup_certs
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            log_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
