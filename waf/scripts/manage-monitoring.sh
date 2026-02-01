#!/bin/bash

# WAF Monitoring Stack - Setup and Management Script
# Author: Charles WAF Lab
# Date: January 31, 2026

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if monitoring stack is running
check_monitoring_status() {
    log_info "Checking monitoring stack status..."
    
    services=("prometheus" "grafana" "loki" "promtail" "nginx-exporter" "node-exporter" "cadvisor")
    
    for service in "${services[@]}"; do
        if docker ps | grep -q "$service"; then
            log_success "$service is running"
        else
            log_warning "$service is not running"
        fi
    done
}

# Start monitoring stack
start_monitoring() {
    log_info "Starting monitoring stack..."
    cd "$PROJECT_ROOT"
    docker-compose -f docker-compose-monitoring.yml up -d
    
    log_info "Waiting for services to be healthy..."
    sleep 10
    
    check_monitoring_status
    
    log_success "Monitoring stack started!"
    log_info "Access points:"
    log_info "  - Grafana: https://monitoring.charles.work.gd (admin/WafAdmin123!)"
    log_info "  - Prometheus: http://localhost:9090"
    log_info "  - Loki: http://localhost:3100"
}

# Stop monitoring stack
stop_monitoring() {
    log_info "Stopping monitoring stack..."
    cd "$PROJECT_ROOT"
    docker-compose -f docker-compose-monitoring.yml down
    log_success "Monitoring stack stopped"
}

# Restart monitoring stack
restart_monitoring() {
    log_info "Restarting monitoring stack..."
    stop_monitoring
    sleep 2
    start_monitoring
}

# View logs
view_logs() {
    local service=$1
    if [ -z "$service" ]; then
        log_error "Please specify a service: prometheus, grafana, loki, promtail, nginx-exporter"
        return 1
    fi
    
    log_info "Showing logs for $service..."
    docker logs -f "$service"
}

# Show metrics
show_metrics() {
    log_info "Fetching current metrics..."
    
    echo ""
    log_info "=== WAF Request Rate ==="
    curl -s 'http://localhost:9090/api/v1/query?query=rate(nginx_http_requests_total[5m])' | \
        python3 -m json.tool 2>/dev/null || echo "Prometheus not ready"
    
    echo ""
    log_info "=== Blocked Requests ==="
    curl -s 'http://localhost:9090/api/v1/query?query=rate(nginx_http_requests_total{status="403"}[5m])' | \
        python3 -m json.tool 2>/dev/null || echo "Prometheus not ready"
}

# Test monitoring endpoints
test_endpoints() {
    log_info "Testing monitoring endpoints..."
    
    endpoints=(
        "http://localhost:9090/-/healthy|Prometheus"
        "http://localhost:3000/api/health|Grafana"
        "http://localhost:3100/ready|Loki"
        "http://localhost:9113/metrics|Nginx Exporter"
        "http://localhost:9100/metrics|Node Exporter"
        "http://localhost:8080/metrics|cAdvisor"
    )
    
    for endpoint_info in "${endpoints[@]}"; do
        IFS='|' read -r url name <<< "$endpoint_info"
        if curl -sf "$url" > /dev/null 2>&1; then
            log_success "$name is healthy"
        else
            log_error "$name is not responding"
        fi
    done
}

# Backup configuration
backup_config() {
    log_info "Creating backup of monitoring configuration..."
    backup_dir="$PROJECT_ROOT/monitoring-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    
    cp -r "$PROJECT_ROOT/monitoring" "$backup_dir/"
    cp "$PROJECT_ROOT/docker-compose-monitoring.yml" "$backup_dir/"
    
    log_success "Backup created at: $backup_dir"
}

# Show usage
show_usage() {
    cat << EOF
WAF Monitoring Stack Management Script

Usage: $0 [COMMAND]

Commands:
    start           Start monitoring stack
    stop            Stop monitoring stack
    restart         Restart monitoring stack
    status          Check status of all monitoring services
    logs [SERVICE]  View logs for a specific service
    metrics         Show current metrics from Prometheus
    test            Test all monitoring endpoints
    backup          Backup monitoring configuration
    help            Show this help message

Examples:
    $0 start
    $0 logs grafana
    $0 test

EOF
}

# Main execution
main() {
    case "${1:-help}" in
        start)
            start_monitoring
            ;;
        stop)
            stop_monitoring
            ;;
        restart)
            restart_monitoring
            ;;
        status)
            check_monitoring_status
            ;;
        logs)
            view_logs "$2"
            ;;
        metrics)
            show_metrics
            ;;
        test)
            test_endpoints
            ;;
        backup)
            backup_config
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
