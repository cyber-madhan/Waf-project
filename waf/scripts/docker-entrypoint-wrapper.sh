#!/bin/sh
# Create log directory if it doesn't exist
mkdir -p /var/log
touch /var/log/modsec_debug.log /var/log/modsec_audit.log
chmod 666 /var/log/modsec_*.log

# Execute the original entrypoint
exec /docker-entrypoint.sh "$@"
