#!/bin/sh
set -e
if [ -n "$SMTP_HOST" ] && [ -n "$SMTP_USERNAME" ] && [ -n "$SMTP_PASSWORD" ]; then
    cat > /etc/msmtprc <<EOF
# Auto-generated msmtp configuration
defaults
logfile /var/log/msmtp.log
account default
host ${SMTP_HOST}
port ${SMTP_PORT:-587}
from ${SMTP_FROM_ADDRESS:-$SMTP_USERNAME}
user ${SMTP_USERNAME}
password ${SMTP_PASSWORD}
auth on
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile /var/log/msmtp.log

# Set a default account
account default : default
EOF
    chmod 600 /etc/msmtprc
    chown www-data:www-data /etc/msmtprc
    echo "msmtp configuration generated successfully"
else
    echo "smtp  configuration not set, skipping msmtp setup"
fi
exec "$@"
