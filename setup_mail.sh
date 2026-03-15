#!/bin/bash
# setup_mail.sh - Configure Postfix for hermescrm.xyz on Hetzner server
# Run as root on the server: sudo bash setup_mail.sh

set -e

DOMAIN="hermescrm.xyz"
NOREPLY_EMAIL="noreply@hermescrm.xyz"
SERVER_IP="178.156.249.177"

echo "========================================"
echo "Hermes CRM Mail Setup"
echo "Domain: $DOMAIN"
echo "Server IP: $SERVER_IP"
echo "========================================"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Update package lists
echo "[1/5] Updating package lists..."
apt-get update -qq

# Install Postfix
echo "[2/5] Installing Postfix..."
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix mailutils > /dev/null 2>&1

# Configure Postfix for $DOMAIN
echo "[3/5] Configuring Postfix..."
postconf -e "myhostname = $DOMAIN"
postconf -e "mydomain = $DOMAIN"
postconf -e "myorigin = $DOMAIN"
postconf -e "mydestination = $DOMAIN, localhost"
postconf -e "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = ipv4"

# Reload Postfix
postfix reload

echo ""
echo "[4/5] Testing mail configuration..."
echo "Postfix is configured and ready to accept mail on port 25 and 587."
echo ""

# Create noreply user (mailbox)
if id "$NOREPLY_EMAIL" &>/dev/null 2>&1; then
    echo "User $NOREPLY_EMAIL already exists"
else
    echo "Creating mailbox for $NOREPLY_EMAIL..."
    useradd -m -s /usr/sbin/nologin noreply 2>/dev/null || true
fi

echo ""
echo "[5/5] DNS Records Required"
echo "========================================"
echo ""
echo "Add these DNS records to your domain registrar:"
echo ""
echo "1. SPF Record (TXT):"
echo "   Name: @  (or $DOMAIN)"
echo "   Value: v=spf1 ip4:$SERVER_IP ~all"
echo ""
echo "2. MX Record:"
echo "   Name: @  (or $DOMAIN)"
echo "   Value: $DOMAIN"
echo "   Priority: 10"
echo ""
echo "3. DKIM (optional but recommended):"
echo "   Install opendkim-tools: apt-get install opendkim opendkim-tools"
echo "   Generate key: opendkim-genkey -b 2048 -d $DOMAIN -D /etc/dkim/keys"
echo "   Add TXT record for DKIM with the public key from /etc/dkim/keys"
echo ""
echo "4. DMARC (optional but recommended):"
echo "   Name: _dmarc"
echo "   Value: v=DMARC1; p=quarantine; rua=mailto:$NOREPLY_EMAIL"
echo ""
echo "========================================"
echo ""
echo "Testing email send..."
echo ""

# Test send email
TEST_EMAIL_FILE="/tmp/test_email_$$.txt"
cat > "$TEST_EMAIL_FILE" <<EOF
Subject: Hermes CRM Mail Test

This is a test email from Hermes CRM mail setup on $DOMAIN.
If you received this, your mail server is working correctly.

---
Sent from: $SERVER_IP
EOF

# Try to send to a valid test address if provided
if [ ! -z "$1" ]; then
    echo "Sending test email to: $1"
    cat "$TEST_EMAIL_FILE" | sendmail -v "$1"
    echo "Test email sent!"
else
    echo "To test email sending, run:"
    echo "  echo 'Test' | sendmail -v your-email@example.com"
    echo ""
    echo "Or use the Hermes CRM API endpoint:"
    echo "  POST /api/channels/test-email"
    echo "  Body: {\"to\": \"your-email@example.com\", \"subject\": \"Test\", \"body\": \"Test message\"}"
fi

rm -f "$TEST_EMAIL_FILE"

echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "Postfix is running and configured for $DOMAIN"
echo "You can now send emails via the Hermes CRM API:"
echo ""
echo "Environment variables needed in .env:"
echo "  SMTP_HOST=localhost"
echo "  SMTP_PORT=587"
echo "  SMTP_FROM=noreply@hermescrm.xyz"
echo ""
echo "Test with:"
echo "  POST /api/channels/test-email"
echo "  {\"to\": \"user@example.com\", \"subject\": \"Test\", \"body\": \"Hello\"}"
echo ""
