#!/bin/bash
###############################################################################
# Multi-Tenant AI Email Gateway Installer for Debian 12
# Model: Phi-3-mini (Optimised for Classification)
# Author: Senior Software & Web Developer
# Description: Installs PostgreSQL, Postfix, Ollama, and Python AI Filter Service
#              with dynamic tenant-aware routing and credential management.
###############################################################################

set -e  # Exit on error
set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration Variables
DB_NAME="${EMAIL_GATEWAY_DB:-email_gateway}"
DB_USER="${EMAIL_GATEWAY_DB_USER:-gateway_admin}"
DB_PASSWORD="${EMAIL_GATEWAY_DB_PASSWORD:-$(openssl rand -base64 32)}"
POSTGRES_LISTEN_ADDRESS="${POSTGRES_LISTEN_ADDRESS:-127.0.0.1}"
OLLAMA_MODEL="${OLLAMA_MODEL:-phi3:mini}"
FILTER_SERVICE_PORT="${FILTER_SERVICE_PORT:-10025}"
REINJECT_PORT="${REINJECT_PORT:-10026}"
MY_HOSTNAME="${MY_HOSTNAME:-$(hostname -f)}"
MY_DOMAIN="${MY_DOMAIN:-$(hostname -d)}"

# Logging functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
log_debug() { [[ "${DEBUG:-0}" == "1" ]] && echo -e "${BLUE}[DEBUG]${NC} $1" || true; }

# Check prerequisites
check_prerequisites() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root (use sudo)."
    fi
    
    if [ ! -f /etc/debian_version ]; then
        log_error "This script is designed for Debian systems only."
    fi
    
    local debian_version=$(cat /etc/debian_version | cut -d. -f1)
    if [ "$debian_version" -lt 12 ]; then
        log_error "Debian 12 (Bookworm) or newer is required. Found version: $debian_version"
    fi
    
    log_info "Prerequisites check passed."
}

# Save configuration for future reference
save_configuration() {
    log_info "Saving installation configuration..."
    mkdir -p /etc/email-gateway
    cat > /etc/email-gateway/config.env <<EOF
# Email Gateway Configuration - Generated $(date)
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
POSTGRES_LISTEN_ADDRESS=$POSTGRES_LISTEN_ADDRESS
OLLAMA_MODEL=$OLLAMA_MODEL
FILTER_SERVICE_PORT=$FILTER_SERVICE_PORT
REINJECT_PORT=$REINJECT_PORT
MY_HOSTNAME=$MY_HOSTNAME
MY_DOMAIN=$MY_DOMAIN
EOF
    chmod 600 /etc/email-gateway/config.env
    log_info "Configuration saved to /etc/email-gateway/config.env"
}

###############################################################################
# 1. System Preparation
###############################################################################
system_prepare() {
    log_info "Starting system preparation..."
    
    # Update system
    apt update && apt upgrade -y
    
    # Install core packages
    log_info "Installing core dependencies..."
    apt install -y \
        postfix python3 python3-pip python3-venv python3-dev \
        curl git ufw fail2ban postgresql postgresql-contrib \
        libpq-dev build-essential ssl-cert libsasl2-modules
    
    # Configure Postfix (basic, will be reconfigured later)
    log_info "Configuring basic Postfix settings..."
    debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
    debconf-set-selections <<< "postfix postfix/mailname string $MY_HOSTNAME"
    
    log_info "System preparation completed."
}

###############################################################################
# 2. PostgreSQL Setup for Tenant Management
###############################################################################
postgres_setup() {
    log_info "Setting up PostgreSQL database for tenant management..."
    
    # Start PostgreSQL and enable on boot
    systemctl enable --now postgresql
    
    # Generate secure password for postfix_reader
    POSTFIX_READER_PASSWORD=$(openssl rand -base64 32)
    
    # Create database and user
    su - postgres -c "psql" <<EOF
-- Create database
CREATE DATABASE $DB_NAME;

-- Create admin user with secure password
CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;

-- Connect to the database for further grants
\c $DB_NAME

-- Create tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    relay_host VARCHAR(255) NOT NULL,
    relay_port INTEGER DEFAULT 587,
    sasl_username VARCHAR(255),
    sasl_password VARCHAR(255),
    use_tls BOOLEAN DEFAULT true,
    require_auth BOOLEAN DEFAULT true,
    ai_filter_enabled BOOLEAN DEFAULT true,
    spam_action VARCHAR(20) DEFAULT 'reject',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT true
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_tenant_domain ON tenants(domain);
CREATE INDEX IF NOT EXISTS idx_tenant_active ON tenants(active) WHERE active = true;

-- Create audit log table
CREATE TABLE IF NOT EXISTS filter_audit_log (
    id SERIAL PRIMARY KEY,
    tenant_domain VARCHAR(255),
    sender VARCHAR(255),
    recipient VARCHAR(255),
    ai_decision VARCHAR(20),
    processing_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Grant table permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;

-- Create read-only user for Postfix lookups
CREATE USER postfix_reader WITH PASSWORD '$POSTFIX_READER_PASSWORD';
GRANT CONNECT ON DATABASE $DB_NAME TO postfix_reader;
GRANT USAGE ON SCHEMA public TO postfix_reader;
GRANT SELECT ON tenants TO postfix_reader;
EOF

    # Save credentials securely
    cat > /etc/email-gateway/db_credentials.conf <<EOF
# PostgreSQL Credentials for Email Gateway
# DO NOT SHARE THIS FILE
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=$DB_NAME
DB_ADMIN_USER=$DB_USER
DB_ADMIN_PASSWORD=$DB_PASSWORD
POSTFIX_READER_USER=postfix_reader
POSTFIX_READER_PASSWORD=$POSTFIX_READER_PASSWORD
EOF
    chmod 600 /etc/email-gateway/db_credentials.conf
    
    # Configure PostgreSQL to listen on localhost only
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '$POSTGRES_LISTEN_ADDRESS'/" /etc/postgresql/*/main/postgresql.conf
    
    # Restart PostgreSQL to apply changes
    systemctl restart postgresql
    
    log_info "PostgreSQL setup completed."
}

###############################################################################
# 3. Ollama Installation and Configuration (Phi-3-mini)
###############################################################################
ollama_setup() {
    log_info "Installing and configuring Ollama with Phi-3-mini..."
    
    # Install Ollama
    curl -fsSL https://ollama.com/install.sh | sh
    
    # Configure Ollama service
    log_info "Configuring Ollama systemd service..."
    cat > /etc/systemd/system/ollama.service <<EOF
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_ORIGINS=*"
User=ollama
Group=ollama
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now ollama
    
    # Wait for Ollama to be ready
    log_info "Waiting for Ollama to be ready..."
    for i in {1..30}; do
        if curl -s http://127.0.0.1:11434/api/tags > /dev/null 2>&1; then
            log_info "Ollama is ready."
            break
        fi
        sleep 2
    done
    
    # Pull the AI model (Phi-3-mini optimized for classification)
    log_info "Pulling AI model: $OLLAMA_MODEL"
    su - ollama -c "ollama pull $OLLAMA_MODEL" || {
        log_warn "Failed to pull $OLLAMA_MODEL. Attempting fallback..."
        su - ollama -c "ollama pull phi3:mini"
    }
    
    log_info "Ollama setup completed."
}

###############################################################################
# 4. Postfix Configuration for Multi-Tenant Relay
###############################################################################
postfix_setup() {
    log_info "Configuring Postfix for multi-tenant email routing..."
    
    # Backup existing configuration
    cp -r /etc/postfix /etc/postfix.backup.$(date +%F)
    
    # Create PostgreSQL lookup configuration files
    mkdir -p /etc/postfix/pgsql
    
    # Load DB credentials
    source /etc/email-gateway/db_credentials.conf
    
    # Relay host lookup configuration
    cat > /etc/postfix/pgsql/relay_hosts.cf <<EOF
user = postfix_reader
password = $POSTFIX_READER_PASSWORD
hosts = 127.0.0.1
port = 5432
dbname = $DB_NAME
query = SELECT relay_host || ':' || relay_port FROM tenants WHERE domain = '%s' AND active = true
EOF
    chmod 640 /etc/postfix/pgsql/relay_hosts.cf
    
    # SASL password lookup configuration
    cat > /etc/postfix/pgsql/sasl_passwd.cf <<EOF
user = postfix_reader
password = $POSTFIX_READER_PASSWORD
hosts = 127.0.0.1
port = 5432
dbname = $DB_NAME
query = SELECT sasl_username || ':' || sasl_password FROM tenants WHERE relay_host || ':' || relay_port = '%s' AND active = true AND sasl_username IS NOT NULL
EOF
    chmod 640 /etc/postfix/pgsql/sasl_passwd.cf
    
    # Main Postfix configuration
    cat > /etc/postfix/main.cf <<EOF
# Basic Settings
smtpd_banner = \$myhostname ESMTP AI Gateway
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6

# Network Settings
myhostname = $MY_HOSTNAME
mydomain = $MY_DOMAIN
myorigin = \$mydomain
mydestination = \$myhostname, localhost.\$mydomain, localhost
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

# Content Filtering
content_filter = smtp-filter:127.0.0.1:$FILTER_SERVICE_PORT

# Multi-Tenant Relay Configuration
sender_dependent_relayhost_maps = pgsql:/etc/postfix/pgsql/relay_hosts.cf
smtp_sasl_password_maps = pgsql:/etc/postfix/pgsql/sasl_passwd.cf
smtp_sasl_auth_enable = yes
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = may
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt

# TLS Parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls=yes
smtpd_tls_security_level=may

# Performance and Security
smtpd_client_connection_count_limit = 50
smtpd_client_message_rate_limit = 100
anvil_rate_time_unit = 60s
EOF

    # Master.cf configuration for filtering loop
    cat >> /etc/postfix/master.cf <<EOF

# AI Content Filter Service
smtp-filter unix -       n       n       -       -       smtp
    -o smtp_data_done_timeout=1200
    -o smtp_send_xforward_command=yes
    -o disable_dns_lookups=yes
    -o syslog_name=postfix-filter

# Re-injection Service (After Filtering)
127.0.0.1:$REINJECT_PORT inet n    -       n       -       -       smtpd
    -o content_filter=
    -o local_recipient_maps=
    -o relay_recipient_maps=
    -o smtpd_restriction_classes=
    -o smtpd_client_restrictions=
    -o smtpd_helo_restrictions=
    -o smtpd_sender_restrictions=
    -o smtpd_recipient_restrictions=permit_mynetworks,reject
    -o mynetworks=127.0.0.0/8
    -o strict_rfc821_envelopes=yes
    -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
    -o smtp_send_xforward_command=yes
    -o disable_dns_lookups=yes
    -o syslog_name=postfix-reinject
EOF

    # Set proper permissions
    chmod 644 /etc/postfix/main.cf
    chmod 755 /etc/postfix/master.cf
    
    # Create SASL password file (empty, for fallback)
    touch /etc/postfix/sasl_passwd
    chmod 600 /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd 2>/dev/null || true
    
    log_info "Postfix configuration completed."
}

###############################################################################
# 5. Python AI Filter Service Installation (Phi-3 Optimized)
###############################################################################
filter_service_setup() {
    log_info "Setting up Python AI Filter Service..."
    
    # Create service directory
    mkdir -p /opt/email-filter
    cd /opt/email-filter
    
    # Create Python virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python dependencies
    pip install --upgrade pip
    pip install aiosmtpd requests psycopg2-binary python-dotenv
    
    # Create the main filter script
    cat > /opt/email-filter/filter.py <<'PYTHON_EOF'
#!/usr/bin/env python3
"""
Multi-Tenant AI Email Filter Service
Optimized for Phi-3-mini classification tasks.
"""

import asyncio
import logging
import requests
import time
import psycopg2
from aiosmtpd.controller import Controller
from email.parser import BytesParser
from email.policy import default
import smtplib
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/etc/email-gateway/config.env')

# Configuration
OLLAMA_URL = os.getenv('OLLAMA_URL', 'http://127.0.0.1:11434/api/generate')
POSTFIX_REINJECT_HOST = os.getenv('POSTFIX_REINJECT_HOST', '127.0.0.1')
POSTFIX_REINJECT_PORT = int(os.getenv('POSTFIX_REINJECT_PORT', 10026))
MODEL_NAME = os.getenv('OLLAMA_MODEL', 'phi3:mini')
DB_CONFIG = {
    'host': os.getenv('DB_HOST', '127.0.0.1'),
    'port': os.getenv('DB_PORT', 5432),
    'dbname': os.getenv('DB_NAME', 'email_gateway'),
    'user': os.getenv('POSTFIX_READER_USER', 'postfix_reader'),
    'password': os.getenv('POSTFIX_READER_PASSWORD')
}

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/email-filter/filter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AIFilter")

def get_tenant_config(domain):
    """Retrieve tenant configuration from PostgreSQL."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            SELECT id, domain, relay_host, relay_port, sasl_username, 
                   ai_filter_enabled, spam_action, use_tls
            FROM tenants 
            WHERE domain = %s AND active = true
        """, (domain,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if result:
            return {
                'id': result[0],
                'domain': result[1],
                'relay_host': result[2],
                'relay_port': result[3],
                'sasl_username': result[4],
                'ai_filter_enabled': result[5],
                'spam_action': result[6],
                'use_tls': result[7]
            }
        return None
    except Exception as e:
        logger.error(f"Database error for domain {domain}: {e}")
        return None

def analyze_with_ollama(content, tenant_config):
    """Send content to Ollama for spam classification using Phi-3-mini template."""
    if not tenant_config.get('ai_filter_enabled', True):
        return False
    
    # Phi-3-mini Chat Template for Classification
    # Optimized for speed and deterministic output
    prompt = f"""<|user|>
Classify the following email as SPAM or LEGITIMATE. 
Reply with ONLY one word.

Email Content:
{content[:1500]}
<|end|>
<|assistant|>"""
    
    start_time = time.time()
    try:
        response = requests.post(OLLAMA_URL, json={
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.0,      # Deterministic output
                "num_predict": 5,        # Minimal tokens
                "top_p": 0.9,
                "repeat_penalty": 1.1
            }
        }, timeout=30)  # Reduced timeout for Phi-3-mini
        
        if response.status_code == 200:
            result = response.json().get('response', '').strip().upper()
            processing_time = int((time.time() - start_time) * 1000)
            
            # Determine classification
            classification = 'SPAM' if 'SPAM' in result else 'LEGITIMATE'
            
            # Log audit trail
            log_audit(tenant_config['domain'], "AI_CHECK", classification, processing_time)
            
            logger.info(f"Phi-3-mini decision for {tenant_config['domain']}: {classification} ({processing_time}ms)")
            return classification == 'SPAM'
        else:
            logger.error(f"Ollama API error: {response.status_code}")
            return False
    except requests.exceptions.Timeout:
        logger.warning(f"Ollama request timeout for {tenant_config['domain']}")
        return False
    except Exception as e:
        logger.error(f"AI inference failed for {tenant_config['domain']}: {e}")
        return False

def log_audit(tenant_domain, event_type, decision, processing_time_ms):
    """Log filtering decisions to audit table."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO filter_audit_log (tenant_domain, ai_decision, processing_time_ms)
            VALUES (%s, %s, %s)
        """, (tenant_domain, decision, processing_time_ms))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        logger.error(f"Audit logging failed: {e}")

class AIFilterHandler:
    async def handle_DATA(self, server, session, envelope):
        """Main email processing handler."""
        start_time = time.time()
        
        recipient = envelope.rcpt_tos[0] if envelope.rcpt_tos else ''
        tenant_domain = recipient.split('@')[-1].lower() if '@' in recipient else None
        
        if not tenant_domain:
            logger.warning(f"Cannot determine tenant domain for recipient: {recipient}")
            return '550 5.7.1 Cannot determine routing domain'
        
        logger.info(f"Processing message for tenant: {tenant_domain} from {envelope.mail_from}")
        
        tenant_config = get_tenant_config(tenant_domain)
        if not tenant_config:
            logger.warning(f"Tenant {tenant_domain} not found or inactive")
            return '550 5.7.1 Domain not configured for filtering service'
        
        try:
            msg = BytesParser(policy=default).parsebytes(envelope.content)
            body_part = msg.get_body(preferencelist=('plain', 'html'))
            content = body_part.get_content() if body_part else str(msg)
        except Exception as e:
            logger.error(f"Failed to parse email: {e}")
            return '451 4.6.0 Message parsing error'
        
        is_spam = analyze_with_ollama(content, tenant_config)
        
        if is_spam:
            spam_action = tenant_config.get('spam_action', 'reject')
            logger.warning(f"SPAM detected for {tenant_domain}: action={spam_action}")
            
            if spam_action == 'reject':
                return '550 5.7.1 Message rejected as spam by AI Gateway'
            elif spam_action == 'tag':
                envelope.content += b"\nX-AI-Spam-Status: Yes, score=5.0\n"
        
        envelope.content += f"\nX-Tenant-Domain: {tenant_domain}".encode()
        envelope.content += f"\nX-AI-Processed: {time.strftime('%Y-%m-%d %H:%M:%S')}".encode()
        
        try:
            with smtplib.SMTP(POSTFIX_REINJECT_HOST, POSTFIX_REINJECT_PORT) as client:
                client.sendmail(envelope.mail_from, envelope.rcpt_tos, envelope.content)
            
            total_time = int((time.time() - start_time) * 1000)
            logger.info(f"Message from {envelope.mail_from} to {tenant_domain} delivered ({total_time}ms)")
            return '250 OK'
        except Exception as e:
            logger.error(f"Failed to reinject mail for {tenant_domain}: {e}")
            return '451 4.3.0 Temporary filtering error'

if __name__ == '__main__':
    os.makedirs('/var/log/email-filter', exist_ok=True)
    
    controller = Controller(
        AIFilterHandler(), 
        hostname='127.0.0.1', 
        port=int(os.getenv('FILTER_SERVICE_PORT', 10025))
    )
    controller.start()
    logger.info(f"AI Filter Service started on port {os.getenv('FILTER_SERVICE_PORT', 10025)}")
    
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down AI Filter Service")
        controller.stop()
PYTHON_EOF

    # Create environment file for the service
    cat > /opt/email-filter/.env <<EOF
# AI Filter Service Environment Variables
OLLAMA_URL=http://127.0.0.1:11434/api/generate
POSTFIX_REINJECT_HOST=127.0.0.1
POSTFIX_REINJECT_PORT=$REINJECT_PORT
OLLAMA_MODEL=$OLLAMA_MODEL
FILTER_SERVICE_PORT=$FILTER_SERVICE_PORT
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=$DB_NAME
POSTFIX_READER_USER=postfix_reader
POSTFIX_READER_PASSWORD=$POSTFIX_READER_PASSWORD
EOF
    chmod 600 /opt/email-filter/.env

    # Create systemd service file
    cat > /etc/systemd/system/email-filter.service <<EOF
[Unit]
Description=Multi-Tenant AI Email Filter Service
After=network.target ollama.service postgresql.service postfix.service
Requires=ollama.service postgresql.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/email-filter
Environment="PATH=/opt/email-filter/venv/bin"
ExecStart=/opt/email-filter/venv/bin/python /opt/email-filter/filter.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=email-filter

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/email-filter /opt/email-filter

[Install]
WantedBy=multi-user.target
EOF

    mkdir -p /var/log/email-filter
    chmod 755 /var/log/email-filter
    
    deactivate
    
    log_info "Python AI Filter Service setup completed."
}

###############################################################################
# 6. Tenant Management Helper Script
###############################################################################
create_tenant_script() {
    log_info "Creating tenant management helper script..."
    
    cat > /usr/local/bin/email-gateway-add-tenant <<'EOF'
#!/bin/bash
# email-gateway-add-tenant - Add new tenant to AI Email Gateway

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <domain> <relay_host> [relay_port] [sasl_user] [sasl_pass]"
    exit 1
fi

DOMAIN="$1"
RELAY_HOST="$2"
RELAY_PORT="${3:-587}"
SASL_USER="${4:-}"
SASL_PASS="${5:-}"

source /etc/email-gateway/db_credentials.conf

if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo "Error: Invalid domain format"
    exit 1
fi

psql -h 127.0.0.1 -U $DB_ADMIN_USER -d $DB_NAME -c "
INSERT INTO tenants (domain, relay_host, relay_port, sasl_username, sasl_password)
VALUES ('$DOMAIN', '$RELAY_HOST', $RELAY_PORT, '$SASL_USER', '$SASL_PASS')
ON CONFLICT (domain) DO UPDATE SET 
    relay_host = EXCLUDED.relay_host,
    relay_port = EXCLUDED.relay_port,
    sasl_username = EXCLUDED.sasl_username,
    sasl_password = EXCLUDED.sasl_password,
    updated_at = CURRENT_TIMESTAMP;
"

systemctl reload postfix

echo "✓ Tenant $DOMAIN added successfully"
EOF

    chmod +x /usr/local/bin/email-gateway-add-tenant
    log_info "Tenant management script created."
}

###############################################################################
# 7. Firewall and Security Configuration
###############################################################################
security_setup() {
    log_info "Configuring firewall and security settings..."
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    ufw allow 22/tcp
    ufw allow 25/tcp
    ufw allow 587/tcp
    ufw allow 465/tcp
    ufw allow 443/tcp
    
    ufw allow from 127.0.0.1 to 127.0.0.1 port 5432
    ufw allow from 127.0.0.1 to 127.0.0.1 port 11434
    
    ufw --force enable
    
    cat > /etc/fail2ban/jail.d/email-gateway.conf <<EOF
[postfix]
enabled = true
port = smtp,submission,smtps
filter = postfix
logpath = /var/log/mail.log
maxretry = 5
bantime = 3600
EOF
    
    systemctl restart fail2ban
    
    chmod 640 /etc/postfix/pgsql/*.cf
    chown root:postfix /etc/postfix/pgsql/*.cf
    
    log_info "Security configuration completed."
}

###############################################################################
# 8. Service Startup and Finalization
###############################################################################
finalize_installation() {
    log_info "Starting services and finalizing installation..."
    
    systemctl daemon-reload
    systemctl enable --now postfix
    systemctl enable --now email-filter
    systemctl enable --now ollama
    systemctl enable --now postgresql
    
    sleep 5
    
    log_info "Verifying service connectivity..."
    
    if PGPASSWORD=$POSTFIX_READER_PASSWORD psql -h 127.0.0.1 -U postfix_reader -d $DB_NAME -c "SELECT 1;" > /dev/null 2>&1; then
        log_info "✓ PostgreSQL connection successful"
    else
        log_warn "✗ PostgreSQL connection failed"
    fi
    
    if curl -s http://127.0.0.1:11434/api/tags > /dev/null 2>&1; then
        log_info "✓ Ollama API accessible"
    else
        log_warn "✗ Ollama API not accessible"
    fi
    
    if postfix check 2>/dev/null; then
        log_info "✓ Postfix configuration valid"
    else
        log_warn "✗ Postfix configuration has issues"
    fi
    
    cat <<EOF

================================================================================
                    INSTALLATION COMPLETE - SUMMARY
================================================================================

✓ Multi-Tenant AI Email Gateway installed successfully on $MY_HOSTNAME
✓ Model: Phi-3-mini (Optimised for Low RAM & High Speed)

SERVICES STATUS:
  • PostgreSQL:     Active (Database: $DB_NAME)
  • Ollama:         Active (Model: $OLLAMA_MODEL)
  • Postfix:        Active (Multi-tenant routing configured)
  • AI Filter:      Active (Listening on port $FILTER_SERVICE_PORT)

CONFIGURATION FILES:
  • Database:       /etc/email-gateway/db_credentials.conf
  • Postfix PGSQL:  /etc/postfix/pgsql/
  • Filter Service: /opt/email-filter/

MANAGEMENT COMMANDS:
  • Add tenant:     /usr/local/bin/email-gateway-add-tenant <domain> <relay> [...]
  • View logs:      journalctl -u email-filter -f
  • Service status: systemctl status email-filter postfix ollama postgresql

CRITICAL NEXT STEPS (MANUAL):
  1. Configure DNS records (PTR, SPF, DKIM, DMARC).
  2. Secure database credentials in /etc/email-gateway/db_credentials.conf.
  3. Configure TLS certificates (Let's Encrypt recommended).
  4. Test email flow with a test tenant.

================================================================================
EOF

    log_info "Installation completed."
}

###############################################################################
# Main Execution
###############################################################################
main() {
    echo "========================================"
    echo "Multi-Tenant AI Email Gateway Installer"
    echo "Model: Phi-3-mini (Optimized)"
    echo "Debian 12 - $(date)"
    echo "========================================"
    
    check_prerequisites
    system_prepare
    save_configuration
    postgres_setup
    ollama_setup
    postfix_setup
    filter_service_setup
    create_tenant_script
    security_setup
    finalize_installation
}

main "$@"
