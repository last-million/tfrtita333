#!/bin/bash
set -e

# -----------------------------------------------------------
# CONFIGURATION VARIABLES
# -----------------------------------------------------------
DOMAIN="ajingolik.fun"
EMAIL="hamzameliani1@gmail.com"

# Directories and file locations (assumes deploy.sh is in the repo root)
APP_DIR="$(pwd)"
BACKEND_DIR="${APP_DIR}/backend"
FRONTEND_DIR="${APP_DIR}/frontend"
WEB_ROOT="/var/www/${DOMAIN}/html"
SERVICE_FILE="/etc/systemd/system/tfrtita333.service"

# -----------------------------------------------------------
# HELPER FUNCTION
# -----------------------------------------------------------
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# -----------------------------------------------------------
# I. SYSTEM PREPARATION
# -----------------------------------------------------------
log "Updating system packages..."
sudo apt update && sudo apt upgrade -y

log "Installing required packages..."
sudo apt install -y nginx certbot python3-certbot-nginx ufw git python3 python3-pip python3-venv \
    libyaml-dev dos2unix mysql-server mysql-client libmysqlclient-dev python3-dev

log "Installing Node Version Manager (nvm) if not present..."
export NVM_DIR="$HOME/.nvm"
if [ ! -d "$NVM_DIR" ]; then
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
fi
# Load nvm in this shell
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && . "$NVM_DIR/bash_completion"

log "Installing Node.js LTS via nvm..."
nvm install --lts
nvm use --lts

log "Ensuring deploy.sh uses Unix line endings..."
dos2unix deploy.sh || true

log "Configuring UFW firewall (OpenSSH, Nginx Full, MySQL, port 8000)..."
sudo ufw allow OpenSSH
sudo ufw allow "Nginx Full"
sudo ufw allow 8000
sudo ufw allow mysql
sudo ufw --force enable
sudo ufw status

log "Setting basic iptables rules (if desired, otherwise optional)..."
sudo mkdir -p /etc/iptables
sudo tee /etc/iptables/rules.v4 > /dev/null <<'EOF'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow loopback interface
-A INPUT -i lo -j ACCEPT
# Allow SSH (port 22)
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
# Allow HTTP (port 80)
-A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
# Allow HTTPS (port 443)
-A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
# Allow MySQL (port 3306)
-A INPUT -p tcp -m state --state NEW -m tcp --dport 3306 -j ACCEPT
# Allow additional port (e.g., 8000)
-A INPUT -p tcp -m state --state NEW -m tcp --dport 8000 -j ACCEPT
# Drop all other incoming traffic
-A INPUT -j DROP
COMMIT
EOF
sudo iptables-restore < /etc/iptables/rules.v4

# -----------------------------------------------------------
# II. MYSQL SETUP AND VALIDATION
# -----------------------------------------------------------
log "Setting up and validating MySQL..."

# Function to check MySQL connection
check_mysql_connection() {
    if mysql -u"$1" -p"$2" -e "SELECT 1;" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to check if database exists
check_database_exists() {
    if mysql -u"$1" -p"$2" -e "USE $3;" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Ensure MySQL service is running
log "Ensuring MySQL service is running..."
sudo systemctl start mysql || { log "Failed to start MySQL service"; exit 1; }

# Test root connection first
log "Testing MySQL root connection..."
if ! check_mysql_connection "root" "AFINasahbi@-11"; then
    log "ERROR: Cannot connect to MySQL as root. Please check root password."
    exit 1
fi

# Create database and user if they don't exist
log "Setting up database and user..."
mysql -uroot -p"AFINasahbi@-11" <<EOF
CREATE DATABASE IF NOT EXISTS voice_call_ai CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'hamza'@'localhost' IDENTIFIED BY 'AFINasahbi@-11';
GRANT ALL PRIVILEGES ON voice_call_ai.* TO 'hamza'@'localhost';
FLUSH PRIVILEGES;
EOF

# Verify database exists
log "Verifying database existence..."
if ! check_database_exists "hamza" "AFINasahbi@-11" "voice_call_ai"; then
    log "ERROR: Database 'voice_call_ai' not accessible with configured credentials"
    exit 1
fi

log "MySQL setup and validation completed successfully"

# Create necessary tables
log "Creating database tables..."
mysql -u"hamza" -p"AFINasahbi@-11" voice_call_ai <<'EOF'
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS calls (
    id INT PRIMARY KEY AUTO_INCREMENT,
    call_sid VARCHAR(255),
    from_number VARCHAR(50),
    to_number VARCHAR(50),
    direction VARCHAR(20),
    duration INT,
    status VARCHAR(50),
    start_time DATETIME,
    end_time DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
EOF

# -----------------------------------------------------------
# III. PYTHON VENV & BACKEND PREP
# -----------------------------------------------------------
log "Setting up Python virtual environment in ${APP_DIR}..."
rm -rf "${APP_DIR}/venv"
python3 -m venv venv
source venv/bin/activate

log "Installing basic Python packages (prometheus_client, etc.)..."
pip install --upgrade pip setuptools wheel
pip install cython prometheus_client

# -----------------------------------------------------------
# IV. BACKEND SETUP
# -----------------------------------------------------------
log "Installing backend dependencies..."
cd "${BACKEND_DIR}"
if [ ! -f ".env" ]; then
  log "Creating an empty .env in ${BACKEND_DIR}..."
  touch .env
fi

if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    log "Warning: No requirements.txt found in ${BACKEND_DIR}."
fi

pip install gunicorn uvicorn mysqlclient python-jose[cryptography] passlib[bcrypt] python-multipart

log "Overwriting backend .env with production values..."
cat > "${BACKEND_DIR}/.env" <<EOF
# Database Configuration
DB_HOST=localhost
DB_USER=hamza
DB_PASSWORD=AFINasahbi@-11
DB_DATABASE=voice_call_ai

# Twilio Credentials
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token

# Supabase Credentials
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your_supabase_key

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# Ultravox API
ULTRAVOX_API_KEY=your_ultravox_api_key

# JWT Secret
JWT_SECRET=your_jwt_secret_key

# App Settings
DEBUG=True
CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,https://${DOMAIN}
SERVER_DOMAIN=${DOMAIN}
EOF

log "Attempting to initialize database tables (python -m app.database)..."
python -m app.database || log "WARNING: Database initialization step failed. Check your .env / DB config."

# -----------------------------------------------------------
# V. FRONTEND SETUP
# -----------------------------------------------------------
log "Building frontend..."
cd "${FRONTEND_DIR}"
if [ ! -f ".env" ]; then
  log "Creating .env in ${FRONTEND_DIR}..."
  touch .env
fi
cat > "${FRONTEND_DIR}/.env" <<EOF
VITE_API_URL=https://${DOMAIN}/api
VITE_WEBSOCKET_URL=wss://${DOMAIN}/ws
VITE_GOOGLE_CLIENT_ID=your_google_client_id
EOF

npm install
npm run build

log "Deploying built frontend to ${WEB_ROOT}..."
sudo mkdir -p "${WEB_ROOT}"
sudo rm -rf "${WEB_ROOT:?}"/*
sudo cp -r dist/* "${WEB_ROOT}/"

# -----------------------------------------------------------
# VI. SYSTEMD SERVICE FOR BACKEND
# -----------------------------------------------------------
log "Creating systemd service for Gunicorn/Uvicorn backend..."
sudo tee ${SERVICE_FILE} > /dev/null <<EOF
[Unit]
Description=Tfrtita333 App Backend
After=network.target mysql.service

[Service]
User=ubuntu
WorkingDirectory=${BACKEND_DIR}
Environment="PATH=${APP_DIR}/venv/bin"
ExecStart=${APP_DIR}/venv/bin/gunicorn -k uvicorn.workers.UvicornWorker -w 3 --bind 127.0.0.1:8080 app.main:app
Restart=always
RestartSec=5
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable tfrtita333.service
sudo systemctl restart tfrtita333.service

# -----------------------------------------------------------
# VII. NGINX CONFIGURATION
# -----------------------------------------------------------
log "Configuring Nginx for domain ${DOMAIN}..."
NGINX_CONF="/etc/nginx/sites-available/${DOMAIN}"
sudo tee ${NGINX_CONF} > /dev/null <<EOF
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};

    location /.well-known/acme-challenge/ {
        root ${WEB_ROOT};
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN} www.${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;

    # DH param file if present
    ssl_dhparam /etc/ssl/certs/dhparam.pem;

    client_max_body_size 100M;

    # Serve React frontend
    location / {
        root ${WEB_ROOT};
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    # Proxy /api to Gunicorn
    location /api/ {
        proxy_pass http://127.0.0.1:8080/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # WebSocket support
    location /ws {
        proxy_pass http://127.0.0.1:8080/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }
}
EOF

if [ ! -f "/etc/ssl/certs/dhparam.pem" ]; then
  log "Generating /etc/ssl/certs/dhparam.pem (2048 bits). This may take a few minutes..."
  sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
fi

log "Enabling Nginx config..."
sudo ln -sf ${NGINX_CONF} /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

# -----------------------------------------------------------
# VIII. SSL CERTIFICATE WITH CERTBOT
# -----------------------------------------------------------
log "Obtaining SSL certificate via Certbot..."
sudo certbot --nginx -d ${DOMAIN} -d www.${DOMAIN} --non-interactive --agree-tos --email ${EMAIL} --redirect

# -----------------------------------------------------------
# IX. FINAL STEPS & VERIFICATION
# -----------------------------------------------------------
log "Restarting services..."
sudo systemctl restart mysql
sudo systemctl restart tfrtita333
sudo systemctl restart nginx

log "Checking service statuses..."
services=("mysql" "nginx" "tfrtita333")
for service in "${services[@]}"; do
    if ! sudo systemctl is-active --quiet "$service"; then
        log "WARNING: $service is NOT running!"
    else
        log "$service is running OK."
    fi
done

log "Deployment complete!"
log "Site: https://${DOMAIN}"
log "Default admin credentials: username=hamza, password=AFINasahbi@-11"
log "Check logs if needed:"
log "  Backend:  sudo journalctl -u tfrtita333 -f"
log "  Nginx:    sudo tail -f /var/log/nginx/error.log"
log "  MySQL:    sudo tail -f /var/log/mysql/error.log"
