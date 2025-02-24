#!/bin/bash
set -e

# -----------------------------------------------------------
# CONFIGURATION VARIABLES
# -----------------------------------------------------------
DOMAIN="ajingolik.fun"
EMAIL="hamzameliani1@gmail.com"

# MySQL Configuration
MYSQL_ROOT_PASSWORD="AFINasahbi@-11"
MYSQL_USER="hamza"
MYSQL_PASSWORD="AFINasahbi@-11"
MYSQL_DATABASE="voice_call_ai"

# Directories and file locations (assumes deploy.sh is in the repo root)
APP_DIR="$(pwd)"
BACKEND_DIR="${APP_DIR}/backend"
FRONTEND_DIR="${APP_DIR}/frontend"
WEB_ROOT="/var/www/${DOMAIN}/html"
SERVICE_FILE="/etc/systemd/system/tfrtita333.service"

# -----------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

check_error() {
  if [ $? -ne 0 ]; then
    log "ERROR: $1"
    exit 1
  fi
}

# -----------------------------------------------------------
# I. SYSTEM PREPARATION
# -----------------------------------------------------------
log "Updating system packages..."
sudo apt update && sudo apt upgrade -y
check_error "System update failed"

log "Installing required packages..."
sudo apt install -y nginx certbot python3-certbot-nginx ufw git python3 python3-pip python3-venv \
    libyaml-dev dos2unix mysql-server mysql-client libmysqlclient-dev python3-dev
check_error "Package installation failed"

log "Installing Node Version Manager (nvm)..."
export NVM_DIR="$HOME/.nvm"
if [ ! -d "$NVM_DIR" ]; then
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
  check_error "NVM installation failed"
fi

# Load nvm
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && . "$NVM_DIR/bash_completion"

log "Installing Node.js LTS..."
nvm install --lts
nvm use --lts
check_error "Node.js installation failed"

log "Ensuring deploy.sh uses Unix line endings..."
dos2unix deploy.sh || true

log "Configuring UFW firewall..."
sudo ufw allow OpenSSH
sudo ufw allow "Nginx Full"
sudo ufw allow 8000
sudo ufw allow mysql
sudo ufw --force enable
sudo ufw status
check_error "Firewall configuration failed"

# -----------------------------------------------------------
# II. MYSQL SETUP AND VALIDATION
# -----------------------------------------------------------
log "Setting up MySQL..."

# Ensure MySQL is running
sudo systemctl start mysql
check_error "Failed to start MySQL"

# Secure MySQL installation
sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASSWORD}';"
check_error "Failed to set root password"

# Create database and user
sudo mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" <<EOF
CREATE DATABASE IF NOT EXISTS ${MYSQL_DATABASE} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'localhost' IDENTIFIED BY '${MYSQL_PASSWORD}';
GRANT ALL PRIVILEGES ON ${MYSQL_DATABASE}.* TO '${MYSQL_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF
check_error "Failed to create database and user"

# Verify database access
if ! mysql -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" -e "USE ${MYSQL_DATABASE};"; then
    log "ERROR: Database access verification failed"
    exit 1
fi

# Create tables
mysql -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" ${MYSQL_DATABASE} <<'EOF'
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
check_error "Failed to create tables"

# -----------------------------------------------------------
# III. PYTHON VENV & BACKEND PREP
# -----------------------------------------------------------
log "Setting up Python virtual environment..."
cd "${APP_DIR}"
rm -rf venv
python3 -m venv venv
source venv/bin/activate
check_error "Virtual environment setup failed"

log "Installing Python packages..."
pip install --upgrade pip setuptools wheel
pip install cython prometheus_client
check_error "Basic Python packages installation failed"

# -----------------------------------------------------------
# IV. BACKEND SETUP
# -----------------------------------------------------------
log "Installing backend dependencies..."
cd "${BACKEND_DIR}"

if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    check_error "Failed to install requirements.txt"
fi

pip install gunicorn uvicorn mysqlclient python-jose[cryptography] passlib[bcrypt] python-multipart
check_error "Failed to install additional packages"

log "Configuring backend environment..."
cat > "${BACKEND_DIR}/.env" <<EOF
# Database Configuration
DB_HOST=localhost
DB_USER=${MYSQL_USER}
DB_PASSWORD=${MYSQL_PASSWORD}
DB_DATABASE=${MYSQL_DATABASE}

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
DEBUG=False
CORS_ORIGINS=https://${DOMAIN}
SERVER_DOMAIN=${DOMAIN}
EOF

log "Initializing database..."
python -m app.database || log "WARNING: Database initialization failed. Check configuration."

# -----------------------------------------------------------
# V. FRONTEND SETUP
# -----------------------------------------------------------
log "Setting up frontend..."
cd "${FRONTEND_DIR}"

cat > "${FRONTEND_DIR}/.env" <<EOF
VITE_API_URL=https://${DOMAIN}/api
VITE_WEBSOCKET_URL=wss://${DOMAIN}/ws
VITE_GOOGLE_CLIENT_ID=your_google_client_id
EOF

log "Installing frontend dependencies..."
npm install
check_error "npm install failed"

log "Building frontend..."
npm run build
check_error "Frontend build failed"

log "Deploying frontend..."
sudo mkdir -p "${WEB_ROOT}"
sudo rm -rf "${WEB_ROOT:?}"/*
sudo cp -r dist/* "${WEB_ROOT}/"
check_error "Frontend deployment failed"

# -----------------------------------------------------------
# VI. SYSTEMD SERVICE SETUP
# -----------------------------------------------------------
log "Creating systemd service..."
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
check_error "Service setup failed"

# -----------------------------------------------------------
# VII. NGINX CONFIGURATION
# -----------------------------------------------------------
log "Configuring Nginx..."
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
    ssl_dhparam /etc/ssl/certs/dhparam.pem;

    client_max_body_size 100M;

    location / {
        root ${WEB_ROOT};
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8080/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

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
    log "Generating DH parameters..."
    sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
fi

log "Enabling Nginx configuration..."
sudo ln -sf ${NGINX_CONF} /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
check_error "Nginx configuration failed"

# -----------------------------------------------------------
# VIII. SSL CERTIFICATE
# -----------------------------------------------------------
log "Obtaining SSL certificate..."
sudo certbot --nginx -d ${DOMAIN} -d www.${DOMAIN} --non-interactive --agree-tos --email ${EMAIL} --redirect
check_error "SSL certificate acquisition failed"

# -----------------------------------------------------------
# IX. FINAL VERIFICATION
# -----------------------------------------------------------
log "Restarting services..."
sudo systemctl restart mysql
sudo systemctl restart tfrtita333
sudo systemctl restart nginx

log "Verifying services..."
services=("mysql" "nginx" "tfrtita333")
for service in "${services[@]}"; do
    if ! sudo systemctl is-active --quiet "$service"; then
        log "WARNING: $service is not running!"
    else
        log "$service is running OK."
    fi
done

log "Deployment complete!"
log "Site: https://${DOMAIN}"
log "Default admin credentials: username=${MYSQL_USER}, password=${MYSQL_PASSWORD}"
log "Check logs if needed:"
log "  Backend:  sudo journalctl -u tfrtita333 -f"
log "  Nginx:    sudo tail -f /var/log/nginx/error.log"
log "  MySQL:    sudo tail -f /var/log/mysql/error.log"
