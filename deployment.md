# Deployment Guide for Twilio-Ultravox Web Application

## Prerequisites
- Ubuntu 20.04 or higher
- Node.js 16+ and npm
- Python 3.8+
- MySQL 8.0+
- Nginx
- Domain name pointing to your server (ajingolik.fun)

## 1. Initial Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y nginx certbot python3-certbot-nginx ufw git python3 python3-pip python3-venv mysql-server

# Configure firewall
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

## 2. Database Setup

```bash
# Secure MySQL installation
sudo mysql_secure_installation

# Create database and user
sudo mysql -u root -p
```

```sql
CREATE DATABASE twilio_ultravox;
CREATE USER 'ultravox_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON twilio_ultravox.* TO 'ultravox_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

## 3. Application Setup

```bash
# Clone repository
cd /var/www
sudo git clone [your-repo-url] twilio-ultravox
cd twilio-ultravox

# Frontend setup
npm install
npm run build

# Backend setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create environment file
sudo nano .env
```

Add the following to .env:
```
DATABASE_URL=mysql://ultravox_user:your_password@localhost/twilio_ultravox
ULTRAVOX_API_KEY=your_ultravox_key
PINECONE_API_KEY=your_pinecone_key
N8N_WEBHOOK_URL=your_webhook_url
TWILIO_ACCOUNT_SID=your_twilio_sid
TWILIO_AUTH_TOKEN=your_twilio_token
TWILIO_PHONE_NUMBER=your_twilio_number
SECRET_KEY=your_jwt_secret
```

## 4. Nginx Configuration

```bash
# Remove default config
sudo rm /etc/nginx/sites-enabled/default

# Create new config
sudo nano /etc/nginx/sites-available/ajingolik.fun
```

Copy the contents of nginx/ajingolik.fun.conf

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/ajingolik.fun /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Get SSL certificate
sudo certbot --nginx -d ajingolik.fun -d www.ajingolik.fun

# Restart Nginx
sudo systemctl restart nginx
```

## 5. Setup Systemd Service

```bash
sudo nano /etc/systemd/system/ultravox.service
```

Add:
```ini
[Unit]
Description=Ultravox FastAPI Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/twilio-ultravox
Environment="PATH=/var/www/twilio-ultravox/venv/bin"
EnvironmentFile=/var/www/twilio-ultravox/.env
ExecStart=/var/www/twilio-ultravox/venv/bin/gunicorn -w 3 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8000

[Install]
WantedBy=multi-user.target
```

```bash
# Start and enable service
sudo systemctl start ultravox
sudo systemctl enable ultravox
```

## 6. Final Steps

```bash
# Set proper permissions
sudo chown -R www-data:www-data /var/www/twilio-ultravox
sudo chmod -R 755 /var/www/twilio-ultravox

# Restart all services
sudo systemctl restart nginx
sudo systemctl restart ultravox
```

## Maintenance

### Logs
- Application logs: `sudo journalctl -u ultravox`
- Nginx access logs: `sudo tail -f /var/log/nginx/access.log`
- Nginx error logs: `sudo tail -f /var/log/nginx/error.log`

### Updates
```bash
cd /var/www/twilio-ultravox
sudo git pull
npm install
npm run build
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart ultravox
```

### SSL Renewal
SSL certificates will auto-renew, but you can manually renew with:
```bash
sudo certbot renew
```
