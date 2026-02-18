#!/bin/bash
#
# MailMCP Installation Script
# MailMCP 安装脚本
#
# Usage: sudo ./install.sh
# 用法: sudo ./install.sh

set -e

VERSION="3.2"
INSTALL_DIR="/opt/mailmcp"
CONFIG_DIR="/etc/mailmcp"
DATA_DIR="/var/lib/mailmcp"
LOG_DIR="/var/log/mailmcp"

echo "========================================"
echo "  MailMCP v${VERSION} Installer"
echo "  MailMCP v${VERSION} 安装程序"
echo "========================================"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root"
    echo "错误: 请使用 root 权限运行"
    exit 1
fi

# Check Python version
echo "[1/8] Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo "Error: Python 3.10+ required, found $PYTHON_VERSION"
    echo "错误: 需要 Python 3.10+，当前版本 $PYTHON_VERSION"
    exit 1
fi
echo "  Python $PYTHON_VERSION OK"

# Install system dependencies
echo "[2/8] Installing system dependencies..."
apt update -qq
apt install -y -qq sshpass gnupg openssl curl > /dev/null 2>&1
echo "  System dependencies installed"

# Install Python packages
echo "[3/8] Installing Python packages..."
if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 13 ]; then
    pip3 install --break-system-packages python-gnupg requests > /dev/null 2>&1
else
    pip3 install python-gnupg requests > /dev/null 2>&1
fi
echo "  Python packages installed"

# Create directories
echo "[4/8] Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"/{auth,keys,jobs,sockets}
mkdir -p "$LOG_DIR"
mkdir -p "$CONFIG_DIR"/certs
echo "  Directories created"

# Copy files
echo "[5/8] Copying files..."
cp mailmcp_unified.py "$INSTALL_DIR/"
cp mailmcp_client.py "$INSTALL_DIR/"
cp mcp_client.py "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR"/*.py
echo "  Files copied to $INSTALL_DIR"

# Generate TLS certificate
echo "[6/8] Generating TLS certificate..."
mkdir -p "$CONFIG_DIR/certs"
if [ ! -f "$CONFIG_DIR/certs/cert.pem" ] || [ ! -f "$CONFIG_DIR/certs/key.pem" ]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CONFIG_DIR/certs/key.pem" \
        -out "$CONFIG_DIR/certs/cert.pem" \
        -days 365 -nodes \
        -subj "/CN=mailmcp" 2>/dev/null
    chmod 600 "$CONFIG_DIR/certs/key.pem"
    chmod 644 "$CONFIG_DIR/certs/cert.pem"
    echo "  TLS certificate generated"
    echo "  TLS 证书已生成"
else
    echo "  TLS certificate already exists, skipping"
    echo "  TLS 证书已存在，跳过"
fi

# Create config file
echo "[7/8] Creating configuration..."
if [ ! -f "$CONFIG_DIR/mailmcp.conf" ]; then
    cp mailmcp.conf "$CONFIG_DIR/"
    echo "  Configuration file created: $CONFIG_DIR/mailmcp.conf"
    echo ""
    echo "  IMPORTANT: Please edit $CONFIG_DIR/mailmcp.conf"
    echo "  重要: 请编辑 $CONFIG_DIR/mailmcp.conf"
else
    echo "  Configuration file already exists, preserving"
fi

# Create servers config
if [ ! -f "$CONFIG_DIR/servers.conf" ]; then
    cat > "$CONFIG_DIR/servers.conf" << 'EOF'
# MailMCP Server Configuration
# Format: name host port user password_or_key_path
# 格式: 名称 主机 端口 用户 密码或密钥路径
#
# Examples:
# ovh example.com 22 user /home/user/.ssh/id_rsa
# bage example.com 22 root password123
# local 127.0.0.1 22 root /root/.ssh/id_rsa
EOF
    echo "  Server config created: $CONFIG_DIR/servers.conf"
fi

# Create systemd service
echo "[8/8] Creating systemd service..."
cat > /etc/systemd/system/mailmcp.service << EOF
[Unit]
Description=MailMCP - Email-based Server Management
Documentation=https://github.com/your-repo/MailMCP
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/mailmcp_unified.py
WorkingDirectory=$INSTALL_DIR

# Environment configuration
Environment="CONFIG_FILE=$CONFIG_DIR/servers.conf"
Environment="LOG_FILE=$LOG_DIR/mailmcp.log"
Environment="AUTH_DIR=$DATA_DIR/auth"
Environment="KEYS_DIR=$DATA_DIR/keys"
Environment="JOBS_DIR=$DATA_DIR/jobs"
Environment="SOCKET_DIR=$DATA_DIR/sockets"
Environment="CERT_FILE=$CONFIG_DIR/certs/cert.pem"
Environment="KEY_FILE=$CONFIG_DIR/certs/key.pem"

# Load config file
EnvironmentFile=-$CONFIG_DIR/mailmcp.conf

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mailmcp > /dev/null 2>&1

echo ""
echo "========================================"
echo "  Installation Complete!"
echo "  安装完成!"
echo "========================================"
echo ""
echo "Files installed to: $INSTALL_DIR"
echo "Configuration: $CONFIG_DIR/mailmcp.conf"
echo "Server list: $CONFIG_DIR/servers.conf"
echo "Logs: $LOG_DIR/mailmcp.log"
echo ""
echo "Next steps:"
echo "  1. Edit $CONFIG_DIR/mailmcp.conf"
echo "     编辑 $CONFIG_DIR/mailmcp.conf"
echo ""
echo "  2. Edit $CONFIG_DIR/servers.conf"
echo "     编辑 $CONFIG_DIR/servers.conf"
echo ""
echo "  3. Start service:"
echo "     启动服务:"
echo "     systemctl start mailmcp"
echo ""
echo "  4. Check status:"
echo "     检查状态:"
echo "     systemctl status mailmcp"
echo ""
