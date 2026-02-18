#!/bin/bash
#
# MailMCP Uninstallation Script
# MailMCP 卸载脚本
#
# Usage: sudo ./uninstall.sh [--purge]
# 用法: sudo ./uninstall.sh [--purge]
#
# --purge: Remove all data including configuration and logs
# --purge: 删除所有数据包括配置和日志

set -e

INSTALL_DIR="/opt/mailmcp"
CONFIG_DIR="/etc/mailmcp"
DATA_DIR="/var/lib/mailmcp"
LOG_DIR="/var/log/mailmcp"

PURGE=false
if [ "$1" == "--purge" ]; then
    PURGE=true
fi

echo "========================================"
echo "  MailMCP Uninstaller"
echo "  MailMCP 卸载程序"
echo "========================================"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root"
    echo "错误: 请使用 root 权限运行"
    exit 1
fi

# Confirm
if [ "$PURGE" = true ]; then
    echo "WARNING: --purge will remove ALL data including:"
    echo "警告: --purge 将删除所有数据包括:"
    echo "  - Configuration files"
    echo "  - 配置文件"
    echo "  - Authentication data"
    echo "  - 认证数据"
    echo "  - Logs"
    echo "  - 日志"
    echo ""
fi

read -p "Continue? / 继续? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled / 已取消"
    exit 0
fi

# Stop service
echo "[1/4] Stopping service..."
systemctl stop mailmcp 2>/dev/null || true
systemctl disable mailmcp 2>/dev/null || true
echo "  Service stopped"

# Remove systemd service
echo "[2/4] Removing systemd service..."
rm -f /etc/systemd/system/mailmcp.service
systemctl daemon-reload
echo "  Service removed"

# Remove program files
echo "[3/4] Removing program files..."
rm -rf "$INSTALL_DIR"
echo "  Program files removed"

# Remove data (if purge)
echo "[4/4] Removing data..."
if [ "$PURGE" = true ]; then
    rm -rf "$CONFIG_DIR"
    rm -rf "$DATA_DIR"
    rm -rf "$LOG_DIR"
    echo "  All data removed (purge mode)"
else
    echo "  Data preserved (use --purge to remove all)"
    echo "  数据已保留 (使用 --purge 删除所有)"
fi

echo ""
echo "========================================"
echo "  Uninstallation Complete!"
echo "  卸载完成!"
echo "========================================"
echo ""
if [ "$PURGE" = false ]; then
    echo "Note: Configuration and data preserved at:"
    echo "注意: 配置和数据保留在:"
    echo "  $CONFIG_DIR"
    echo "  $DATA_DIR"
    echo "  $LOG_DIR"
    echo ""
    echo "Run with --purge to remove everything."
    echo "使用 --purge 参数可删除所有内容。"
fi
