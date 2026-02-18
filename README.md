# MailMCP

**Email-Based Server Management with PGP Authorization**

[English](#english) | [中文](#中文)

---

<a name="english"></a>
## English

### Overview

MailMCP is a secure server management system that allows you to control remote servers via email or MCP (Model Context Protocol). It features:

- **PGP Authorization** - Public key authentication via keys.openpgp.org
- **Persistent SSH Connections** - SSH ControlMaster for reliable connections
- **Interactive Command Support** - ncurses/menuconfig compatible
- **Job Management** - Background tasks with input/output control
- **LLM Integration** - Natural language command processing
- **Security Hardening** - IP whitelist, rate limiting, command sanitization

### Innovation Highlights

MailMCP introduces several innovative approaches to server management:

#### 1. Email as Universal Interface
- **Zero Client Requirement**: Control servers from any email client (Gmail, Outlook, mobile apps)
- **Air-Gap Compatible**: Works through email gateways without direct network access
- **Audit Trail**: All commands logged in email history automatically

#### 2. Decentralized PGP Authentication
- **No Central Authority**: Uses keys.openpgp.org for public key distribution
- **User-Controlled Keys**: Users own and manage their PGP keys
- **Challenge-Response Flow**: Cryptographic proof of identity before access

#### 3. Dual-Channel Architecture
```
Email Channel (Async)     MCP Channel (Real-time)
      │                          │
      │  Authorization           │  Command Execution
      │  Long-form commands      │  Interactive sessions
      │  Audit logging           │  Job management
      │                          │
      └──────────┬───────────────┘
                 │
           MailMCP Server
```

#### 4. AI-Ready Design
- **MCP Protocol**: Native support for Model Context Protocol (AI agent integration)
- **LLM Processing**: Natural language command parsing
- **Structured Output**: JSON responses for programmatic consumption

#### 5. Interactive Terminal Support
- **PTY Emulation**: Full pseudo-terminal support for interactive commands
- **ncurses Compatible**: Works with menuconfig, top, vim, etc.
- **Job Control**: Background tasks with real-time I/O

### Architecture

```
┌─────────────────┐                    ┌─────────────────┐
│   Email Client  │                    │   MCP Client    │
│  (User Device)  │                    │  (AI/CLI/App)   │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
         │ Email (IMAP/SMTP)                    │ MCP Protocol (TLS)
         │                                      │
         ▼                                      ▼
┌─────────────────────────────────────────────────────────┐
│                    MailMCP Server                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   Email     │  │     MCP     │  │  Persistent │    │
│  │   Gateway   │  │   Server    │  │  SSH Tunnel │    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │  PGP Auth   │  │  Job Mgr    │  │  LLM Parser │    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
└─────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
   ┌──────────┐        ┌──────────┐        ┌──────────┐
   │  Server  │        │  Server  │        │  Server  │
   │  (local) │        │   (ovh)  │        │  (bage)  │
   └──────────┘        └──────────┘        └──────────┘
```

### Features

#### 1. Persistent SSH Connection Manager

MailMCP maintains persistent SSH connections using ControlMaster:

- Auto-reconnect on failure
- Connection pooling for multiple servers
- Socket-based communication (`/var/run/ssh-tunnel/{name}.sock`)

#### 2. PGP Authorization Flow

```
User                    MailMCP                 Admin
  │                        │                      │
  │ 1. Request Auth        │                      │
  │───────────────────────>│                      │
  │                        │ 2. Fetch pubkey      │
  │                        │   from keys.openpgp  │
  │                        │                      │
  │ 3. Challenge Email     │                      │
  │<───────────────────────│                      │
  │                        │                      │
  │ 4. Signed Challenge    │                      │
  │───────────────────────>│                      │
  │                        │ 5. Verify signature  │
  │                        │                      │
  │                        │ 6. Approval request  │
  │                        │─────────────────────>│
  │                        │                      │
  │                        │ 7. APPROVE email     │
  │                        │<─────────────────────│
  │                        │                      │
  │ 8. Token Email         │                      │
  │<───────────────────────│                      │
```

#### 3. Interactive Command Support

Supports ncurses-based applications:

```python
client = MailMCPClient()
job = client.job_start("ovh", "make menuconfig")

# Send navigation keys
client.job_input(job["job_id"], client.key("up"))
client.job_input(job["job_id"], client.key("enter"))
```

#### 4. Job Management

| Tool | Description |
|------|-------------|
| `job_start` | Start background job |
| `job_status` | Get job status |
| `job_output` | Get job output |
| `job_input` | Send input to job |
| `job_kill` | Kill running job |
| `job_list` | List all jobs |

### Installation

#### Quick Install (Recommended)

```bash
# Clone or download MailMCP
git clone https://github.com/your-repo/MailMCP.git
cd MailMCP

# Run installer
sudo ./install.sh
```

#### Manual Installation

```bash
# Install dependencies
apt install -y python3 python3-pip sshpass gnupg openssl

# Install Python packages
pip3 install python-gnupg requests

# Create directories
mkdir -p /opt/mailmcp
mkdir -p /etc/mailmcp/certs
mkdir -p /var/lib/mailmcp/{auth,keys,jobs,sockets}
mkdir -p /var/log/mailmcp

# Copy files
cp mailmcp_unified.py /opt/mailmcp/
cp mailmcp_client.py /opt/mailmcp/
cp mcp_client.py /opt/mailmcp/
chmod +x /opt/mailmcp/*.py

# Copy configuration
cp mailmcp.conf /etc/mailmcp/
cp servers.conf.example /etc/mailmcp/servers.conf

# Generate TLS certificate
openssl req -x509 -newkey rsa:2048 -keyout /etc/mailmcp/certs/key.pem \
    -out /etc/mailmcp/certs/cert.pem -days 365 -nodes \
    -subj "/CN=mailmcp"
chmod 600 /etc/mailmcp/certs/key.pem

# Create systemd service (or use install.sh)
systemctl enable mailmcp
systemctl start mailmcp
```

#### Client Setup

```bash
# Install GPG (Windows: Gpg4win, macOS: brew install gnupg)
apt install -y gnupg

# Setup client
python3 mailmcp_client.py setup your@email.com "Your Name"

# This will:
# 1. Generate GPG key
# 2. Upload to keys.openpgp.org
# 3. Save config to ~/.mailmcp/
```

### Configuration

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IMAP_SERVER` | imap.qq.com | IMAP server |
| `SMTP_SERVER` | smtp.qq.com | SMTP server |
| `EMAIL_USER` | - | Email username |
| `EMAIL_PASS` | - | Email password |
| `USE_IMAP_IDLE` | false | Use IMAP IDLE for real-time push |
| `EMAIL_CHECK_INTERVAL` | 60 | Check interval (seconds) |
| `ADMIN_EMAIL` | - | Admin email for approvals |
| `ALLOWED_SENDERS` | - | Comma-separated allowed emails |
| `MCP_PORT` | 18443 | MCP server port |
| `MCP_BIND_HOST` | 127.0.0.1 | MCP bind address |
| `IP_WHITELIST` | - | Comma-separated IPs |
| `IP_BLACKLIST` | - | Comma-separated blocked IPs |
| `RATE_LIMIT` | 60 | Requests per window |
| `RATE_LIMIT_WINDOW` | 60 | Window in seconds |
| `LLM_ENABLED` | false | Enable LLM parsing |
| `LLM_API_URL` | - | LLM API endpoint |
| `LLM_API_KEY` | - | LLM API key |
| `LLM_MODEL` | - | LLM model name |

#### Supported Email Providers

| Provider | IMAP Server | SMTP Server | IDLE Support |
|----------|-------------|-------------|--------------|
| QQ Mail | imap.qq.com | smtp.qq.com | ✅ |
| Gmail | imap.gmail.com | smtp.gmail.com | ✅ |
| Outlook.com | outlook.office365.com | smtp-mail.outlook.com | ✅ |
| Microsoft 365 | outlook.office365.com | smtp.office365.com | ✅ |
| 163 Mail | imap.163.com | smtp.163.com | ✅ |

**Note**: Gmail and Outlook.com require App Passwords, not your login password.

### API Reference

#### MCP Tools

```json
{
  "tools": [
    {"name": "ssh_exec", "description": "Execute command on server"},
    {"name": "ssh_disconnect", "description": "Disconnect SSH connection"},
    {"name": "ssh_list", "description": "List SSH connections"},
    {"name": "job_start", "description": "Start background job"},
    {"name": "job_status", "description": "Get job status"},
    {"name": "job_output", "description": "Get job output"},
    {"name": "job_input", "description": "Send input to job"},
    {"name": "job_kill", "description": "Kill running job"},
    {"name": "job_list", "description": "List all jobs"}
  ]
}
```

#### Example Usage

```python
from mcp_client import MailMCPClient

client = MailMCPClient(host='your-server.com', port=18443)

# List connections
connections = client.list_connections()

# Execute command
result = client.execute('ovh', 'uptime')

# Start interactive job
job = client.job_start('ovh', 'make menuconfig')

# Send input
client.job_input(job['job_id'], '\x1b[B')  # Down arrow

# Get output
output = client.job_output(job['job_id'])

# Check status
status = client.job_status(job['job_id'])
```

### Security

#### TLS Certificate

MailMCP uses TLS (Transport Layer Security) to encrypt MCP communication:

- **Self-signed certificate**: Generated automatically during installation
- **Location**: `/etc/mailmcp/certs/cert.pem` (public) and `/etc/mailmcp/certs/key.pem` (private)
- **Purpose**: Encrypts all MCP client-server communication
- **Validity**: 365 days (regenerate if expired)

```bash
# Regenerate TLS certificate
sudo openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/mailmcp/certs/key.pem \
    -out /etc/mailmcp/certs/cert.pem \
    -days 365 -nodes -subj "/CN=mailmcp"
sudo chmod 600 /etc/mailmcp/certs/key.pem
sudo systemctl restart mailmcp
```

**Note**: Since the certificate is self-signed, clients need to disable certificate verification:
```python
# Python client
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
```

For production use, consider using a CA-signed certificate (e.g., Let's Encrypt).

#### Command Sanitization

Dangerous characters are blocked:
- Shell operators: `;`, `&&`, `||`, `|`
- Command substitution: `` ` ``, `$(`, `${`
- Redirections: `>`, `<`, `>>`, `<<`
- Newlines: `\n`, `\r`

#### Dual Authentication

1. **IP Whitelist** - Bypass auth for trusted IPs
2. **Token + PGP Signature** - Required for non-whitelisted IPs

### Troubleshooting

#### Service fails to start

```bash
# Check logs
journalctl -u mailmcp -n 50

# Common issues:

# 1. TLS certificate missing
sudo mkdir -p /etc/mailmcp/certs
sudo openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/mailmcp/certs/key.pem \
    -out /etc/mailmcp/certs/cert.pem \
    -days 365 -nodes -subj "/CN=mailmcp"
sudo chmod 600 /etc/mailmcp/certs/key.pem

# 2. Servers config missing
sudo cp /etc/mailmcp/servers.conf.example /etc/mailmcp/servers.conf
# Edit servers.conf with your server details

# 3. Permission issues
sudo chown -R root:root /etc/mailmcp
sudo chown -R root:root /var/lib/mailmcp
```

#### MCP connection refused

```bash
# Check if service is running
systemctl status mailmcp

# Check if port is listening
ss -tlnp | grep 18443

# Check IP whitelist in /etc/mailmcp/mailmcp.conf
IP_WHITELIST=127.0.0.1,your_client_ip
```

---

<a name="中文"></a>
## 中文

### 概述

MailMCP 是一个安全的服务器管理系统，支持通过电子邮件或 MCP 协议控制远程服务器。主要特性：

- **PGP 授权认证** - 通过 keys.openpgp.org 进行公钥认证
- **持久 SSH 连接** - 使用 SSH ControlMaster 保持可靠连接
- **交互式命令支持** - 兼容 ncurses/menuconfig
- **作业管理** - 后台任务支持输入输出控制
- **LLM 集成** - 自然语言命令解析
- **安全加固** - IP 白名单、速率限制、命令过滤

### 创新亮点

MailMCP 引入了多项服务器管理创新方法：

#### 1. 邮件作为通用接口
- **零客户端需求**：从任何邮件客户端控制服务器（Gmail、Outlook、移动应用）
- **气隙兼容**：通过邮件网关工作，无需直接网络访问
- **审计追踪**：所有命令自动记录在邮件历史中

#### 2. 去中心化 PGP 认证
- **无中心权威**：使用 keys.openpgp.org 进行公钥分发
- **用户控制密钥**：用户拥有并管理自己的 PGP 密钥
- **挑战-响应流程**：访问前需提供加密身份证明

#### 3. 双通道架构
```
邮件通道 (异步)           MCP 通道 (实时)
      │                          │
      │  授权认证                │  命令执行
      │  长文本命令              │  交互式会话
      │  审计日志                │  作业管理
      │                          │
      └──────────┬───────────────┘
                 │
           MailMCP 服务器
```

#### 4. AI 就绪设计
- **MCP 协议**：原生支持模型上下文协议（AI 代理集成）
- **LLM 处理**：自然语言命令解析
- **结构化输出**：JSON 响应便于程序化处理

#### 5. 交互式终端支持
- **PTY 模拟**：完整的伪终端支持交互式命令
- **ncurses 兼容**：支持 menuconfig、top、vim 等
- **作业控制**：后台任务支持实时 I/O

### 架构

```
┌─────────────────┐                    ┌─────────────────┐
│   邮件客户端    │                    │   MCP 客户端    │
│  (用户设备)     │                    │  (AI/CLI/应用)  │
└────────┬────────┘                    └────────┬────────┘
         │                                      │
         │ 邮件 (IMAP/SMTP)                     │ MCP 协议 (TLS)
         │                                      │
         ▼                                      ▼
┌─────────────────────────────────────────────────────────┐
│                    MailMCP 服务端                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   邮件      │  │    MCP      │  │   持久      │    │
│  │   网关      │  │   服务器    │  │  SSH 隧道   │    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │  PGP 认证   │  │  作业管理   │  │  LLM 解析   │    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### 功能详解

#### 1. 持久 SSH 连接管理器

MailMCP 使用 ControlMaster 维护持久 SSH 连接：

- 故障自动重连
- 多服务器连接池
- Socket 通信 (`/var/run/ssh-tunnel/{name}.sock`)

#### 2. PGP 授权流程

```
用户                    MailMCP                 管理员
  │                        │                      │
  │ 1. 请求授权            │                      │
  │───────────────────────>│                      │
  │                        │ 2. 从 keys.openpgp   │
  │                        │    获取公钥          │
  │                        │                      │
  │ 3. 挑战邮件            │                      │
  │<───────────────────────│                      │
  │                        │                      │
  │ 4. 签名挑战            │                      │
  │───────────────────────>│                      │
  │                        │ 5. 验证签名          │
  │                        │                      │
  │                        │ 6. 审批请求          │
  │                        │─────────────────────>│
  │                        │                      │
  │                        │ 7. APPROVE 邮件      │
  │                        │<─────────────────────│
  │                        │                      │
  │ 8. Token 邮件          │                      │
  │<───────────────────────│                      │
```

#### 3. 交互式命令支持

支持 ncurses 应用：

```python
client = MailMCPClient()
job = client.job_start("ovh", "make menuconfig")

# 发送导航键
client.job_input(job["job_id"], client.key("up"))
client.job_input(job["job_id"], client.key("enter"))
```

#### 4. 作业管理

| 工具 | 描述 |
|------|------|
| `job_start` | 启动后台作业 |
| `job_status` | 获取作业状态 |
| `job_output` | 获取作业输出 |
| `job_input` | 发送输入到作业 |
| `job_kill` | 终止运行中的作业 |
| `job_list` | 列出所有作业 |

### 安装部署

#### 快速安装（推荐）

```bash
# 克隆或下载 MailMCP
git clone https://github.com/your-repo/MailMCP.git
cd MailMCP

# 运行安装脚本
sudo ./install.sh
```

#### 手动安装

```bash
# 安装依赖
apt install -y python3 python3-pip sshpass gnupg openssl

# 安装 Python 包
pip3 install python-gnupg requests

# 创建目录
mkdir -p /opt/mailmcp
mkdir -p /etc/mailmcp/certs
mkdir -p /var/lib/mailmcp/{auth,keys,jobs,sockets}
mkdir -p /var/log/mailmcp

# 复制文件
cp mailmcp_unified.py /opt/mailmcp/
cp mailmcp_client.py /opt/mailmcp/
cp mcp_client.py /opt/mailmcp/
chmod +x /opt/mailmcp/*.py

# 复制配置
cp mailmcp.conf /etc/mailmcp/
cp servers.conf.example /etc/mailmcp/servers.conf

# 生成 TLS 证书
openssl req -x509 -newkey rsa:2048 -keyout /etc/mailmcp/certs/key.pem \
    -out /etc/mailmcp/certs/cert.pem -days 365 -nodes \
    -subj "/CN=mailmcp"
chmod 600 /etc/mailmcp/certs/key.pem

# 创建 systemd 服务（或使用 install.sh）
systemctl enable mailmcp
systemctl start mailmcp
```

#### 客户端配置

```bash
# 安装 GPG (Windows: Gpg4win, macOS: brew install gnupg)
apt install -y gnupg

# 配置客户端
python3 mailmcp_client.py setup your@email.com "Your Name"

# 这将：
# 1. 生成 GPG 密钥
# 2. 上传到 keys.openpgp.org
# 3. 保存配置到 ~/.mailmcp/
```

### 配置说明

#### 环境变量

| 变量 | 默认值 | 描述 |
|------|--------|------|
| `IMAP_SERVER` | imap.qq.com | IMAP 服务器 |
| `SMTP_SERVER` | smtp.qq.com | SMTP 服务器 |
| `EMAIL_USER` | - | 邮箱用户名 |
| `EMAIL_PASS` | - | 邮箱密码 |
| `USE_IMAP_IDLE` | false | 使用 IMAP IDLE 实时推送 |
| `EMAIL_CHECK_INTERVAL` | 60 | 检查间隔（秒） |
| `ADMIN_EMAIL` | - | 管理员邮箱 |
| `ALLOWED_SENDERS` | - | 允许的发件人（逗号分隔） |
| `MCP_PORT` | 18443 | MCP 服务端口 |
| `MCP_BIND_HOST` | 127.0.0.1 | MCP 绑定地址 |
| `IP_WHITELIST` | - | IP 白名单（逗号分隔） |
| `IP_BLACKLIST` | - | IP 黑名单（逗号分隔） |
| `RATE_LIMIT` | 60 | 窗口内请求数 |
| `RATE_LIMIT_WINDOW` | 60 | 窗口秒数 |
| `LLM_ENABLED` | false | 启用 LLM 解析 |
| `LLM_API_URL` | - | LLM API 地址 |
| `LLM_API_KEY` | - | LLM API 密钥 |
| `LLM_MODEL` | - | LLM 模型名称 |

#### 支持的邮箱服务商

| 服务商 | IMAP 服务器 | SMTP 服务器 | IDLE 支持 |
|--------|-------------|-------------|-----------|
| QQ 邮箱 | imap.qq.com | smtp.qq.com | ✅ |
| Gmail | imap.gmail.com | smtp.gmail.com | ✅ |
| Outlook.com | outlook.office365.com | smtp-mail.outlook.com | ✅ |
| Microsoft 365 | outlook.office365.com | smtp.office365.com | ✅ |
| 163 邮箱 | imap.163.com | smtp.163.com | ✅ |

**注意**：Gmail 和 Outlook.com 需要使用应用专用密码，而非登录密码。

### 安全机制

#### TLS 证书

MailMCP 使用 TLS（传输层安全）加密 MCP 通信：

- **自签名证书**：安装时自动生成
- **位置**：`/etc/mailmcp/certs/cert.pem`（公钥）和 `/etc/mailmcp/certs/key.pem`（私钥）
- **用途**：加密所有 MCP 客户端与服务端之间的通信
- **有效期**：365 天（过期需重新生成）

```bash
# 重新生成 TLS 证书
sudo openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/mailmcp/certs/key.pem \
    -out /etc/mailmcp/certs/cert.pem \
    -days 365 -nodes -subj "/CN=mailmcp"
sudo chmod 600 /etc/mailmcp/certs/key.pem
sudo systemctl restart mailmcp
```

**注意**：由于证书是自签名的，客户端需要禁用证书验证：
```python
# Python 客户端
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
```

生产环境建议使用 CA 签名的证书（如 Let's Encrypt）。

#### 命令过滤

危险字符被阻止：
- Shell 操作符: `;`, `&&`, `||`, `|`
- 命令替换: `` ` ``, `$(`, `${`
- 重定向: `>`, `<`, `>>`, `<<`
- 换行符: `\n`, `\r`

#### 双重认证

1. **IP 白名单** - 白名单 IP 可跳过认证
2. **Token + PGP 签名** - 非 IP 白名单需要

### 故障排除

#### 服务启动失败

```bash
# 查看日志
journalctl -u mailmcp -n 50

# 常见问题：

# 1. TLS 证书缺失
sudo mkdir -p /etc/mailmcp/certs
sudo openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/mailmcp/certs/key.pem \
    -out /etc/mailmcp/certs/cert.pem \
    -days 365 -nodes -subj "/CN=mailmcp"
sudo chmod 600 /etc/mailmcp/certs/key.pem

# 2. 服务器配置缺失
sudo cp /etc/mailmcp/servers.conf.example /etc/mailmcp/servers.conf
# 编辑 servers.conf 添加您的服务器信息

# 3. 权限问题
sudo chown -R root:root /etc/mailmcp
sudo chown -R root:root /var/lib/mailmcp
```

#### MCP 连接被拒绝

```bash
# 检查服务是否运行
systemctl status mailmcp

# 检查端口是否监听
ss -tlnp | grep 18443

# 检查 /etc/mailmcp/mailmcp.conf 中的 IP 白名单
IP_WHITELIST=127.0.0.1,您的客户端IP
```

### 许可证

MIT License

### 贡献

欢迎提交 Issue 和 Pull Request！
