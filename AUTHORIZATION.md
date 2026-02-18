# MailMCP Authorization Guide / MailMCP 授权指南

[English](#english) | [中文](#中文)

---

<a name="english"></a>

## English

### Authorization Overview

MailMCP uses **PGP + Token Dual Authentication** for maximum security:

1. **Authorization Phase**: Email-based PGP verification + Admin approval
2. **MCP Access Phase**: Token + PGP signature for each request

### Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Authorization Phase                       │
├─────────────────────────────────────────────────────────────┤
│  1. User requests authorization via email                    │
│  2. Server fetches PGP public key from keys.openpgp.org      │
│  3. Challenge-response verification                          │
│  4. Admin approval required                                  │
│  5. Token generated and bound to PGP fingerprint             │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    MCP Access Phase                          │
├─────────────────────────────────────────────────────────────┤
│  Each MCP request requires:                                  │
│  - Token (from authorization)                                │
│  - Timestamp (valid for 5 minutes)                           │
│  - Nonce (prevents replay attacks)                           │
│  - PGP Signature (proves private key ownership)              │
│                                                              │
│  Message format: TOKEN:TIMESTAMP:NONCE                       │
│  Signature: PGP detach-sign of the message                   │
└─────────────────────────────────────────────────────────────┘
```

### Security Benefits

| Attack Scenario | Protection |
|-----------------|------------|
| Token leaked | ✅ Cannot use without PGP private key |
| Replay attack | ✅ Nonce prevents reuse, timestamp limits window |
| Man-in-the-middle | ✅ TLS + PGP signature |
| Brute force | ✅ Rate limiting + IP whitelist |

### Step-by-Step Authorization

#### Step 1: Generate PGP Key

```bash
gpg --full-generate-key
# Choose RSA 4096 bits, your email, and a strong passphrase
```

#### Step 2: Publish Public Key

```bash
# Get your key ID
gpg --list-keys

# Upload to keys.openpgp.org
gpg --send-keys --keyserver keys.openpgp.org YOUR_KEY_ID

# Or upload via web: https://keys.openpgp.org/upload
# Verify your email after upload
```

#### Step 3: Request Authorization

Send email to MailMCP:

```
To: mailmcp@example.com
Subject: Authorization Request
Body: request authorization
```

#### Step 4: Sign Challenge

You'll receive a challenge. Sign it:

```bash
echo "CHALLENGE_CODE" | gpg --clearsign
```

Reply with:

```
SIGNATURE: [your signed challenge]
```

#### Step 5: Wait for Admin Approval

After signature verification, wait for admin approval.

#### Step 6: Receive Token

You'll receive:

```
Your Token: xxxxxxxxxxxxxxxxxxxx
PGP Fingerprint: ABCD1234...
```

### Using MCP Client

#### Setup

```bash
export MCP_TOKEN="your_token"
export PGP_KEY_ID="your_email@example.com"
export MCP_HOST="localhost"
export MCP_PORT="18443"
```

#### Python Client

```python
from mcp_client import MailMCPClient

client = MailMCPClient(
    host="localhost",
    port=18443,
    token="your_token",
    pgp_key_id="your_email@example.com"
)

# Execute command
result = client.execute("local", "hostname && uptime")
print(result)
```

#### Command Line

```bash
python mcp_client.py
```

### Manual MCP Request

```bash
# Create message
TOKEN="your_token"
TIMESTAMP=$(date +%s)
NONCE=$(openssl rand -hex 16)
MESSAGE="${TOKEN}:${TIMESTAMP}:${NONCE}"

# Sign with GPG
SIGNATURE=$(echo -n "$MESSAGE" | gpg --default-key your@email.com --armor --detach-sign)

# Send request
# Include: token, timestamp, nonce, pgp_signature in JSON params
```

---

<a name="中文"></a>

## 中文

### 授权概述

MailMCP 使用 **PGP + Token 双重认证** 实现最高安全性：

1. **授权阶段**：基于邮件的 PGP 验证 + 管理员审批
2. **MCP 访问阶段**：每次请求需要 Token + PGP 签名

### 安全架构

```
┌─────────────────────────────────────────────────────────────┐
│                      授权阶段                                │
├─────────────────────────────────────────────────────────────┤
│  1. 用户通过邮件请求授权                                      │
│  2. 服务器从 keys.openpgp.org 获取 PGP 公钥                  │
│  3. 挑战码验证                                               │
│  4. 管理员审批                                               │
│  5. 生成 Token，绑定 PGP 指纹                                │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    MCP 访问阶段                              │
├─────────────────────────────────────────────────────────────┤
│  每次 MCP 请求需要：                                          │
│  - Token（来自授权）                                          │
│  - 时间戳（5分钟内有效）                                      │
│  - Nonce（防止重放攻击）                                      │
│  - PGP 签名（证明拥有私钥）                                   │
│                                                              │
│  消息格式：TOKEN:TIMESTAMP:NONCE                              │
│  签名：消息的 PGP 分离签名                                    │
└─────────────────────────────────────────────────────────────┘
```

### 安全优势

| 攻击场景 | 防护效果 |
|----------|----------|
| Token 泄露 | ✅ 无私钥无法使用 |
| 重放攻击 | ✅ Nonce 防止重复，时间戳限制窗口 |
| 中间人攻击 | ✅ TLS + PGP 签名 |
| 暴力破解 | ✅ 速率限制 + IP 白名单 |

### 授权步骤

#### 步骤1：生成 PGP 密钥

```bash
gpg --full-generate-key
# 选择 RSA 4096 位，填写邮箱和强密码
```

#### 步骤2：发布公钥

```bash
# 获取密钥 ID
gpg --list-keys

# 上传到 keys.openpgp.org
gpg --send-keys --keyserver keys.openpgp.org YOUR_KEY_ID

# 或通过网页上传：https://keys.openpgp.org/upload
# 上传后验证邮箱
```

#### 步骤3：请求授权

发送邮件到 MailMCP：

```
收件人: mailmcp@example.com
主题: 请求授权
内容: 请求授权
```

#### 步骤4：签名挑战码

收到挑战码后签名：

```bash
echo "挑战码" | gpg --clearsign
```

回复：

```
SIGNATURE: [您签名的挑战码]
```

#### 步骤5：等待管理员审批

签名验证通过后，等待管理员审批。

#### 步骤6：接收 Token

您将收到：

```
Your Token: xxxxxxxxxxxxxxxxxxxx
PGP Fingerprint: ABCD1234...
```

### 使用 MCP 客户端

#### 配置

```bash
export MCP_TOKEN="your_token"
export PGP_KEY_ID="your_email@example.com"
export MCP_HOST="localhost"
export MCP_PORT="18443"
```

#### Python 客户端

```python
from mcp_client import MailMCPClient

client = MailMCPClient(
    host="localhost",
    port=18443,
    token="your_token",
    pgp_key_id="your_email@example.com"
)

# 执行命令
result = client.execute("local", "hostname && uptime")
print(result)
```

#### 命令行

```bash
python mcp_client.py
```

---

## Admin Commands / 管理员命令

| Command | Description |
|---------|-------------|
| `APPROVE user@example.com` | Approve pending authorization |
| `REJECT user@example.com` | Reject pending authorization |
| `REVOKE user@example.com` | Revoke existing token |

| 命令 | 说明 |
|------|------|
| `APPROVE user@example.com` | 批准待审批授权 |
| `REJECT user@example.com` | 拒绝待审批授权 |
| `REVOKE user@example.com` | 撤销已有令牌 |

---

## Environment Variables / 环境变量

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_HOST` | MCP Server host | localhost |
| `MCP_PORT` | MCP Server port | 18443 |
| `MCP_TOKEN` | Authorization token | (required) |
| `PGP_KEY_ID` | PGP key ID for signing | (optional) |
| `USE_DUAL_AUTH` | Enable dual auth | true |
| `SIGNATURE_EXPIRE` | Signature validity (seconds) | 300 |

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `MCP_HOST` | MCP 服务器地址 | localhost |
| `MCP_PORT` | MCP 服务器端口 | 18443 |
| `MCP_TOKEN` | 授权令牌 | (必填) |
| `PGP_KEY_ID` | PGP 密钥 ID | (可选) |
| `USE_DUAL_AUTH` | 启用双重认证 | true |
| `SIGNATURE_EXPIRE` | 签名有效期(秒) | 300 |

---

## Security Notes / 安全说明

- Challenge codes expire in 10 minutes / 挑战码10分钟内有效
- Tokens expire in 30 days / 令牌30天有效
- Signatures expire in 5 minutes / 签名5分钟内有效
- Nonce prevents replay attacks / Nonce 防止重放攻击
- Admin approval required / 需要管理员审批
- IP whitelist/blacklist supported / 支持IP白名单/黑名单
- Rate limiting enabled / 启用速率限制
- TLS encrypted communication / TLS加密通信
- Keep your tokens and private key secure / 请妥善保管令牌和私钥
