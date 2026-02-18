#!/usr/bin/env python3
"""
MailMCP - Enhanced Key Exchange with PGP Support
Copyright (c) 2026 MailMCP Contributors
Licensed under MIT License
"""

import os, json, time, secrets, re, base64, subprocess, tempfile

KEYS_DIR = os.environ.get("KEYS_DIR", "/var/run/ssh-tunnel/keys")
AUTH_DIR = os.environ.get("AUTH_DIR", "/var/run/ssh-tunnel/auth")

os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(AUTH_DIR, exist_ok=True)

# ============ PGP 加密模块 ============

def encrypt_with_pgp(message, public_key_armor):
    """使用 PGP 公钥加密消息"""
    try:
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.asc', delete=False) as key_file:
            key_file.write(public_key_armor)
            key_path = key_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as msg_file:
            msg_file.write(message)
            msg_path = msg_file.name
        
        output_path = msg_path + '.gpg'
        
        # 导入公钥
        import_result = subprocess.run(
            ['gpg', '--import', key_path],
            capture_output=True, text=True
        )
        
        # 加密消息
        encrypt_result = subprocess.run(
            ['gpg', '--encrypt', '--armor', '--always-trust', 
             '--output', output_path, msg_path],
            capture_output=True, text=True
        )
        
        # 读取加密结果
        if os.path.exists(output_path):
            with open(output_path, 'r') as f:
                encrypted = f.read()
            # 清理临时文件
            os.unlink(key_path)
            os.unlink(msg_path)
            os.unlink(output_path)
            return encrypted
        
    except Exception as e:
        print(f"PGP encrypt error: {e}")
    
    return None

def verify_pgp_signature(message, signature, public_key_armor):
    """验证 PGP 签名"""
    try:
        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.asc', delete=False) as key_file:
            key_file.write(public_key_armor)
            key_path = key_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as msg_file:
            msg_file.write(message)
            msg_path = msg_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sig', delete=False) as sig_file:
            sig_file.write(signature)
            sig_path = sig_file.name
        
        # 导入公钥
        subprocess.run(['gpg', '--import', key_path], capture_output=True)
        
        # 验证签名
        result = subprocess.run(
            ['gpg', '--verify', sig_path, msg_path],
            capture_output=True, text=True
        )
        
        # 清理
        os.unlink(key_path)
        os.unlink(msg_path)
        os.unlink(sig_path)
        
        return result.returncode == 0
        
    except Exception as e:
        print(f"PGP verify error: {e}")
    
    return False

def decrypt_with_pgp(encrypted_message, private_key_passphrase=None):
    """使用 PGP 私钥解密消息（服务端需要私钥）"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.gpg', delete=False) as f:
            f.write(encrypted_message)
            input_path = f.name
        
        cmd = ['gpg', '--decrypt', input_path]
        if private_key_passphrase:
            cmd = ['gpg', '--batch', '--passphrase', private_key_passphrase, '--decrypt', input_path]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        os.unlink(input_path)
        
        if result.returncode == 0:
            return result.stdout
        
    except Exception as e:
        print(f"PGP decrypt error: {e}")
    
    return None

# ============ 增强版密钥交换 ============

def generate_secure_key():
    """生成安全密钥"""
    return secrets.token_urlsafe(32)  # 43字符，256位

def save_key_exchange(email, key_id, key, key_type="xor"):
    """保存密钥交换记录"""
    key_file = f"{KEYS_DIR}/{key_id}.json"
    with open(key_file, "w") as f:
        json.dump({
            "key_id": key_id,
            "key": key,
            "email": email,
            "type": key_type,
            "created": time.time(),
            "expires": time.time() + 3600,  # 1小时
            "used": False
        }, f)

def get_key_exchange(key_id):
    """获取密钥交换记录"""
    key_file = f"{KEYS_DIR}/{key_id}.json"
    try:
        with open(key_file, "r") as f:
            data = json.load(f)
            if time.time() < data["expires"] and not data["used"]:
                return data
    except:
        pass
    return None

def mark_key_used(key_id):
    """标记密钥已使用"""
    key_file = f"{KEYS_DIR}/{key_id}.json"
    try:
        with open(key_file, "r") as f:
            data = json.load(f)
        data["used"] = True
        with open(key_file, "w") as f:
            json.dump(data, f)
    except:
        pass

# ============ XOR 加密（简化版，用于快速加密） ============

def xor_encrypt(message, key):
    """XOR 加密"""
    key_bytes = key.encode() if isinstance(key, str) else key
    message_bytes = message.encode() if isinstance(message, str) else message
    result = bytearray()
    for i, byte in enumerate(message_bytes):
        result.append(byte ^ key_bytes[i % len(key_bytes)])
    return base64.b64encode(result).decode()

def xor_decrypt(encrypted_b64, key):
    """XOR 解密"""
    try:
        encrypted = base64.b64decode(encrypted_b64)
        key_bytes = key.encode() if isinstance(key, str) else key
        result = bytearray()
        for i, byte in enumerate(encrypted):
            result.append(byte ^ key_bytes[i % len(key_bytes)])
        return result.decode()
    except:
        return None

# ============ 使用示例 ============

if __name__ == "__main__":
    print("=== MailMCP 密钥交换模块 ===\n")
    
    # 1. 生成密钥
    key_id = secrets.token_hex(8)
    key = generate_secure_key()
    print(f"Key ID: {key_id}")
    print(f"Key: {key}")
    
    # 2. XOR 加密测试
    message = "敏感命令: rm -rf /tmp/test"
    encrypted = xor_encrypt(message, key)
    print(f"\n加密后: {encrypted[:50]}...")
    
    decrypted = xor_decrypt(encrypted, key)
    print(f"解密后: {decrypted}")
    
    # 3. PGP 加密需要 gpg 命令行工具
    print("\nPGP 加密需要安装 GnuPG:")
    print("  Ubuntu: apt install gnupg")
    print("  macOS: brew install gnupg")
    print("  Windows: choco install gnupg")
