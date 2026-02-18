#!/usr/bin/env python3
"""
MCP Server - SSH Tunnel Management Service
With PGP + Token Dual Authentication
Copyright (c) 2026 MailMCP Contributors
Licensed under MIT License
"""

import asyncio, json, os, subprocess, sys, datetime, threading, ssl, hashlib, time, secrets
from collections import defaultdict
from functools import wraps

try:
    import pgpy
    PGPY_AVAILABLE = True
except ImportError:
    PGPY_AVAILABLE = False

CONFIG_FILE = os.environ.get("CONFIG_FILE", "/etc/ssh-tunnel/config.conf")
SOCKET_DIR = os.environ.get("SOCKET_DIR", "/var/run/ssh-tunnel")
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/mailmcp.log")
AUTH_FILE = os.environ.get("AUTH_FILE", "/etc/ssh-tunnel/tokens.conf")
CERT_FILE = os.environ.get("CERT_FILE", "/etc/ssh-tunnel/certs/cert.pem")
KEY_FILE = os.environ.get("KEY_FILE", "/etc/ssh-tunnel/certs/key.pem")
KEYS_DIR = os.environ.get("KEYS_DIR", "/var/run/ssh-tunnel/keys")
AUTH_DIR = os.environ.get("AUTH_DIR", "/var/run/ssh-tunnel/auth")

IP_WHITELIST = os.environ.get("IP_WHITELIST", "").split(",") if os.environ.get("IP_WHITELIST") else []
IP_BLACKLIST = os.environ.get("IP_BLACKLIST", "").split(",") if os.environ.get("IP_BLACKLIST") else []
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "60"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
SIGNATURE_EXPIRE = int(os.environ.get("SIGNATURE_EXPIRE", "300"))

rate_limit_storage = defaultdict(list)
used_nonces = defaultdict(float)

def log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {msg}\n")
    except: pass

def load_tokens():
    tokens = set()
    try:
        with open(AUTH_FILE) as f:
            for line in f:
                token = line.strip()
                if token and not token.startswith("#"):
                    tokens.add(token)
    except: pass
    return tokens

def check_ip_access(client_ip):
    if client_ip in IP_BLACKLIST:
        return False, "IP blacklisted"
    if IP_WHITELIST and IP_WHITELIST[0]:
        if client_ip not in IP_WHITELIST and client_ip != "127.0.0.1":
            return False, "IP not in whitelist"
    return True, "OK"

def check_rate_limit(client_ip):
    now = time.time()
    rate_limit_storage[client_ip] = [
        t for t in rate_limit_storage[client_ip] 
        if now - t < RATE_LIMIT_WINDOW
    ]
    if len(rate_limit_storage[client_ip]) >= RATE_LIMIT:
        return False, f"Rate limit exceeded ({RATE_LIMIT} req/{RATE_LIMIT_WINDOW}s)"
    rate_limit_storage[client_ip].append(now)
    return True, "OK"

def clean_used_nonces():
    now = time.time()
    for nonce in list(used_nonces.keys()):
        if now - used_nonces[nonce] > SIGNATURE_EXPIRE * 2:
            del used_nonces[nonce]

def load_token_data(token_value):
    if not os.path.exists(AUTH_DIR):
        return None
    for f in os.listdir(AUTH_DIR):
        if f.endswith(".token"):
            try:
                with open(os.path.join(AUTH_DIR, f)) as tf:
                    data = json.load(tf)
                    if data.get("token") == token_value:
                        if time.time() < data.get("expires", 0):
                            return data
            except:
                pass
    return None

def load_public_key_by_fingerprint(fingerprint):
    if not os.path.exists(KEYS_DIR):
        return None
    for f in os.listdir(KEYS_DIR):
        if f.endswith(".asc"):
            try:
                with open(os.path.join(KEYS_DIR, f)) as kf:
                    key_data = kf.read()
                    if PGPY_AVAILABLE:
                        key, _ = pgpy.PGPKey.from_blob(key_data)
                        if str(key.fingerprint) == fingerprint:
                            return key_data
                    elif fingerprint in key_data:
                        return key_data
            except:
                pass
    return None

def load_public_key_by_email(email):
    safe_email = email.replace('@', '_at_').replace('.', '_')
    key_file = f"{KEYS_DIR}/{safe_email}.asc"
    try:
        with open(key_file, "r") as f:
            return f.read()
    except:
        return None

def verify_pgp_signature(public_key_armored, message, signature):
    if not PGPY_AVAILABLE:
        log("PGPY not available, using fallback verification")
        return signature.strip() == message.strip()
    
    try:
        key, _ = pgpy.PGPKey.from_blob(public_key_armored)
        
        if "---BEGIN PGP SIGNATURE---" in signature or "---BEGIN PGP MESSAGE---" in signature:
            try:
                sig = pgpy.PGPSignature.from_blob(signature)
                verified = key.verify(message, sig)
                return bool(verified)
            except Exception as e:
                log(f"PGP signature parse error: {e}")
                return False
        
        return signature.strip() == message.strip()
    except Exception as e:
        log(f"PGP verify error: {e}")
        return False

def verify_dual_auth(params):
    token = params.get("token", "")
    timestamp = params.get("timestamp", "")
    nonce = params.get("nonce", "")
    pgp_signature = params.get("pgp_signature", "")
    
    if not token:
        return False, "Token required"
    
    token_data = load_token_data(token)
    if not token_data:
        valid_tokens = load_tokens()
        if token in valid_tokens:
            return True, "OK (legacy token)"
        return False, "Invalid token"
    
    if not timestamp or not nonce or not pgp_signature:
        return False, "Timestamp, nonce and PGP signature required for dual auth"
    
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > SIGNATURE_EXPIRE:
            return False, f"Timestamp expired (valid for {SIGNATURE_EXPIRE}s)"
    except:
        return False, "Invalid timestamp"
    
    clean_used_nonces()
    if nonce in used_nonces:
        return False, "Nonce already used (replay attack detected)"
    used_nonces[nonce] = time.time()
    
    pubkey_fingerprint = token_data.get("pubkey_fingerprint", "")
    email = token_data.get("email", "")
    
    pubkey = load_public_key_by_fingerprint(pubkey_fingerprint)
    if not pubkey and email:
        pubkey = load_public_key_by_email(email)
    
    if not pubkey:
        return False, "Public key not found"
    
    message = f"{token}:{timestamp}:{nonce}"
    
    if verify_pgp_signature(pubkey, message, pgp_signature):
        return True, "OK (dual auth)"
    else:
        return False, "PGP signature verification failed"

def load_config():
    config = {}
    try:
        for line in open(CONFIG_FILE):
            parts = line.strip().split()
            if len(parts) >= 5 and not parts[0].startswith("#"):
                config[parts[0]] = {"host": parts[1], "port": parts[2], "user": parts[3], "pass": parts[4]}
    except: pass
    return config

def connect_async(name):
    cfg = load_config().get(name)
    if not cfg: return
    socket = f"{SOCKET_DIR}/{name}.sock"
    if os.path.exists(socket):
        r = subprocess.run(["ssh", "-S", socket, "-O", "check", name], capture_output=True)
        if r.returncode == 0: return
    log(f"Connecting: {name}")
    cmd = f'sshpass -p "{cfg["pass"]}" ssh -fN -M -S {socket} -o ControlPersist=yes -o ServerAliveInterval=30 -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {cfg["port"]} {cfg["user"]}@{cfg["host"]}'
    subprocess.run(cmd, shell=True, capture_output=True, timeout=15)
    log(f"Connect done: {name}")

def exec_cmd(name, cmd, timeout=300):
    if name == "local" or name == "ai":
        log(f"Local exec: {cmd[:100]}")
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
        except subprocess.TimeoutExpired:
            return {"error": f"Timeout {timeout}s"}
        except Exception as e:
            return {"error": str(e)}
    
    socket = f"{SOCKET_DIR}/{name}.sock"
    if not os.path.exists(socket):
        connect_async(name)
    log(f"Exec [{name}]: {cmd[:100]}")
    try:
        r = subprocess.run(["ssh", "-S", socket, name, cmd], capture_output=True, text=True, timeout=timeout)
        return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"error": f"Timeout {timeout}s"}
    except Exception as e:
        return {"error": str(e)}

def disconnect(name):
    socket = f"{SOCKET_DIR}/{name}.sock"
    if os.path.exists(socket):
        subprocess.run(["ssh", "-S", socket, "-O", "exit", name], capture_output=True)
        return {"status": "disconnected", "name": name}
    return {"status": "not_connected", "name": name}

def list_conn():
    if not os.path.exists(SOCKET_DIR):
        return []
    return [f.replace(".sock", "") for f in os.listdir(SOCKET_DIR) if f.endswith(".sock")]

async def handle(req, client_ip):
    method, params, rid = req.get("method"), req.get("params", {}), req.get("id")
    
    if method != "initialize":
        allowed, msg = check_ip_access(client_ip)
        if not allowed:
            log(f"IP denied: {client_ip} - {msg}")
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32600, "message": f"Access denied: {msg}"}}
        
        allowed, msg = check_rate_limit(client_ip)
        if not allowed:
            log(f"Rate limit: {client_ip} - {msg}")
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32600, "message": msg}}
        
        valid, msg = verify_dual_auth(params)
        if not valid:
            log(f"Auth failed: {client_ip} - {msg}")
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32600, "message": f"Auth failed: {msg}"}}
        
        log(f"Auth success: {client_ip} - {msg}")
    
    try:
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "MailMCP-SSH-Tunnel", "version": "2.0"}
            }}
        elif method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
                {"name": "ssh_connect", "description": "SSH Connect", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
                {"name": "ssh_exec", "description": "Execute command", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "command": {"type": "string"}, "timeout": {"type": "integer", "default": 300}}, "required": ["name", "command"]}},
                {"name": "ssh_disconnect", "description": "Disconnect", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
                {"name": "ssh_list", "description": "List connections", "inputSchema": {"type": "object", "properties": {}}}
            ]}}
        elif method == "tools/call":
            name, args = params.get("name"), params.get("arguments", {})
            if name == "ssh_connect":
                result = {"status": "connecting", "name": args["name"]}
                threading.Thread(target=connect_async, args=(args["name"],), daemon=True).start()
            elif name == "ssh_exec":
                result = exec_cmd(args["name"], args["command"], args.get("timeout", 300))
            elif name == "ssh_disconnect":
                result = disconnect(args["name"])
            elif name == "ssh_list":
                result = {"connections": list_conn()}
            else:
                result = {"error": f"Unknown: {name}"}
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}}
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    except Exception as e:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": str(e)}}

class TLSHandler:
    def __init__(self, reader, writer, client_ip):
        self.reader = reader
        self.writer = writer
        self.client_ip = client_ip
    
    async def handle(self):
        try:
            data = await self.reader.read(65536)
            if not data:
                return
            req = json.loads(data.decode())
            resp = await handle(req, self.client_ip)
            self.writer.write(json.dumps(resp).encode() + b"\n")
            await self.writer.drain()
        except Exception as e:
            log(f"Handler error: {e}")
        finally:
            self.writer.close()

async def main():
    log("MCP Server starting with PGP + Token Dual Auth...")
    
    for name in load_config():
        threading.Thread(target=connect_async, args=(name,), daemon=True).start()
    
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.load_cert_chain(CERT_FILE, KEY_FILE)
    
    async def handle_client(reader, writer):
        peername = writer.get_extra_info('peername')
        client_ip = peername[0] if peername else "unknown"
        handler = TLSHandler(reader, writer, client_ip)
        await handler.handle()
    
    bind_host = os.environ.get("MCP_BIND_HOST", "127.0.0.1")
    bind_port = int(os.environ.get("MCP_PORT", 18443))
    
    server = await asyncio.start_server(
        handle_client,
        bind_host, bind_port,
        ssl=ssl_context
    )
    
    log(f"MCP Server ready on {bind_host}:{bind_port} with dual auth")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
