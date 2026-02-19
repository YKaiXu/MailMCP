#!/usr/bin/env python3
"""
MailMCP - Unified Email Interface for Server Management
With PGP Authorization + IP Whitelist + Interactive Commands
Copyright (c) 2026 MailMCP Contributors
Licensed under MIT License

SECURITY: This version includes security hardening
Supports: pgpy (Python <3.13) or python-gnupg (Python 3.13+)
"""

import asyncio, imaplib, smtplib, ssl, json, hashlib, time, secrets, os, re, requests, subprocess, threading, datetime, socket, pty, select, fcntl, struct, termios, shlex
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import message_from_bytes
from email.header import decode_header
from collections import defaultdict
from typing import Dict, Optional, Any

PGPY_AVAILABLE = False
GNUPG_AVAILABLE = False

try:
    import pgpy
    PGPY_AVAILABLE = True
except ImportError:
    pass

if not PGPY_AVAILABLE:
    try:
        import gnupg
        GNUPG_AVAILABLE = True
    except ImportError:
        pass

# ============ Configuration File Loader ============
def load_config_file(config_path="/etc/ssh-tunnel/mailmcp.conf"):
    config = {}
    try:
        with open(config_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    except Exception as e:
        pass
    return config

_config = load_config_file()

def get_config(key, default=""):
    return os.environ.get(key, _config.get(key, default))

# ============ Configuration ============
IMAP_SERVER = get_config("IMAP_SERVER", "imap.qq.com")
SMTP_SERVER = get_config("SMTP_SERVER", "smtp.qq.com")
EMAIL_USER = get_config("EMAIL_USER", "")
EMAIL_PASS = get_config("EMAIL_PASS", "")
ALLOWED_SENDERS = get_config("ALLOWED_SENDERS", "")
ADMIN_EMAIL = get_config("ADMIN_EMAIL", "")

USE_IMAP_IDLE = get_config("USE_IMAP_IDLE", "false").lower() == "true"
EMAIL_CHECK_INTERVAL = int(get_config("EMAIL_CHECK_INTERVAL", "60"))

LLM_ENABLED = get_config("LLM_ENABLED", "false").lower() == "true"
LLM_API_URL = get_config("LLM_API_URL", "")
LLM_API_KEY = get_config("LLM_API_KEY", "")
LLM_MODEL = get_config("LLM_MODEL", "")

LOG_FILE = get_config("LOG_FILE", "/var/log/mailmcp.log")
AUTH_DIR = get_config("AUTH_DIR", "/var/run/ssh-tunnel/auth")
KEYS_DIR = get_config("KEYS_DIR", "/var/run/ssh-tunnel/keys")
CONFIG_FILE = get_config("CONFIG_FILE", "/etc/ssh-tunnel/config.conf")
SOCKET_DIR = get_config("SOCKET_DIR", "/var/run/ssh-tunnel")
CERT_FILE = get_config("CERT_FILE", "/etc/ssh-tunnel/certs/cert.pem")
KEY_FILE = get_config("KEY_FILE", "/etc/ssh-tunnel/certs/key.pem")
JOBS_DIR = get_config("JOBS_DIR", "/var/run/ssh-tunnel/jobs")
GNUPG_HOME = get_config("GNUPG_HOME", os.path.expanduser("~/.gnupg"))

ip_whitelist_str = get_config("IP_WHITELIST", "")
IP_WHITELIST = ip_whitelist_str.split(",") if ip_whitelist_str else []
ip_blacklist_str = get_config("IP_BLACKLIST", "")
IP_BLACKLIST = ip_blacklist_str.split(",") if ip_blacklist_str else []
RATE_LIMIT = int(get_config("RATE_LIMIT", "60"))
RATE_LIMIT_WINDOW = int(get_config("RATE_LIMIT_WINDOW", "60"))
SIGNATURE_EXPIRE = int(get_config("SIGNATURE_EXPIRE", "300"))
MCP_BIND_HOST = get_config("MCP_BIND_HOST", "127.0.0.1")
MCP_PORT = int(get_config("MCP_PORT", "18443"))

for d in [AUTH_DIR, KEYS_DIR, SOCKET_DIR, JOBS_DIR]:
    os.makedirs(d, exist_ok=True)

rate_limit_storage = defaultdict(list)
used_nonces = {}
nonces_lock = threading.Lock()

# ============ Security Helpers ============
def sanitize_command(cmd):
    dangerous = [";", "&&", "||", "|", "`", "$(", "${", ">", "<", ">>", "<<", "\n", "\r"]
    for d in dangerous:
        if d in cmd:
            return None, f"Dangerous character detected: {d}"
    return cmd, None

def log_safe(msg):
    safe_msg = msg.replace(EMAIL_PASS, "***").replace(LLM_API_KEY, "***")
    for key in ["pass", "password", "secret", "token"]:
        if key in safe_msg.lower():
            safe_msg = re.sub(rf'({key}["\s:=]+)([^\s"]+)', rf'\1***', safe_msg, flags=re.IGNORECASE)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {safe_msg}\n")
    except:
        pass

def log(msg):
    log_safe(msg)

# ============ PGP Functions ============
def fetch_public_key_from_pgp_server(email):
    try:
        url = f"https://keys.openpgp.org/vks/v1/by-email/{email}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return None

def get_pgp_fingerprint(public_key_armored):
    if PGPY_AVAILABLE:
        try:
            key, _ = pgpy.PGPKey.from_blob(public_key_armored)
            return str(key.fingerprint)
        except:
            pass
    if GNUPG_AVAILABLE:
        try:
            gpg = gnupg.GPG(gnupghome=GNUPG_HOME)
            import_result = gpg.import_keys(public_key_armored)
            if import_result.fingerprints:
                return import_result.fingerprints[0]
        except:
            pass
    return hashlib.sha256(public_key_armored.encode()).hexdigest()[:40]

def save_public_key(email, public_key_armored):
    safe_email = email.replace('@', '_at_').replace('.', '_')
    key_file = f"{KEYS_DIR}/{safe_email}.asc"
    with open(key_file, "w") as f:
        f.write(public_key_armored)
    
    if GNUPG_AVAILABLE:
        try:
            gpg = gnupg.GPG(gnupghome=GNUPG_HOME)
            gpg.import_keys(public_key_armored)
        except:
            pass
    
    return key_file

def load_public_key(email):
    safe_email = email.replace('@', '_at_').replace('.', '_')
    key_file = f"{KEYS_DIR}/{safe_email}.asc"
    try:
        with open(key_file, "r") as f:
            return f.read()
    except:
        return None

def verify_pgp_signature(public_key_armored, message, signature):
    if PGPY_AVAILABLE:
        try:
            key, _ = pgpy.PGPKey.from_blob(public_key_armored)
            if "---BEGIN PGP SIGNATURE---" in signature or "---BEGIN PGP MESSAGE---" in signature:
                try:
                    sig = pgpy.PGPSignature.from_blob(signature)
                    verified = key.verify(message, sig)
                    return bool(verified)
                except:
                    pass
            return False
        except:
            return False
    
    if GNUPG_AVAILABLE:
        try:
            gpg = gnupg.GPG(gnupghome=GNUPG_HOME)
            
            with open("/tmp/verify_msg.txt", "w") as f:
                f.write(message)
            with open("/tmp/verify_sig.asc", "w") as f:
                f.write(signature)
            
            with open("/tmp/verify_sig.asc", "rb") as f:
                verified = gpg.verify_file(f, "/tmp/verify_msg.txt")
            
            os.remove("/tmp/verify_msg.txt")
            os.remove("/tmp/verify_sig.asc")
            
            return bool(verified.valid)
        except Exception as e:
            log(f"GPG verify error: {type(e).__name__}")
            return False
    
    log("SECURITY WARNING: No PGP library available!")
    return False

# ============ Job Management ============
class JobManager:
    def __init__(self):
        self.jobs: Dict[str, Dict] = {}
        self.lock = threading.Lock()
    
    def create_job(self, job_id: str, server: str, command: str) -> Dict:
        with self.lock:
            job = {
                "id": job_id, "server": server, "command": command,
                "status": "created", "created": time.time(),
                "started": None, "finished": None, "exit_code": None,
                "output_file": f"{JOBS_DIR}/{job_id}.log",
                "pid": None, "fd": None
            }
            self.jobs[job_id] = job
            return job
    
    def get_job(self, job_id: str) -> Optional[Dict]:
        with self.lock:
            return self.jobs.get(job_id)
    
    def update_job(self, job_id: str, **kwargs):
        with self.lock:
            if job_id in self.jobs:
                self.jobs[job_id].update(kwargs)
    
    def list_jobs(self) -> list:
        with self.lock:
            return list(self.jobs.values())
    
    def delete_job(self, job_id: str):
        with self.lock:
            if job_id in self.jobs:
                job = self.jobs[job_id]
                if job.get("pid"):
                    try: os.kill(job["pid"], 9)
                    except: pass
                del self.jobs[job_id]

job_manager = JobManager()

def run_interactive_job(job_id: str, server: str, command: str, env: dict = None):
    job = job_manager.create_job(job_id, server, command)
    try:
        pid, fd = pty.fork()
        if pid == 0:
            if server == "local" or server == "ai":
                cmd_env = os.environ.copy()
                if env: cmd_env.update(env)
                os.execvpe("/bin/bash", ["/bin/bash", "-c", command], cmd_env)
            else:
                socket_path = f"{SOCKET_DIR}/{server}.sock"
                os.execvp("ssh", ["ssh", "-S", socket_path, server, command])
        else:
            job_manager.update_job(job_id, pid=pid, fd=fd, status="running", started=time.time())
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            output_file = open(job["output_file"], "w")
            while True:
                try:
                    data = os.read(fd, 4096)
                    if data:
                        output_file.write(data.decode('utf-8', errors='replace'))
                        output_file.flush()
                    else: break
                except OSError: pass
                pid_result, status = os.waitpid(pid, os.WNOHANG)
                if pid_result != 0: break
                time.sleep(0.1)
            output_file.close()
            os.close(fd)
            exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
            job_manager.update_job(job_id, status="finished", finished=time.time(), exit_code=exit_code)
    except Exception as e:
        job_manager.update_job(job_id, status="error", finished=time.time(), exit_code=-1)
        with open(job["output_file"], "a") as f:
            f.write(f"\nError: {e}\n")

def send_job_input(job_id: str, input_data: str) -> bool:
    job = job_manager.get_job(job_id)
    if not job or job["status"] != "running": return False
    try:
        if job.get("fd"):
            os.write(job["fd"], input_data.encode())
            return True
    except: pass
    return False

def get_job_output(job_id: str, lines: int = 100) -> str:
    job = job_manager.get_job(job_id)
    if not job: return "Job not found"
    try:
        with open(job["output_file"], "r") as f:
            all_lines = f.readlines()
            return "".join(all_lines[-lines:])
    except: return ""

# ============ IP & Rate Limit ============
def ip_in_cidr(ip, cidr):
    if '/' not in cidr: return ip == cidr
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except: return False

def check_ip_access(client_ip):
    if client_ip in IP_BLACKLIST: return False, "IP blacklisted"
    if IP_WHITELIST and IP_WHITELIST[0]:
        for allowed in IP_WHITELIST:
            if ip_in_cidr(client_ip, allowed.strip()): return True, "OK"
        if client_ip != "127.0.0.1":
            return False, "IP not in whitelist"
    return True, "OK"

def check_rate_limit(client_ip):
    now = time.time()
    rate_limit_storage[client_ip] = [t for t in rate_limit_storage[client_ip] if now - t < RATE_LIMIT_WINDOW]
    if len(rate_limit_storage[client_ip]) >= RATE_LIMIT:
        return False, "Rate limit exceeded"
    rate_limit_storage[client_ip].append(now)
    return True, "OK"

def clean_used_nonces():
    now = time.time()
    with nonces_lock:
        for nonce in list(used_nonces.keys()):
            if now - used_nonces[nonce] > SIGNATURE_EXPIRE * 2:
                del used_nonces[nonce]

# ============ Email Helpers ============
def decode_email_header(header):
    if not header: return ""
    try:
        decoded_parts = decode_header(header)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                result.append(part.decode(charset or 'utf-8', errors='ignore'))
            else:
                result.append(part)
        return ''.join(result)
    except: return header

def send_email(to_addr, subject, body):
    if not EMAIL_USER or not EMAIL_PASS: return False
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = to_addr
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, 465, context=context) as s:
            s.login(EMAIL_USER, EMAIL_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        log(f"Send error: {type(e).__name__}")
        return False

# ============ Token Management ============
def generate_token(): return secrets.token_hex(32)

def get_auth_file(email, suffix=""):
    safe_email = email.replace('@', '_at_').replace('.', '_')
    return f"{AUTH_DIR}/{safe_email}{suffix}"

def save_auth_state(email, state, data):
    with open(get_auth_file(email, ".state"), "w") as f:
        json.dump({"email": email, "state": state, "data": data, "updated": time.time()}, f)

def load_auth_state(email):
    try:
        with open(get_auth_file(email, ".state"), "r") as f:
            return json.load(f)
    except: return None

def delete_auth_state(email):
    try: os.remove(get_auth_file(email, ".state"))
    except: pass

def save_token(email, token, pubkey_fingerprint, expires_days=30):
    with open(get_auth_file(email, ".token"), "w") as f:
        json.dump({"email": email, "token": token, "pubkey_fingerprint": pubkey_fingerprint,
                   "created": time.time(), "expires": time.time() + (expires_days * 86400)}, f)

def load_token_by_value(token_value):
    if not os.path.exists(AUTH_DIR): return None
    for f in os.listdir(AUTH_DIR):
        if f.endswith(".token"):
            try:
                with open(os.path.join(AUTH_DIR, f)) as tf:
                    data = json.load(tf)
                    if data.get("token") == token_value and time.time() < data.get("expires", 0):
                        return data
            except: pass
    return None

# ============ Dual Auth Verification ============
def verify_dual_auth(params, client_ip=None):
    if client_ip and IP_WHITELIST and IP_WHITELIST[0]:
        for allowed in IP_WHITELIST:
            if ip_in_cidr(client_ip, allowed.strip()):
                return True, "OK (IP whitelisted)"
        if client_ip == "127.0.0.1":
            return True, "OK (IP whitelisted)"
    
    token = params.get("token", "")
    timestamp = params.get("timestamp", "")
    nonce = params.get("nonce", "")
    pgp_signature = params.get("pgp_signature", "")
    
    if not token: return False, "Token required"
    token_data = load_token_by_value(token)
    if not token_data: return False, "Invalid token"
    if not timestamp or not nonce or not pgp_signature:
        return False, "Timestamp, nonce and PGP signature required"
    
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > SIGNATURE_EXPIRE:
            return False, "Timestamp expired"
    except: return False, "Invalid timestamp"
    
    with nonces_lock:
        if nonce in used_nonces: return False, "Nonce already used"
        used_nonces[nonce] = time.time()
    
    email = token_data.get("email", "")
    pubkey = load_public_key(email)
    if not pubkey: return False, "Public key not found"
    
    message = f"{token}:{timestamp}:{nonce}"
    if verify_pgp_signature(pubkey, message, pgp_signature):
        return True, "OK"
    return False, "PGP signature verification failed"

# ============ SSH Tunnel Management ============
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
    subprocess.run(
        ["sshpass", "-p", cfg["pass"], "ssh", "-fN", "-M", "-S", socket,
         "-o", "ControlPersist=yes", "-o", "ServerAliveInterval=30",
         "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
         "-p", cfg["port"], f'{cfg["user"]}@{cfg["host"]}'],
        capture_output=True, timeout=15
    )

def exec_cmd(name, cmd, timeout=300):
    sanitized, err = sanitize_command(cmd)
    if err: return {"error": f"Command rejected: {err}"}
    
    if name == "local" or name == "ai":
        log(f"Local exec: {cmd[:100]}")
        try:
            r = subprocess.run(["/bin/bash", "-c", cmd], capture_output=True, text=True, timeout=timeout)
            return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
        except subprocess.TimeoutExpired: return {"error": f"Timeout {timeout}s"}
        except Exception as e: return {"error": str(e)}
    
    socket = f"{SOCKET_DIR}/{name}.sock"
    if not os.path.exists(socket): connect_async(name)
    log(f"Exec [{name}]: {cmd[:100]}")
    try:
        r = subprocess.run(["ssh", "-S", socket, name, cmd], capture_output=True, text=True, timeout=timeout)
        return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
    except subprocess.TimeoutExpired: return {"error": f"Timeout {timeout}s"}
    except Exception as e: return {"error": str(e)}

def disconnect(name):
    socket = f"{SOCKET_DIR}/{name}.sock"
    if os.path.exists(socket):
        subprocess.run(["ssh", "-S", socket, "-O", "exit", name], capture_output=True)
        return {"status": "disconnected", "name": name}
    return {"status": "not_connected", "name": name}

def list_conn():
    if not os.path.exists(SOCKET_DIR): return []
    return [f.replace(".sock", "") for f in os.listdir(SOCKET_DIR) if f.endswith(".sock")]

# ============ LLM ============
def call_llm(prompt):
    if not LLM_ENABLED:
        return None
    if not LLM_API_URL or not LLM_API_KEY:
        return None
    headers = {"Authorization": f"Bearer {LLM_API_KEY}", "Content-Type": "application/json"}
    data = {"model": LLM_MODEL, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
    try:
        response = requests.post(LLM_API_URL, headers=headers, json=data, timeout=60)
        result = response.json()
        if "choices" in result:
            return result["choices"][0]["message"]["content"]
    except Exception as e:
        log(f"LLM error: {type(e).__name__}")
    return None

SYSTEM_PROMPT = """You are MailMCP, an intelligent server management terminal.
# Available Servers
- local/ai: AI Host (MCP Server location)
- bage: Hong Kong Server
- ovh: France Server
# Capabilities
- System: hostname, uptime, df, free, ps, top
- Files: ls, cat, head, tail, find, grep
- Network: curl, wget, ping, netstat
- Services: systemctl status/start/stop/restart
- Docker: docker ps, logs, exec
# Return Format (JSON Array)
[{"type": "execute", "server": "server_name", "command": "command", "explanation": "explanation"}]
# Special Commands
- "request authorization": {"type": "authorization"}
- "help": {"type": "help"}"""

def process_with_llm(subject, body):
    prompt = f"{SYSTEM_PROMPT}\n\nEmail:\nSubject: {subject}\nBody: {body}\n\nReturn JSON array:"
    response = call_llm(prompt)
    if not response: return None
    try:
        json_match = re.search(r'\[.*\]', response, re.DOTALL)
        if json_match: return json.loads(json_match.group())
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match: return [json.loads(json_match.group())]
    except: pass
    return None

# ============ Authorization Flow ============
def process_authorization_request(sender, body):
    log(f"Authorization request from {sender}")
    if ALLOWED_SENDERS and sender not in ALLOWED_SENDERS.split(","):
        send_email(sender, "[MailMCP] Authorization Rejected", "Your email is not in the whitelist.")
        return
    
    pubkey = fetch_public_key_from_pgp_server(sender)
    if not pubkey:
        send_email(sender, "[MailMCP] Public Key Not Found", "Your PGP public key was not found.\n\nPlease upload to:\nhttps://keys.openpgp.org/upload")
        return
    
    fingerprint = get_pgp_fingerprint(pubkey)
    save_public_key(sender, pubkey)
    challenge = generate_token()
    save_auth_state(sender, "pending_challenge", {"challenge": challenge, "pubkey_fingerprint": fingerprint, "created": time.time()})
    
    send_email(sender, "[MailMCP] Authorization Challenge", f"Challenge: {challenge}\n\nPlease sign and reply:\nSIGNATURE: [your signed challenge]\n\nExpires in 10 minutes.")
    if ADMIN_EMAIL:
        send_email(ADMIN_EMAIL, "[MailMCP] New Authorization Request", f"Email: {sender}\nFingerprint: {fingerprint}\n\nAPPROVE {sender}\nREJECT {sender}")
    log(f"Challenge sent to {sender}")

def process_signature_verification(sender, body):
    log(f"Signature verification from {sender}")
    auth_state = load_auth_state(sender)
    if not auth_state or auth_state["state"] != "pending_challenge":
        send_email(sender, "[MailMCP] Verification Failed", "No pending authorization found.")
        return
    
    challenge_data = auth_state["data"]
    if time.time() - challenge_data["created"] > 600:
        delete_auth_state(sender)
        send_email(sender, "[MailMCP] Challenge Expired", "Challenge expired.")
        return
    
    match = re.search(r'SIGNATURE[:\s]+(.+)', body, re.IGNORECASE | re.DOTALL)
    if not match:
        send_email(sender, "[MailMCP] Invalid Format", "Reply with: SIGNATURE: [your signed challenge]")
        return
    
    signature = match.group(1).strip()
    pubkey = load_public_key(sender)
    
    if verify_pgp_signature(pubkey, challenge_data["challenge"], signature):
        save_auth_state(sender, "pending_approval", {"challenge": challenge_data["challenge"], "pubkey_fingerprint": challenge_data["pubkey_fingerprint"], "verified": time.time()})
        send_email(sender, "[MailMCP] Signature Verified", "Waiting for administrator approval.")
        if ADMIN_EMAIL:
            send_email(ADMIN_EMAIL, "[MailMCP] Signature Verified", f"Email: {sender}\n\nAPPROVE {sender}\nREJECT {sender}")
        log(f"Signature verified for {sender}")
    else:
        send_email(sender, "[MailMCP] Signature Verification Failed", "Signature verification failed.")

def process_admin_approval(sender, body):
    if not ADMIN_EMAIL or sender != ADMIN_EMAIL: return False
    
    approve_match = re.search(r'APPROVE[:\s]+([^\s]+)', body, re.IGNORECASE)
    reject_match = re.search(r'REJECT[:\s]+([^\s]+)', body, re.IGNORECASE)
    
    if approve_match:
        target_email = approve_match.group(1).strip()
        auth_state = load_auth_state(target_email)
        if auth_state and auth_state["state"] == "pending_approval":
            token = generate_token()
            save_token(target_email, token, auth_state["data"].get("pubkey_fingerprint", "unknown"))
            delete_auth_state(target_email)
            send_email(target_email, "[MailMCP] Authorization Approved", f"Token: {token}\nValid for 30 days.")
            log(f"Approved: {target_email}")
        return True
    elif reject_match:
        target_email = reject_match.group(1).strip()
        delete_auth_state(target_email)
        send_email(target_email, "[MailMCP] Authorization Rejected", "Your request has been rejected.")
        log(f"Rejected: {target_email}")
        return True
    return False

# ============ Email Processing ============
def process_email(email_data):
    try:
        msg = message_from_bytes(email_data)
        sender = msg['From']
        subject = decode_email_header(msg['Subject'])
        if '<' in sender: sender = sender.split('<')[1].split('>')[0]
        log(f"Email from: {sender} - {subject}")
        
        if ALLOWED_SENDERS and sender not in ALLOWED_SENDERS.split(",") and sender != ADMIN_EMAIL: return
        
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    body = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
        else:
            payload = msg.get_payload(decode=True)
            body = payload.decode(msg.get_content_charset() or 'utf-8', errors='ignore') if payload else ""
        
        if process_admin_approval(sender, body): return
        if "authorization" in subject.lower() or "authorization" in body.lower() or "授权" in subject or "授权" in body:
            process_authorization_request(sender, body); return
        if "SIGNATURE" in body.upper():
            process_signature_verification(sender, body); return
        
        results = process_with_llm(subject, body)
        if not results: send_email(sender, subject, "Unable to process request"); return
        
        response_parts = []
        for result in results:
            if result.get("type") == "authorization": process_authorization_request(sender, body); return
            elif result.get("type") == "help": response_parts.append("MailMCP Help\n\nServers: local(ai), bage, ovh\n\nAuthorization:\n1. Send: 'request authorization'\n2. Sign challenge\n3. Wait for admin approval")
            elif result.get("type") == "execute":
                server, command = result.get("server", "local"), result.get("command", "")
                if command:
                    log(f"Exec [{server}]: {command}")
                    output = exec_cmd(server, command)
                    if isinstance(output, dict): output = output.get("stdout", "") or output.get("stderr", "") or output.get("error", "")
                    response_parts.append(f"Server: {server}\nCommand: {command}\nResult:\n{str(output)[:5000]}")
        
        if response_parts: send_email(sender, subject, "\n\n---\n\n".join(response_parts))
    except Exception as e: log(f"Process error: {type(e).__name__}")

def check_emails():
    if not EMAIL_USER or not EMAIL_PASS: return
    try:
        context = ssl.create_default_context()
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, 993, ssl_context=context)
        mail.login(EMAIL_USER, EMAIL_PASS)
        mail.select('INBOX')
        _, messages = mail.search(None, 'UNSEEN')
        for num in messages[0].split():
            _, data = mail.fetch(num, '(RFC822)')
            threading.Thread(target=process_email, args=(data[0][1],), daemon=True).start()
            mail.store(num, '+FLAGS', '\\Seen')
        mail.close(); mail.logout()
    except Exception as e: log(f"Check error: {type(e).__name__}")

def check_emails_idle():
    if not EMAIL_USER or not EMAIL_PASS: return
    try:
        context = ssl.create_default_context()
        mail = imaplib.IMAP4_SSL(IMAP_SERVER, 993, ssl_context=context)
        mail.login(EMAIL_USER, EMAIL_PASS)
        mail.select('INBOX')
        log(f"IMAP IDLE connected to {IMAP_SERVER}")
        
        while True:
            try:
                mail.send(b'IDLE\r\n')
                response = mail.readline()
                if b'+ idling' in response or b'+ OK' in response:
                    while True:
                        line = mail.readline()
                        if b'EXISTS' in line or b'RECENT' in line:
                            mail.send(b'DONE\r\n')
                            mail.readline()
                            _, messages = mail.search(None, 'UNSEEN')
                            for num in messages[0].split():
                                _, data = mail.fetch(num, '(RFC822)')
                                threading.Thread(target=process_email, args=(data[0][1],), daemon=True).start()
                                mail.store(num, '+FLAGS', '\\Seen')
                            mail.send(b'IDLE\r\n')
                            mail.readline()
                        elif b'OK' not in line and line.strip():
                            pass
            except Exception as e:
                log(f"IDLE error: {type(e).__name__}, reconnecting...")
                time.sleep(5)
                try:
                    mail.close()
                    mail.logout()
                except:
                    pass
                mail = imaplib.IMAP4_SSL(IMAP_SERVER, 993, ssl_context=context)
                mail.login(EMAIL_USER, EMAIL_PASS)
                mail.select('INBOX')
    except Exception as e:
        log(f"IDLE connection error: {type(e).__name__}")

# ============ MCP Server ============
async def handle_mcp(req, client_ip):
    method, params, rid = req.get("method"), req.get("params", {}), req.get("id")
    
    if method != "initialize":
        allowed, msg = check_ip_access(client_ip)
        if not allowed: return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32600, "message": f"Access denied: {msg}"}}
        allowed, msg = check_rate_limit(client_ip)
        if not allowed: return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32600, "message": msg}}
        valid, msg = verify_dual_auth(params, client_ip)
        if not valid: return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32600, "message": f"Auth failed: {msg}"}}
    
    try:
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "MailMCP", "version": "3.1-gnupg"}}}
        elif method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
                {"name": "ssh_exec", "description": "Execute command", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "command": {"type": "string"}, "timeout": {"type": "integer", "default": 300}}, "required": ["name", "command"]}},
                {"name": "ssh_disconnect", "description": "Disconnect", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
                {"name": "ssh_list", "description": "List connections", "inputSchema": {"type": "object", "properties": {}}},
                {"name": "job_start", "description": "Start background job", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "command": {"type": "string"}, "job_id": {"type": "string"}, "env": {"type": "object"}}, "required": ["name", "command"]}},
                {"name": "job_status", "description": "Get job status", "inputSchema": {"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]}},
                {"name": "job_output", "description": "Get job output", "inputSchema": {"type": "object", "properties": {"job_id": {"type": "string"}, "lines": {"type": "integer", "default": 100}}, "required": ["job_id"]}},
                {"name": "job_input", "description": "Send input to job", "inputSchema": {"type": "object", "properties": {"job_id": {"type": "string"}, "input": {"type": "string"}}, "required": ["job_id", "input"]}},
                {"name": "job_kill", "description": "Kill job", "inputSchema": {"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]}},
                {"name": "job_list", "description": "List all jobs", "inputSchema": {"type": "object", "properties": {}}}
            ]}}
        elif method == "tools/call":
            name, args = params.get("name"), params.get("arguments", {})
            if name == "ssh_exec": result = exec_cmd(args["name"], args["command"], args.get("timeout", 300))
            elif name == "ssh_disconnect": result = disconnect(args["name"])
            elif name == "ssh_list": result = {"connections": list_conn()}
            elif name == "job_start":
                job_id = args.get("job_id") or secrets.token_hex(8)
                threading.Thread(target=run_interactive_job, args=(job_id, args["name"], args["command"], args.get("env")), daemon=True).start()
                result = {"job_id": job_id, "status": "started"}
            elif name == "job_status":
                job = job_manager.get_job(args["job_id"])
                result = {k: v for k, v in job.items() if k not in ["fd"]} if job else {"error": "Job not found"}
            elif name == "job_output": result = {"output": get_job_output(args["job_id"], args.get("lines", 100))}
            elif name == "job_input": result = {"success": send_job_input(args["job_id"], args["input"])}
            elif name == "job_kill": job_manager.delete_job(args["job_id"]); result = {"status": "killed"}
            elif name == "job_list": result = {"jobs": [{k: v for k, v in j.items() if k not in ["fd"]} for j in job_manager.list_jobs()]}
            else: result = {"error": f"Unknown: {name}"}
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}}
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    except Exception as e:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": str(e)}}

class TLSHandler:
    def __init__(self, reader, writer, client_ip):
        self.reader, self.writer, self.client_ip = reader, writer, client_ip
    
    async def handle(self):
        try:
            data = await self.reader.read(65536)
            if not data: return
            req = json.loads(data.decode())
            resp = await handle_mcp(req, self.client_ip)
            self.writer.write(json.dumps(resp).encode() + b"\n")
            await self.writer.drain()
        except Exception as e: log(f"Handler error: {type(e).__name__}")
        finally: self.writer.close()

async def email_checker():
    if USE_IMAP_IDLE:
        log("Using IMAP IDLE mode (real-time push)")
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, check_emails_idle)
    else:
        log(f"Using IMAP polling mode (interval: {EMAIL_CHECK_INTERVAL}s)")
        while True:
            try:
                check_emails()
            except Exception as e:
                log(f"Email check error: {type(e).__name__}")
            await asyncio.sleep(EMAIL_CHECK_INTERVAL)

async def mcp_server():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.load_cert_chain(CERT_FILE, KEY_FILE)
    
    async def handle_client(reader, writer):
        peername = writer.get_extra_info('peername')
        client_ip = peername[0] if peername else "unknown"
        await TLSHandler(reader, writer, client_ip).handle()
    
    server = await asyncio.start_server(handle_client, MCP_BIND_HOST, MCP_PORT, ssl=ssl_context)
    log(f"MCP Server ready on {MCP_BIND_HOST}:{MCP_PORT}")
    async with server: await server.serve_forever()

async def main():
    pgp_status = "pgpy" if PGPY_AVAILABLE else ("gnupg" if GNUPG_AVAILABLE else "NONE")
    log(f"MailMCP v3.1 starting... PGP: {pgp_status}")
    
    if not PGPY_AVAILABLE and not GNUPG_AVAILABLE:
        log("SECURITY WARNING: No PGP library! Install pgpy or python-gnupg")
    
    for name in load_config():
        threading.Thread(target=connect_async, args=(name,), daemon=True).start()
    
    await asyncio.gather(email_checker(), mcp_server())

if __name__ == "__main__":
    asyncio.run(main())
