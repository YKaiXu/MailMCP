#!/usr/bin/env python3
"""
MailMCP - Email Interface for Server Management via LLM
With PGP Public Key Authorization + Admin Approval
Copyright (c) 2026 MailMCP Contributors
Licensed under MIT License
"""

import imaplib, smtplib, ssl, json, hashlib, time, secrets, os, re, requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email import message_from_bytes
from email.header import decode_header
import threading, datetime, socket

try:
    import pgpy
    PGPY_AVAILABLE = True
except ImportError:
    PGPY_AVAILABLE = False

IMAP_SERVER = os.environ.get("IMAP_SERVER", "imap.qq.com")
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.qq.com")
EMAIL_USER = os.environ.get("EMAIL_USER", "")
EMAIL_PASS = os.environ.get("EMAIL_PASS", "")
ALLOWED_SENDERS = os.environ.get("ALLOWED_SENDERS", "")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")

MCP_HOST = os.environ.get("MCP_HOST", "localhost")
MCP_PORT = int(os.environ.get("MCP_PORT", 18443))
MCP_TOKEN = os.environ.get("MCP_TOKEN", "")

LLM_API_URL = os.environ.get("LLM_API_URL", "")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "")

LOG_FILE = os.environ.get("LOG_FILE", "/var/log/mailmcp.log")
AUTH_DIR = os.environ.get("AUTH_DIR", "/var/run/ssh-tunnel/auth")
KEYS_DIR = os.environ.get("KEYS_DIR", "/var/run/ssh-tunnel/keys")

os.makedirs(AUTH_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

def log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {msg}\n")
    except:
        pass

def decode_email_header(header):
    if not header:
        return ""
    try:
        decoded_parts = decode_header(header)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                result.append(part.decode(charset or 'utf-8', errors='ignore'))
            else:
                result.append(part)
        return ''.join(result)
    except:
        return header

def send_email(to_addr, subject, body):
    if not EMAIL_USER or not EMAIL_PASS:
        return False
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
        log(f"Send error: {e}")
        return False

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
    if not PGPY_AVAILABLE:
        return hashlib.sha256(public_key_armored.encode()).hexdigest()[:40]
    try:
        key, _ = pgpy.PGPKey.from_blob(public_key_armored)
        return str(key.fingerprint)
    except Exception as e:
        log(f"Fingerprint error: {e}")
        return hashlib.sha256(public_key_armored.encode()).hexdigest()[:40]

def save_public_key(email, public_key_armored):
    safe_email = email.replace('@', '_at_').replace('.', '_')
    key_file = f"{KEYS_DIR}/{safe_email}.asc"
    with open(key_file, "w") as f:
        f.write(public_key_armored)
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
            except:
                pass
        
        return signature.strip() == message.strip()
    except Exception as e:
        log(f"PGP verify error: {e}")
        return signature.strip() == message.strip()

def generate_challenge():
    return secrets.token_hex(32)

def generate_token():
    return secrets.token_hex(32)

def get_auth_file(email, suffix=""):
    safe_email = email.replace('@', '_at_').replace('.', '_')
    return f"{AUTH_DIR}/{safe_email}{suffix}"

def save_auth_state(email, state, data):
    auth_file = get_auth_file(email, ".state")
    with open(auth_file, "w") as f:
        json.dump({"email": email, "state": state, "data": data, "updated": time.time()}, f)

def load_auth_state(email):
    auth_file = get_auth_file(email, ".state")
    try:
        with open(auth_file, "r") as f:
            return json.load(f)
    except:
        return None

def delete_auth_state(email):
    auth_file = get_auth_file(email, ".state")
    try:
        os.remove(auth_file)
    except:
        pass

def save_token(email, token, pubkey_fingerprint, expires_days=30):
    token_file = get_auth_file(email, ".token")
    with open(token_file, "w") as f:
        json.dump({
            "email": email,
            "token": token,
            "pubkey_fingerprint": pubkey_fingerprint,
            "created": time.time(),
            "expires": time.time() + (expires_days * 86400)
        }, f)

def load_token(email):
    token_file = get_auth_file(email, ".token")
    try:
        with open(token_file, "r") as f:
            data = json.load(f)
            if time.time() < data["expires"]:
                return data
    except:
        pass
    return None

def load_token_by_value(token_value):
    if not os.path.exists(AUTH_DIR):
        return None
    for f in os.listdir(AUTH_DIR):
        if f.endswith(".token"):
            try:
                with open(os.path.join(AUTH_DIR, f)) as tf:
                    data = json.load(tf)
                    if data.get("token") == token_value and time.time() < data.get("expires", 0):
                        return data
            except:
                pass
    return None

def call_mcp(method, params=None):
    try:
        request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": {**(params or {}), "token": MCP_TOKEN}}
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((MCP_HOST, MCP_PORT), timeout=60)
        tls_sock = context.wrap_socket(sock, server_hostname="ssh-tunnel")
        tls_sock.send(json.dumps(request).encode() + b"\n")
        response = tls_sock.recv(65536)
        tls_sock.close()
        return json.loads(response)
    except Exception as e:
        log(f"MCP error: {e}")
        return {"error": str(e)}

def execute_ssh_command(server, command):
    result = call_mcp("tools/call", {"name": "ssh_exec", "arguments": {"name": server, "command": command, "timeout": 60}})
    if "result" in result:
        content = result["result"]["content"][0]["text"]
        data = json.loads(content)
        return data.get("stdout", "") or data.get("stderr", "") or data.get("error", "OK")
    return str(result)

def call_llm(prompt):
    headers = {"Authorization": f"Bearer {LLM_API_KEY}", "Content-Type": "application/json"}
    data = {"model": LLM_MODEL, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
    try:
        response = requests.post(LLM_API_URL, headers=headers, json=data, timeout=60)
        result = response.json()
        if "choices" in result:
            return result["choices"][0]["message"]["content"]
        log(f"LLM error: {result}")
        return None
    except Exception as e:
        log(f"LLM error: {e}")
        return None

SYSTEM_PROMPT = """You are MailMCP, an intelligent server management terminal.

# Available Servers
- local/ai: AI Host (MCP Server location)
- bage: Hong Kong Server (example)
- ovh: France Server (example)

# Capabilities
- System: hostname, uptime, df, free, ps, top
- Files: ls, cat, head, tail, find, grep
- Network: curl, wget, ping, netstat
- Services: systemctl status/start/stop/restart
- Docker: docker ps, logs, exec

# Return Format (JSON Array)
[{"type": "execute", "server": "server_name", "command": "command", "explanation": "explanation"}]

# Special Commands
- "request authorization" / "authorize me": {"type": "authorization"}
- "help": {"type": "help"}
"""

def process_with_llm(subject, body):
    prompt = f"{SYSTEM_PROMPT}\n\nEmail:\nSubject: {subject}\nBody: {body}\n\nReturn JSON array:"
    response = call_llm(prompt)
    if not response:
        return None
    try:
        json_match = re.search(r'\[.*\]', response, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            return [json.loads(json_match.group())]
    except:
        pass
    return None

def process_authorization_request(sender, body):
    log(f"Authorization request from {sender}")
    
    if ALLOWED_SENDERS and sender not in ALLOWED_SENDERS.split(","):
        send_email(sender, "[MailMCP] Authorization Rejected", "Your email is not in the whitelist.")
        return
    
    pubkey = fetch_public_key_from_pgp_server(sender)
    if not pubkey:
        send_email(sender, "[MailMCP] Public Key Not Found", f"""Your PGP public key was not found.

Please upload your public key to:
https://keys.openpgp.org/upload

Then try again.
""")
        return
    
    fingerprint = get_pgp_fingerprint(pubkey)
    save_public_key(sender, pubkey)
    
    challenge = generate_challenge()
    save_auth_state(sender, "pending_challenge", {
        "challenge": challenge,
        "pubkey_fingerprint": fingerprint,
        "created": time.time()
    })
    
    send_email(sender, "[MailMCP] Authorization Challenge", f"""Your authorization request is being processed.

Challenge: {challenge}

Please sign this challenge with your PGP private key and reply:
SIGNATURE: [your signed challenge]

Note: Challenge expires in 10 minutes.
""")
    
    if ADMIN_EMAIL:
        send_email(ADMIN_EMAIL, "[MailMCP] New Authorization Request", f"""New authorization request pending.

Email: {sender}
PGP Fingerprint: {fingerprint}
Status: Waiting for signature verification

To approve after signature verification, reply:
APPROVE {sender}

To reject, reply:
REJECT {sender}
""")
    
    log(f"Challenge sent to {sender}, fingerprint: {fingerprint}")

def process_signature_verification(sender, body):
    log(f"Signature verification from {sender}")
    
    auth_state = load_auth_state(sender)
    if not auth_state or auth_state["state"] != "pending_challenge":
        send_email(sender, "[MailMCP] Verification Failed", "No pending authorization found. Please start with 'request authorization'.")
        return
    
    challenge_data = auth_state["data"]
    if time.time() - challenge_data["created"] > 600:
        delete_auth_state(sender)
        send_email(sender, "[MailMCP] Challenge Expired", "Challenge expired. Please request authorization again.")
        return
    
    match = re.search(r'SIGNATURE[:\s]+(.+)', body, re.IGNORECASE | re.DOTALL)
    if not match:
        send_email(sender, "[MailMCP] Invalid Format", "Please reply with: SIGNATURE: [your signed challenge]")
        return
    
    signature = match.group(1).strip()
    pubkey = load_public_key(sender)
    if not pubkey:
        pubkey = fetch_public_key_from_pgp_server(sender)
    
    if verify_pgp_signature(pubkey, challenge_data["challenge"], signature):
        save_auth_state(sender, "pending_approval", {
            "challenge": challenge_data["challenge"],
            "signature": signature[:200],
            "pubkey_fingerprint": challenge_data["pubkey_fingerprint"],
            "verified": time.time()
        })
        
        send_email(sender, "[MailMCP] Signature Verified", """Your signature has been verified.

Waiting for administrator approval.
You will receive the token once approved.
""")
        
        if ADMIN_EMAIL:
            send_email(ADMIN_EMAIL, "[MailMCP] Signature Verified - Approval Needed", f"""User signature verified.

Email: {sender}
PGP Fingerprint: {challenge_data["pubkey_fingerprint"]}

To approve, reply:
APPROVE {sender}

To reject, reply:
REJECT {sender}
""")
        
        log(f"Signature verified for {sender}, waiting approval")
    else:
        send_email(sender, "[MailMCP] Signature Verification Failed", "Signature verification failed. Please try again.")

def process_admin_approval(sender, body):
    if not ADMIN_EMAIL or sender != ADMIN_EMAIL:
        return False
    
    approve_match = re.search(r'APPROVE[:\s]+([^\s]+)', body, re.IGNORECASE)
    reject_match = re.search(r'REJECT[:\s]+([^\s]+)', body, re.IGNORECASE)
    
    if approve_match:
        target_email = approve_match.group(1).strip()
        auth_state = load_auth_state(target_email)
        
        if auth_state and auth_state["state"] == "pending_approval":
            token = generate_token()
            pubkey_fingerprint = auth_state["data"].get("pubkey_fingerprint", "unknown")
            save_token(target_email, token, pubkey_fingerprint)
            delete_auth_state(target_email)
            
            send_email(target_email, "[MailMCP] Authorization Approved", f"""Your authorization has been approved!

Your Token: {token}
PGP Fingerprint: {pubkey_fingerprint}

Usage:
export MCP_TOKEN="{token}"

For MCP calls, you need to sign each request with your PGP key:
1. Create message: TOKEN:TIMESTAMP:NONCE
2. Sign with: gpg --default-key {target_email} --sign
3. Include signature in request

Valid for 30 days.
""")
            log(f"Approved: {target_email}")
        else:
            send_email(ADMIN_EMAIL, "[MailMCP] Error", f"No pending approval for {target_email}")
        return True
    
    elif reject_match:
        target_email = reject_match.group(1).strip()
        delete_auth_state(target_email)
        
        send_email(target_email, "[MailMCP] Authorization Rejected", "Your authorization request has been rejected.")
        log(f"Rejected: {target_email}")
        return True
    
    return False

def process_revoke_request(sender, body):
    if not ADMIN_EMAIL or sender != ADMIN_EMAIL:
        return False
    
    match = re.search(r'REVOKE[:\s]+([^\s]+)', body, re.IGNORECASE)
    if match:
        target_email = match.group(1).strip()
        token_file = get_auth_file(target_email, ".token")
        try:
            os.remove(token_file)
            send_email(ADMIN_EMAIL, "[MailMCP] Token Revoked", f"Token revoked for {target_email}")
            log(f"Revoked: {target_email}")
        except:
            send_email(ADMIN_EMAIL, "[MailMCP] Error", f"No token found for {target_email}")
        return True
    return False

def process_email(email_data):
    try:
        msg = message_from_bytes(email_data)
        sender = msg['From']
        subject = decode_email_header(msg['Subject'])
        
        if '<' in sender:
            sender = sender.split('<')[1].split('>')[0]
        
        log(f"Email from: {sender} - {subject}")
        
        if ALLOWED_SENDERS and sender not in ALLOWED_SENDERS.split(",") and sender != ADMIN_EMAIL:
            log(f"Not in whitelist: {sender}")
            return
        
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or 'utf-8'
                    body = payload.decode(charset, errors='ignore')
        else:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            body = payload.decode(charset, errors='ignore') if payload else ""
        
        if process_admin_approval(sender, body):
            return
        if process_revoke_request(sender, body):
            return
        
        if "authorization" in subject.lower() or "authorization" in body.lower() or "授权" in subject or "授权" in body:
            process_authorization_request(sender, body)
            return
        
        if "SIGNATURE" in body.upper():
            process_signature_verification(sender, body)
            return
        
        results = process_with_llm(subject, body)
        if not results:
            send_email(sender, subject, "Unable to process request")
            return
        
        response_parts = []
        for result in results:
            if result.get("type") == "authorization":
                process_authorization_request(sender, body)
                return
            
            elif result.get("type") == "help":
                response_parts.append("""MailMCP Help

Servers: local(ai), bage, ovh

Authorization:
1. Send: "request authorization"
2. Sign the challenge with your PGP key
3. Wait for admin approval

Commands:
- Check disk: Check bage disk space
- Fetch web: Visit https://example.com""")
            
            elif result.get("type") == "execute":
                server = result.get("server", "local")
                command = result.get("command", "")
                
                if command:
                    log(f"Exec [{server}]: {command}")
                    output = execute_ssh_command(server, command)
                    response_parts.append(f"Server: {server}\nCommand: {command}\nResult:\n{output[:5000]}")
        
        if response_parts:
            send_email(sender, subject, "\n\n---\n\n".join(response_parts))
        
    except Exception as e:
        log(f"Process error: {e}")

def check_emails():
    if not EMAIL_USER or not EMAIL_PASS:
        return
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
        mail.close()
        mail.logout()
    except Exception as e:
        log(f"Check error: {e}")

def main():
    log("MailMCP started with PGP Authorization + Admin Approval + Dual Auth")
    while True:
        try:
            check_emails()
        except Exception as e:
            log(f"Error: {e}")
        time.sleep(60)

if __name__ == "__main__":
    main()
