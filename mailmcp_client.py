#!/usr/bin/env python3
"""
MailMCP Client - All-in-One Tool
Includes: PGP Key Generation, Authorization, MCP Access
"""

import ssl, socket, json, time, os, sys, subprocess, tempfile, shutil

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class MailMCPClient:
    """MailMCP All-in-One Client"""
    
    def __init__(self, host='192.168.1.8', port=18443):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        self.config_dir = os.path.expanduser("~/.mailmcp")
        self.key_file = os.path.join(self.config_dir, "key.pem")
        self.pub_file = os.path.join(self.config_dir, "key.pub")
        self.config_file = os.path.join(self.config_dir, "config.json")
        os.makedirs(self.config_dir, exist_ok=True)
    
    def _call(self, method, params=None):
        sock = socket.create_connection((self.host, self.port), timeout=30)
        tls_sock = self.context.wrap_socket(sock, server_hostname="ssh-tunnel")
        request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        tls_sock.send(json.dumps(request).encode() + b"\n")
        response = tls_sock.recv(65536)
        tls_sock.close()
        return json.loads(response)
    
    # ============ Key Management ============
    def generate_key_pair(self, email, name, passphrase=None, key_size=4096):
        """Generate RSA key pair for signing"""
        if not CRYPTO_AVAILABLE:
            print("Installing cryptography...")
            subprocess.run([sys.executable, "-m", "pip", "install", "cryptography"], check=True)
            return self.generate_key_pair(email, name, passphrase, key_size)
        
        print(f"Generating {key_size}-bit RSA key for {email}...")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        encryption = serialization.NoEncryption()
        if passphrase:
            encryption = serialization.BestAvailableEncryption(passphrase.encode())
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(self.key_file, 'wb') as f:
            f.write(private_pem)
        
        with open(self.pub_file, 'wb') as f:
            f.write(public_pem)
        
        config = {
            "email": email,
            "name": name,
            "key_file": self.key_file,
            "pub_file": self.pub_file,
            "created": time.time()
        }
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"Key pair generated:")
        print(f"  Private: {self.key_file}")
        print(f"  Public:  {self.pub_file}")
        
        return private_pem, public_pem
    
    def load_private_key(self, passphrase=None):
        """Load private key"""
        if not os.path.exists(self.key_file):
            return None
        
        with open(self.key_file, 'rb') as f:
            private_pem = f.read()
        
        return private_pem
    
    def load_public_key(self):
        """Load public key"""
        if not os.path.exists(self.pub_file):
            return None
        
        with open(self.pub_file, 'rb') as f:
            return f.read()
    
    def load_config(self):
        """Load client config"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return {}
    
    # ============ GPG Integration ============
    def generate_gpg_key(self, email, name, passphrase=None):
        """Generate GPG key using system gpg command"""
        print(f"Generating GPG key for {email}...")
        
        if passphrase is None:
            passphrase = os.urandom(16).hex()
        
        key_params = f"""
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: {name}
Name-Email: {email}
Expire-Date: 0
Passphrase: {passphrase}
%commit
"""
        
        result = subprocess.run(
            ['gpg', '--batch', '--gen-key', '--armor'],
            input=key_params,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"GPG key generation failed: {result.stderr}")
            return None
        
        result = subprocess.run(
            ['gpg', '--armor', '--export', email],
            capture_output=True,
            text=True
        )
        
        public_key = result.stdout
        
        config = self.load_config()
        config.update({
            "email": email,
            "name": name,
            "gpg_passphrase": passphrase,
            "gpg_key": True,
            "created": time.time()
        })
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"GPG key generated for {email}")
        print(f"Passphrase saved to: {self.config_file}")
        
        return public_key
    
    def upload_to_keyserver(self, public_key=None, email=None):
        """Upload public key to keys.openpgp.org"""
        if not REQUESTS_AVAILABLE:
            subprocess.run([sys.executable, "-m", "pip", "install", "requests"], check=True)
        
        if public_key is None:
            if email:
                result = subprocess.run(['gpg', '--armor', '--export', email], capture_output=True, text=True)
                public_key = result.stdout
            else:
                public_key = self.load_public_key()
        
        if not public_key:
            print("No public key available")
            return False
        
        print("Uploading to keys.openpgp.org...")
        
        try:
            response = requests.post(
                "https://keys.openpgp.org/vks/v1/upload",
                data=public_key,
                headers={"Content-Type": "application/pgp-keys"}
            )
            
            if response.status_code == 200:
                print("Upload successful!")
                print("Check your email for verification link from keys.openpgp.org")
                return True
            else:
                print(f"Upload failed: {response.status_code} {response.text}")
                return False
        except Exception as e:
            print(f"Upload error: {e}")
            return False
    
    def sign_challenge(self, challenge, email=None, passphrase=None):
        """Sign challenge using GPG"""
        config = self.load_config()
        if email is None:
            email = config.get("email")
        if passphrase is None:
            passphrase = config.get("gpg_passphrase")
        
        if not email:
            print("No email configured")
            return None
        
        result = subprocess.run(
            ['gpg', '--batch', '--yes', '--passphrase', passphrase or '',
             '--armor', '--detach-sign', '--default-key', email],
            input=challenge.encode(),
            capture_output=True
        )
        
        if result.returncode != 0:
            print(f"Signing failed: {result.stderr.decode()}")
            return None
        
        return result.stdout.decode()
    
    def sign_challenge_simple(self, challenge):
        """Simple sign challenge (just return challenge for testing)"""
        return challenge
    
    # ============ Authorization Flow ============
    def request_authorization(self, email=None):
        """Request authorization via email"""
        config = self.load_config()
        if email is None:
            email = config.get("email")
        
        if not email:
            print("No email configured. Run: client.setup('your@email.com', 'Your Name')")
            return False
        
        print(f"Requesting authorization for {email}...")
        print("Please send an email to the MailMCP server with:")
        print(f"  Subject: Authorization Request")
        print(f"  Body: request authorization pgp:{email}")
        print("\nOr use your email client to send this request.")
        
        return True
    
    def verify_authorization(self, challenge, signature=None, email=None):
        """Verify authorization with signed challenge"""
        config = self.load_config()
        if email is None:
            email = config.get("email")
        
        if signature is None:
            signature = self.sign_challenge(challenge, email)
        
        if not signature:
            signature = self.sign_challenge_simple(challenge)
        
        print(f"Challenge: {challenge}")
        print(f"Signature: {signature[:100]}...")
        print("\nPlease reply to the challenge email with:")
        print(f"  SIGNATURE: {signature}")
        
        return signature
    
    # ============ MCP Operations ============
    def execute(self, server, command, timeout=60):
        """Execute command on server"""
        result = self._call("tools/call", {
            "name": "ssh_exec",
            "arguments": {"name": server, "command": command, "timeout": timeout}
        })
        if "result" in result:
            data = json.loads(result["result"]["content"][0]["text"])
            return data.get("stdout", "") or data.get("stderr", "") or data.get("error", "")
        return str(result)
    
    def job_start(self, server, command, job_id=None):
        """Start background job"""
        args = {"name": server, "command": command, "env": {"TERM": "xterm", "LINES": "24", "COLUMNS": "80"}}
        if job_id:
            args["job_id"] = job_id
        result = self._call("tools/call", {"name": "job_start", "arguments": args})
        if "result" in result:
            return json.loads(result["result"]["content"][0]["text"])
        return result
    
    def job_status(self, job_id):
        """Get job status"""
        result = self._call("tools/call", {"name": "job_status", "arguments": {"job_id": job_id}})
        if "result" in result:
            return json.loads(result["result"]["content"][0]["text"])
        return result
    
    def job_output(self, job_id, lines=100):
        """Get job output"""
        result = self._call("tools/call", {"name": "job_output", "arguments": {"job_id": job_id, "lines": lines}})
        if "result" in result:
            data = json.loads(result["result"]["content"][0]["text"])
            return data.get("output", "")
        return ""
    
    def job_input(self, job_id, input_data):
        """Send input to job"""
        result = self._call("tools/call", {"name": "job_input", "arguments": {"job_id": job_id, "input": input_data}})
        if "result" in result:
            return json.loads(result["result"]["content"][0]["text"])
        return result
    
    def list_connections(self):
        """List SSH connections"""
        result = self._call("tools/call", {"name": "ssh_list", "arguments": {}})
        if "result" in result:
            return json.loads(result["result"]["content"][0]["text"])
        return result
    
    # ============ ncurses Keys ============
    KEYS = {
        'up': '\x1b[A', 'down': '\x1b[B', 'right': '\x1b[C', 'left': '\x1b[D',
        'enter': '\r', 'tab': '\t', 'escape': '\x1b', 'space': ' ',
        'backspace': '\x7f', 'delete': '\x1b[3~',
        'home': '\x1b[1~', 'end': '\x1b[4~',
        'page_up': '\x1b[5~', 'page_down': '\x1b[6~',
        'insert': '\x1b[2~',
        'f1': '\x1bOP', 'f2': '\x1bOQ', 'f3': '\x1bOR', 'f4': '\x1bOS',
        'f5': '\x1b[15~', 'f6': '\x1b[17~', 'f7': '\x1b[18~', 'f8': '\x1b[19~',
        'f9': '\x1b[20~', 'f10': '\x1b[21~', 'f11': '\x1b[23~', 'f12': '\x1b[24~',
    }
    
    def key(self, name):
        return self.KEYS.get(name, name)
    
    # ============ Setup Wizard ============
    def setup(self, email, name, use_gpg=True):
        """Interactive setup wizard"""
        print(f"\n=== MailMCP Setup Wizard ===\n")
        print(f"Email: {email}")
        print(f"Name:  {name}")
        print()
        
        if use_gpg:
            print("Checking GPG...")
            result = subprocess.run(['gpg', '--version'], capture_output=True)
            if result.returncode != 0:
                print("GPG not found. Installing...")
                if sys.platform == 'win32':
                    print("Please install Gpg4win from https://www.gpg4win.org/")
                    return False
                else:
                    subprocess.run(['sudo', 'apt', 'install', '-y', 'gnupg'], check=True)
            
            public_key = self.generate_gpg_key(email, name)
        else:
            public_key = self.generate_key_pair(email, name)
        
        if public_key:
            print("\nUploading public key to keys.openpgp.org...")
            self.upload_to_keyserver(public_key, email)
        
        print("\n=== Setup Complete ===")
        print(f"Config saved to: {self.config_file}")
        print("\nNext steps:")
        print("1. Verify your email on keys.openpgp.org (check inbox)")
        print("2. Send authorization request email to MailMCP server")
        print("3. Sign the challenge and reply")
        print("4. Wait for admin approval")
        
        return True
    
    def status(self):
        """Show client status"""
        config = self.load_config()
        
        print("\n=== MailMCP Client Status ===\n")
        
        if not config:
            print("Not configured. Run: client.setup('your@email.com', 'Your Name')")
            return
        
        print(f"Email: {config.get('email', 'Not set')}")
        print(f"Name:  {config.get('name', 'Not set')}")
        print(f"GPG Key: {'Yes' if config.get('gpg_key') else 'No'}")
        print(f"Config: {self.config_file}")
        
        if os.path.exists(self.key_file):
            print(f"Private Key: {self.key_file}")
        if os.path.exists(self.pub_file):
            print(f"Public Key: {self.pub_file}")
        
        print("\nMCP Server:")
        print(f"  Host: {self.host}")
        print(f"  Port: {self.port}")
        
        try:
            result = self.list_connections()
            print(f"  Connections: {result.get('connections', [])}")
        except:
            print("  Status: Cannot connect")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='MailMCP All-in-One Client')
    parser.add_argument('--host', default='your-server.com', help='MCP server host')
    parser.add_argument('--port', type=int, default=18443, help='MCP server port')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    subparsers.add_parser('status', help='Show client status')
    subparsers.add_parser('connections', help='List SSH connections')
    
    setup_parser = subparsers.add_parser('setup', help='Setup client')
    setup_parser.add_argument('email', help='Your email')
    setup_parser.add_argument('name', help='Your name')
    setup_parser.add_argument('--no-gpg', action='store_true', help='Use simple key instead of GPG')
    
    exec_parser = subparsers.add_parser('exec', help='Execute command')
    exec_parser.add_argument('server', help='Server name')
    exec_parser.add_argument('command', help='Command to execute')
    
    upload_parser = subparsers.add_parser('upload', help='Upload public key to keyserver')
    upload_parser.add_argument('--email', help='Email (optional)')
    
    args = parser.parse_args()
    
    client = MailMCPClient(args.host, args.port)
    
    if args.command == 'status':
        client.status()
    elif args.command == 'connections':
        result = client.list_connections()
        print(json.dumps(result, indent=2))
    elif args.command == 'setup':
        client.setup(args.email, args.name, use_gpg=not args.no_gpg)
    elif args.command == 'exec':
        result = client.execute(args.server, args.command)
        print(result)
    elif args.command == 'upload':
        client.upload_to_keyserver(email=args.email)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
