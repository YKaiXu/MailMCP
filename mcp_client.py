#!/usr/bin/env python3
"""
MailMCP Client - Access MailMCP via MCP Protocol
Supports interactive commands with job management
"""

import ssl, socket, json, time

class MailMCPClient:
    def __init__(self, host='your-server.com', port=18443):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
    
    def _call(self, method, params=None):
        sock = socket.create_connection((self.host, self.port), timeout=30)
        tls_sock = self.context.wrap_socket(sock, server_hostname="ssh-tunnel")
        request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        tls_sock.send(json.dumps(request).encode() + b"\n")
        response = tls_sock.recv(65536)
        tls_sock.close()
        return json.loads(response)
    
    def list_connections(self):
        result = self._call("tools/call", {"name": "ssh_list", "arguments": {}})
        if "result" in result:
            return json.loads(result["result"]["content"][0]["text"])
        return result
    
    def execute(self, server, command, timeout=60):
        result = self._call("tools/call", {
            "name": "ssh_exec",
            "arguments": {"name": server, "command": command, "timeout": timeout}
        })
        if "result" in result:
            data = json.loads(result["result"]["content"][0]["text"])
            return data.get("stdout", "") or data.get("stderr", "") or data.get("error", "")
        return str(result)
    
    def write_file(self, server, filepath, content):
        cmd = f'cat > "{filepath}" << \'ENDOFFILE\'\n{content}\nENDOFFILE'
        return self.execute(server, cmd)
    
    def read_file(self, server, filepath):
        return self.execute(server, f'cat "{filepath}"')
    
    # ============ Job Management ============
    def job_start(self, server, command, job_id=None, env=None):
        args = {"name": server, "command": command}
        if job_id:
            args["job_id"] = job_id
        if env:
            args["env"] = env
        result = self._call("tools/call", {"name": "job_start", "arguments": args})
        if "result" in result:
            return json.loads(result["result"]["content"][0]["text"])
        return result
    
    def job_status(self, job_id):
        result = self._call("tools/call", {"name": "job_status", "arguments": {"job_id": job_id}})
        if "result" in result:
            return json.loads(result["result"]["content"][0]["text"])
        return result
    
    def job_output(self, job_id, lines=100):
        result = self._call("tools/call", {"name": "job_output", "arguments": {"job_id": job_id, "lines": lines}})
        if "result" in result:
            data = json.loads(result["result"]["content"][0]["text"])
            return data.get("output", "")
        return ""
    
    def job_input(self, job_id, input_data):
        result = self._call("tools/call", {"name": "job_input", "arguments": {"job_id": job_id, "input": input_data}})
        if "result" in result:
            return json.loads(result["result"]["content"][0]["text"])
        return result
    
    def job_kill(self, job_id):
        result = self._call("tools/call", {"name": "job_kill", "arguments": {"job_id": job_id}})
        if "result" in result:
            return json.loads(result["result"]["content"][0]["text"])
        return result
    
    def job_list(self):
        result = self._call("tools/call", {"name": "job_list", "arguments": {}})
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
    
    # ============ Interactive Helpers ============
    def run_interactive(self, server, command, inputs=None, timeout=300):
        job = self.job_start(server, command)
        job_id = job.get("job_id")
        if not job_id:
            return {"error": "Failed to start job"}
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.job_status(job_id)
            if status.get("status") in ["finished", "error"]:
                break
            
            output = self.job_output(job_id)
            if inputs:
                for prompt, response in inputs.items():
                    if prompt in output:
                        self.job_input(job_id, response + "\n")
                        inputs.pop(prompt)
                        break
            
            time.sleep(0.5)
        
        return {
            "job_id": job_id,
            "status": self.job_status(job_id),
            "output": self.job_output(job_id, lines=1000)
        }
    
    def apt_install(self, server, packages, non_interactive=True):
        if non_interactive:
            cmd = f"DEBIAN_FRONTEND=noninteractive apt install -y {packages}"
            return self.execute(server, cmd, timeout=600)
        else:
            return self.run_interactive(server, f"apt install {packages}", {"Do you want to continue?": "Y"})
    
    def configure_build(self, server, options=None, timeout=300):
        cmd = "./configure"
        if options:
            cmd += " " + " ".join(f"--{k}={v}" for k, v in options.items())
        return self.run_interactive(server, cmd, timeout=timeout)


if __name__ == "__main__":
    client = MailMCPClient()
    
    print("=== MailMCP Client v3.0 (Interactive Support) ===\n")
    
    print("1. List connections:")
    result = client.list_connections()
    print(json.dumps(result, indent=2))
    
    print("\n2. Test interactive job:")
    job = client.job_start("local", "echo 'Hello' && sleep 2 && echo 'World'")
    print(f"Started job: {job}")
    
    time.sleep(3)
    
    status = client.job_status(job.get("job_id"))
    print(f"Status: {status}")
    
    output = client.job_output(job.get("job_id"))
    print(f"Output: {output}")
    
    print("\n3. Test apt install (non-interactive):")
    result = client.apt_install("local", "htop", non_interactive=True)
    print(result[:500] if result else "OK")
