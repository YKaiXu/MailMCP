#!/usr/bin/env python3
"""
MailMCP Client - ncurses Support
Support for interactive menuconfig-style interfaces
"""

import ssl, socket, json, time

class MailMCPClient:
    def __init__(self, host='192.168.1.8', port=18443):
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
    
    # ============ ncurses Keys ============
    KEYS = {
        'up': '\x1b[A',
        'down': '\x1b[B',
        'right': '\x1b[C',
        'left': '\x1b[D',
        'enter': '\r',
        'tab': '\t',
        'escape': '\x1b',
        'space': ' ',
        'backspace': '\x7f',
        'home': '\x1b[1~',
        'end': '\x1b[4~',
        'page_up': '\x1b[5~',
        'page_down': '\x1b[6~',
        'f1': '\x1bOP',
        'f2': '\x1bOQ',
        'f3': '\x1bOR',
        'f4': '\x1bOS',
        'f5': '\x1b[15~',
        'f6': '\x1b[17~',
        'f7': '\x1b[18~',
        'f8': '\x1b[19~',
        'f9': '\x1b[20~',
        'f10': '\x1b[21~',
    }
    
    def key(self, name):
        return self.KEYS.get(name, name)
    
    # ============ Job Management ============
    def job_start(self, server, command, job_id=None, env=None, rows=24, cols=80):
        args = {"name": server, "command": command, "env": env or {}}
        args["env"]["TERM"] = "xterm"
        args["env"]["LINES"] = str(rows)
        args["env"]["COLUMNS"] = str(cols)
        if job_id:
            args["job_id"] = job_id
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
    
    # ============ ncurses Helpers ============
    def menuconfig_navigate(self, job_id, path):
        """
        Navigate menuconfig by path
        path: list of menu items to select, e.g. ['Target System', 'x86', 'Save']
        """
        for item in path:
            time.sleep(0.3)
            output = self.job_output(job_id, lines=50)
            
            # Search for item in output
            lines = output.split('\n')
            found_line = -1
            for i, line in enumerate(lines):
                if item.lower() in line.lower():
                    found_line = i
                    break
            
            if found_line >= 0:
                # Navigate to item (press down multiple times)
                for _ in range(found_line):
                    self.job_input(job_id, self.key('down'))
                    time.sleep(0.1)
                
                # Select item
                self.job_input(job_id, self.key('enter'))
                time.sleep(0.3)
            else:
                print(f"Item not found: {item}")
                return False
        
        return True
    
    def menuconfig_select(self, job_id, option_name):
        """Select an option in menuconfig"""
        self.job_input(job_id, self.key('space'))
        time.sleep(0.2)
    
    def menuconfig_save(self, job_id, filename=".config"):
        """Save configuration and exit"""
        # Press escape to get to main menu
        self.job_input(job_id, self.key('escape'))
        time.sleep(0.2)
        
        # Navigate to Save
        self.job_input(job_id, self.key('down'))
        self.job_input(job_id, self.key('down'))
        time.sleep(0.2)
        
        # Select Save
        self.job_input(job_id, self.key('enter'))
        time.sleep(0.3)
        
        # Confirm filename
        self.job_input(job_id, self.key('enter'))
        time.sleep(0.3)
        
        # Exit
        self.job_input(job_id, self.key('escape'))
        time.sleep(0.2)
        self.job_input(job_id, self.key('enter'))


if __name__ == "__main__":
    client = MailMCPClient()
    
    print("=== ncurses Support Test ===\n")
    
    # Test with a simple menu program
    print("1. Testing ncurses key sequences:")
    print(f"  Up: {repr(client.key('up'))}")
    print(f"  Down: {repr(client.key('down'))}")
    print(f"  Enter: {repr(client.key('enter'))}")
    
    print("\n2. Test simple menu program:")
    menu_code = '''
#!/bin/bash
echo "=== Simple Menu ==="
echo "1. Option A"
echo "2. Option B"  
echo "3. Exit"
echo -n "Select: "
read choice
echo "You selected: $choice"
'''
    
    # Create test script
    result = client.job_start("local", f"echo '{menu_code}' > /tmp/menu.sh && bash /tmp/menu.sh")
    job_id = result['job_id']
    print(f"Job: {job_id}")
    
    time.sleep(0.5)
    output = client.job_output(job_id)
    print(f"Output:\n{output}")
    
    # Send selection
    print("\n3. Send '1' and enter:")
    client.job_input(job_id, "1")
    client.job_input(job_id, client.key('enter'))
    
    time.sleep(0.5)
    output = client.job_output(job_id)
    print(f"Output:\n{output}")
    
    status = client.job_status(job_id)
    print(f"Status: {status['status']}")
