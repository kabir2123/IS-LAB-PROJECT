import os
import time
import threading
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

shared_file = None
valid_tokens = {}
server_instance = None
active_port = None

# -------------------------------
# Token Management
# -------------------------------
def set_file_and_auth(file_path):
    """Set the file to serve."""
    global shared_file
    shared_file = os.path.abspath(file_path)
    print(f"[+] File set to serve: {shared_file}")

def add_valid_token(token, expiry):
    """Register token with expiry and usage counter."""
    valid_tokens[token] = {"expiry": expiry, "uses": 0}
    print(f"[+] Token {token} valid until {time.ctime(expiry)}")

def is_token_valid(token):
    """Check if token exists and not expired."""
    if token in valid_tokens:
        entry = valid_tokens[token]
        if time.time() < entry["expiry"]:
            return True
        else:
            print(f"[-] Token expired: {token}")
            del valid_tokens[token]
    return False

# -------------------------------
# Cleanup Thread
# -------------------------------
def cleanup_tokens():
    """Remove expired tokens every 10 seconds."""
    while True:
        now = time.time()
        expired = [t for t, v in valid_tokens.items() if v["expiry"] < now]
        for t in expired:
            print(f"[-] Cleaning up expired token: {t}")
            del valid_tokens[t]
        time.sleep(10)

# -------------------------------
# Secure HTTP Handler
# -------------------------------
class SecureFileHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        global shared_file
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        token = qs.get("token", [None])[0]

        if not token or not is_token_valid(token):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Forbidden: Invalid or expired token")
            print("[-] Access denied: Invalid or expired token")
            return

        # --- Decode URL path (handles %20 and others) ---
        requested_path = urllib.parse.unquote(parsed.path)
        filename = os.path.basename(shared_file)

        # --- Match .sig or main file ---
        if requested_path.endswith(".sig"):
            path = shared_file + ".sig"
        elif requested_path == "/" + filename:
            path = shared_file
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"File not found")
            print(f"[-] File not found for request: {requested_path}")
            return

        if not os.path.exists(path):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"File not found on disk")
            print(f"[-] Missing file: {path}")
            return

        # --- Serve file ---
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(os.path.getsize(path)))
        self.end_headers()

        with open(path, "rb") as f:
            while chunk := f.read(4096):
                self.wfile.write(chunk)

        print(f"[+] File served: {path} (token: {token})")

        # --- Update token usage ---
        if token in valid_tokens:
            valid_tokens[token]["uses"] += 1
            if valid_tokens[token]["uses"] >= 2:
                print(f"[+] Token {token} used twice — removing.")
                del valid_tokens[token]

# -------------------------------
# Server Controls
# -------------------------------
def run_server(host="0.0.0.0", port=8000):
    """Run the file server with auto-port recovery."""
    global server_instance, active_port
    if not shared_file:
        print("[-] No file set. Use set_file_and_auth() first.")
        return

    for p in range(port, port + 10):
        try:
            server_instance = HTTPServer((host, p), SecureFileHandler)
            active_port = p
            print(f"[+] File server running at {host}:{p}")
            print(f"[+] Serving: {shared_file}")
            threading.Thread(target=cleanup_tokens, daemon=True).start()
            server_instance.serve_forever()
            break
        except OSError as e:
            if e.errno == 48:  # Address already in use
                print(f"[-] Port {p} already in use, trying next...")
                continue
            else:
                raise

def stop_server():
    """Stop the running file server."""
    global server_instance
    if server_instance:
        server_instance.shutdown()
        print("[+] File server stopped")
