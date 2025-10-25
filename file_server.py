import http.server
import socketserver
import os
import time
from urllib.parse import urlparse, parse_qs

FILE_PATH = None
VALID_TOKENS = {}  # token -> expiry
httpd = None

def add_valid_token(token, expiry):
    VALID_TOKENS[token] = expiry

class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        file_name = os.path.basename(parsed_url.path)
        qs = parse_qs(parsed_url.query)
        token_list = qs.get("token", [])

        if not token_list:
            self.send_error(401, "Missing token")
            return

        token = token_list[0]
        expiry = VALID_TOKENS.get(token)
        if not expiry:
            self.send_error(401, "Invalid or used token")
            return
        if time.time() > expiry:
            self.send_error(401, "Token expired")
            del VALID_TOKENS[token]
            return

        # ✅ Serve main file or signature
        target_path = None
        if FILE_PATH:
            base = os.path.basename(FILE_PATH)
            if file_name == base:
                target_path = FILE_PATH
            elif file_name == base + ".sig":
                target_path = FILE_PATH + ".sig"

        print(f"[DEBUG] Requested: {file_name}, Serving: {target_path}")

        if target_path and os.path.isfile(target_path):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(target_path)}"')
            self.end_headers()
            with open(target_path, "rb") as f:
                while chunk := f.read(4096):
                    self.wfile.write(chunk)
        else:
            self.send_error(404, "File not found")

        # ✅ Keep token valid for both .txt and .sig
        # del VALID_TOKENS[token]  # Remove this line for local testing

def set_file_and_auth(file_path):
    global FILE_PATH
    # Convert to absolute path to avoid 404 due to cwd issues
    FILE_PATH = os.path.abspath(file_path)
    print(f"[DEBUG] FILE_PATH set to: {FILE_PATH}")

def run_server(port=8000):
    global httpd
    handler = AuthHandler
    httpd = socketserver.TCPServer(("", port), handler)
    print(f"[+] Server started at http://127.0.0.1:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        stop_server()

def stop_server():
    global httpd
    if httpd:
        httpd.shutdown()
        httpd.server_close()
        print("[+] Server stopped")
        httpd = None
