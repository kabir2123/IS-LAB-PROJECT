# sender.py
import tkinter as tk
from tkinter import filedialog, messagebox
import threading, os, hashlib
from file_server import run_server, stop_server, set_file_and_auth
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import secrets, time, json
import urllib.parse, os
# Tor imports
from stem.control import Controller

TOR_CONTROL_PORT = 9051

class SenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PyTorShare - Sender")

        # File selection
        tk.Label(root, text="Select File to Share:").pack(pady=5)
        self.file_label = tk.Label(root, text="No file selected", fg="red")
        self.file_label.pack()
        tk.Button(root, text="Browse", command=self.browse_file).pack(pady=5)

        # Username & Password
        tk.Label(root, text="Username:").pack(pady=2)
        self.username_entry = tk.Entry(root)
        self.username_entry.pack()

        tk.Label(root, text="Password:").pack(pady=2)
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        # Start/Stop buttons
        self.start_btn = tk.Button(root, text="Start Sharing", command=self.start_server, bg="green", fg="white")
        self.start_btn.pack(pady=10)

        self.stop_btn = tk.Button(root, text="Stop Sharing", command=self.stop_server, bg="red", fg="white", state=tk.DISABLED)
        self.stop_btn.pack(pady=5)

        # Status area
        self.status = tk.Label(root, text="Status: Idle", fg="blue")
        self.status.pack(pady=10)

        # Copy SHA button
        self.copy_sha_btn = tk.Button(root, text="Copy SHA-256", command=self.copy_sha, state=tk.DISABLED)
        self.copy_sha_btn.pack(pady=5)
            
        # Variables
        self.file_path = None
        self.file_hash = None
        self.server_thread = None
        self.onion_address = None

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path = file_path
            self.file_hash = self.compute_hash(file_path)

                # --- NEW: Sign the hash ---
            with open("sender_private.pem", "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            signature = private_key.sign(
                bytes.fromhex(self.file_hash),
                padding.PKCS1v15(),
                hashes.SHA256()
        )

        sig_path = self.file_path + ".sig"
        with open(sig_path, "wb") as f:
            f.write(signature)

        file_size = os.path.getsize(file_path)
        self.file_label.config(text=f"{os.path.basename(file_path)} ({file_size} bytes)")
        self.status.config(text=f"File hash (SHA-256): {self.file_hash}")
        self.copy_sha_btn.config(state=tk.NORMAL)

        print(f"[+] Signature written to {sig_path}")

    def compute_hash(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()

    def start_server(self):
    
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return
        set_file_and_auth(self.file_path)
        # Start server thread
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

        # Create ephemeral onion
        self.create_ephemeral_onion()

        token = secrets.token_urlsafe(12)
        expiry = int(time.time()) + 300  # 5 minutes TTL

        from file_server import add_valid_token
        add_valid_token(token, expiry)
        print(f"[+] One-time token generated: {token} (expires in 5 minutes)")

        # Prepare payload for receiver
        payload = {
            "token": token,
            "url": self.onion_address + "/" + urllib.parse.quote(os.path.basename(self.file_path)),
            "expiry": expiry
        }
        plaintext = json.dumps(payload).encode()

        # Encrypt with receiver's public key
        with open("receiver_public.pem", "rb") as f:
            recv_pub = serialization.load_pem_public_key(f.read())

        ciphertext = recv_pub.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Save encrypted blob
        with open("encrypted_blob.bin", "wb") as f:
            f.write(ciphertext)
        print("[+] Encrypted token+URL saved to encrypted_blob.bin")

        # Update GUI
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status.config(text=f"Server running at {self.onion_address}\nSHA-256: {self.file_hash}")

    def stop_server(self):
        stop_server()
        self.status.config(text="Server stopped")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def create_ephemeral_onion(self):
        try:
            with Controller.from_port(port=TOR_CONTROL_PORT) as c:
                c.authenticate()  # cookie auth
                print("[+] Connected to Tor")
                print("[+] Tor version:", c.get_version())

                # Create a single ephemeral hidden service mapping local port 8000 → onion 80
                result = c.create_ephemeral_hidden_service({80: 8000}, await_publication=True)
                self.onion_address = f"http://{result.service_id}.onion"
                print("[+] Ephemeral Onion service created:", self.onion_address)

                # Save to file for receiver
            

            # For local testing, generate a URL pointing to localhost + encoded filename
            local_url = f"http://127.0.0.1:8000/{os.path.basename(self.file_path)}"

            with open("local_url.txt", "w") as f:
                f.write(local_url)


        except Exception as e:
            messagebox.showerror("Tor Error", f"Failed to create ephemeral onion:\n{e}")
            print("[-] Tor error:", e)
            
    def copy_sha(self):
        if self.file_hash:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.file_hash)
            messagebox.showinfo("Copied", "SHA-256 hash copied to clipboard!")

if __name__ == "__main__":
    root = tk.Tk()
    app = SenderGUI(root)
    root.mainloop()
