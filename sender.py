# sender.py
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
import hashlib
import secrets
import time
import json
import urllib.parse
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# Tor imports
from stem.control import Controller

TOR_CONTROL_PORT = 9051

# file_server functions expected: set_file_and_auth(file_path), add_valid_token(token, expiry), run_server(), stop_server()
from file_server import set_file_and_auth, add_valid_token, run_server, stop_server


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
        if not file_path:
            return

        self.file_path = file_path
        try:
            self.file_hash = self.compute_hash(file_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to compute file hash: {e}")
            return

        # --- Sign the hash with sender_private.pem ---
        sig_path = self.file_path + ".sig"
        try:
            with open("sender_private.pem", "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            signature = private_key.sign(
                bytes.fromhex(self.file_hash),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            with open(sig_path, "wb") as f:
                f.write(signature)

            print(f"[+] Signature written to {sig_path}")

        except FileNotFoundError:
            messagebox.showwarning("Missing key", "sender_private.pem not found — signature not created.")
            print("[-] sender_private.pem not found; skipping signature creation.")
        except Exception as e:
            messagebox.showerror("Signing Error", f"Failed to sign file hash: {e}")
            print("[-] Signing error:", e)

        file_size = os.path.getsize(file_path)
        self.file_label.config(text=f"{os.path.basename(file_path)} ({file_size} bytes)")
        self.status.config(text=f"File hash (SHA-256): {self.file_hash}")
        self.copy_sha_btn.config(state=tk.NORMAL)

    def compute_hash(self, file_path):
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()

    def start_server(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return

        # Ensure file_server knows which file to serve
        set_file_and_auth(self.file_path)

        # Start server thread (file_server.run_server should block; we run it in a daemon thread)
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

        # Create ephemeral onion service
        self.create_ephemeral_onion()

        # Generate one-time token and expiry
        token = secrets.token_urlsafe(12)
        expiry = int(time.time()) + 300  # 5 minutes TTL

        # Register token with file_server
        try:
            add_valid_token(token, expiry)
        except Exception as e:
            print("[-] add_valid_token error:", e)

        print(f"[+] One-time token generated: {token} (expires in 5 minutes)")

        # Prepare payload for receiver (include file_hash to allow verification)
        filename = os.path.basename(self.file_path)
        if self.onion_address:
            onion_url = self.onion_address + "/" + urllib.parse.quote(filename)
        else:
            # For local testing, point to localhost URL
            onion_url = f"http://127.0.0.1:8000/{urllib.parse.quote(filename)}"

        payload_dict = {
            "token": token,
            "url": onion_url,
            "expiry": expiry,
            "file_hash": self.file_hash,
            "filename": filename
        }
        plaintext = json.dumps(payload_dict).encode()

        # HYBRID ENCRYPTION: AES encrypt plaintext, then RSA-encrypt AES key
        try:
            # Load receiver public key
            with open("receiver_public.pem", "rb") as f:
                recv_pub = serialization.load_pem_public_key(f.read())

            # AES key + IV
            aes_key = secrets.token_bytes(32)  # 256-bit key
            iv = secrets.token_bytes(16)

            # PKCS7 pad plaintext
            padder = sym_padding.PKCS7(128).padder()
            padded = padder.update(plaintext) + padder.finalize()

            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded) + encryptor.finalize()

            # Encrypt AES key with RSA-OAEP
            encrypted_key = recv_pub.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Save encrypted bundle as JSON
            blob = {
                "iv": base64.b64encode(iv).decode(),
                "key": base64.b64encode(encrypted_key).decode(),  # RSA-encrypted AES key
                "ciphertext": base64.b64encode(ciphertext).decode()
            }
            with open("encrypted_blob.bin", "w") as f:
                json.dump(blob, f)

            print("[+] Hybrid-encrypted blob saved to encrypted_blob.bin")

        except FileNotFoundError:
            messagebox.showerror("Key error", "receiver_public.pem not found — cannot encrypt payload.")
            print("[-] receiver_public.pem not found; payload not encrypted.")
            return
        except Exception as e:
            messagebox.showerror("Encryption error", f"Failed to encrypt payload: {e}")
            print("[-] Encryption failed:", e)
            return

        # Update GUI
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status.config(text=f"Server running at {self.onion_address or 'http://127.0.0.1:8000'}\nSHA-256: {self.file_hash}")

    def stop_server(self):
        try:
            stop_server()
        except Exception as e:
            print("[-] stop_server error:", e)
        self.status.config(text="Server stopped")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def create_ephemeral_onion(self):
        try:
            with Controller.from_port(port=TOR_CONTROL_PORT) as c:
                c.authenticate()  # cookie auth
                print("[+] Connected to Tor")
                print("[+] Tor version:", c.get_version())

                # Create ephemeral hidden service mapping local port 8000 → onion 80
                result = c.create_ephemeral_hidden_service({80: 8000}, await_publication=True)
                self.onion_address = f"http://{result.service_id}.onion"
                print("[+] Ephemeral Onion service created:", self.onion_address)

                # Save local test URL for receiver testing
                local_url = f"http://127.0.0.1:8000/{os.path.basename(self.file_path)}"
                with open("local_url.txt", "w") as f:
                    f.write(local_url)

        except Exception as e:
            messagebox.showerror("Tor Error", f"Failed to create ephemeral onion:\n{e}")
            print("[-] Tor error:", e)
            # For local testing, still write local_url if file set
            try:
                local_url = f"http://127.0.0.1:8000/{os.path.basename(self.file_path)}"
                with open("local_url.txt", "w") as f:
                    f.write(local_url)
            except Exception:
                pass

    def copy_sha(self):
        if self.file_hash:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.file_hash)
            messagebox.showinfo("Copied", "SHA-256 hash copied to clipboard!")


if __name__ == "__main__":
    root = tk.Tk()
    app = SenderGUI(root)
    root.mainloop()
