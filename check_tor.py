def start_server(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first!")
            return

        # Generate AES-256 session key
        aes_key = os.urandom(32)
        print(f"[+] Generated ephemeral AES-256 key")

        # Encrypt the file with AES
        encrypted_file_path = self.file_path + ".enc"
        if not self.encrypt_file_aes(self.file_path, encrypted_file_path, aes_key):
            messagebox.showerror("Error", "Failed to encrypt file!")
            return

        # Prepare file server
        set_file_and_auth(encrypted_file_path)

        # Start file server
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

        # Create onion service
        self.create_ephemeral_onion()

        # Token generation
        token = secrets.token_urlsafe(12)
        expiry = int(time.time()) + 300
        from file_server import add_valid_token
        add_valid_token(token, expiry)
        print(f"[+] One-time token generated: {token} (expires in 5 minutes)")

        # Encrypt AES key with receiver’s RSA public key
        with open("receiver_public.pem", "rb") as f:
            recv_pub = serialization.load_pem_public_key(f.read())

        encrypted_aes_key = recv_pub.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open("encrypted_aes_key.bin", "wb") as f:
            f.write(encrypted_aes_key)
        print("[+] AES key encrypted and saved to encrypted_aes_key.bin")

        # Payload (no AES key)
        payload = {
            "token": token,
            "url": self.onion_address + "/" + urllib.parse.quote(os.path.basename(encrypted_file_path)),
            "expiry": expiry,
            "file_hash": self.file_hash
        }
        plaintext = json.dumps(payload).encode()

        ciphertext = recv_pub.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open("encrypted_blob.bin", "wb") as f:
            f.write(ciphertext)
        print("[+] Encrypted blob (token + URL + hash) saved to encrypted_blob.bin")

        # Local testing URL
        local_url = f"http://127.0.0.1:8000/{os.path.basename(self.file_path)}.enc"
        with open("local_url.txt", "w") as f:
            f.write(local_url)

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status.config(text=f"Server running at {self.onion_address}\nAES-256 Encrypted\nSHA-256: {self.file_hash}")
