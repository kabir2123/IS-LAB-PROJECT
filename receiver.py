# receiver.py
import requests
import hashlib
import json
import time
import urllib.parse
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from hashlib import sha256

# --- Load receiver private key ---
with open("receiver_private.pem", "rb") as f:
    priv = serialization.load_pem_private_key(f.read(), password=None)

# --- Read encrypted blob ---
with open("encrypted_blob.bin", "rb") as f:
    ciphertext = f.read()

# --- Decrypt payload ---
plaintext = priv.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
payload = json.loads(plaintext.decode())
token = payload["token"]
expiry = payload["expiry"]

# --- Check expiry locally ---
if time.time() > expiry:
    print("❌ Token expired before use!")
    exit(1)

# --- Read local URL for testing ---
with open("local_url.txt", "r") as f:
    local_url = f.read().strip()

# --- Build download URLs ---
download_urls = [
    f"{local_url}?token={token}",            # main file
    f"{local_url}.sig?token={token}"        # signature
]

downloaded_files = ["downloaded.txt", "downloaded.txt.sig"]

# --- Download both files ---
success = True
for url, outfile in zip(download_urls, downloaded_files):
    print(f"[+] Downloading: {url}")
    try:
        r = requests.get(url, stream=True, timeout=60)
        if r.status_code != 200:
            print(f"❌ HTTP error while downloading {url}: {r.status_code}")
            success = False
            continue
        with open(outfile, "wb") as f:
            for chunk in r.iter_content(4096):
                if chunk:
                    f.write(chunk)
    except Exception as e:
        print(f"❌ Download error: {e}")
        success = False

if not success:
    print("❌ Download failed!")
    exit(1)

# --- Verify SHA-256 hash ---
with open("downloaded.txt", "rb") as f:
    file_bytes = f.read()
actual_hash = hashlib.sha256(file_bytes).hexdigest()

expected_hash = payload.get("file_hash")
if expected_hash:
    if actual_hash != expected_hash:
        print("[-] Hash mismatch! File may be corrupted.")
        exit(1)

# --- Verify signature ---
with open("downloaded.txt.sig", "rb") as f:
    signature = f.read()

with open("sender_public.pem", "rb") as f:
    sender_pub = serialization.load_pem_public_key(f.read())

actual_hash = sha256(file_bytes).hexdigest()
try:
    sender_pub.verify(
        signature,
        bytes.fromhex(actual_hash),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("✅ Signature verified! File is authentic and intact.")
except InvalidSignature:
    print("❌ Signature verification failed! Possible tampering.")
