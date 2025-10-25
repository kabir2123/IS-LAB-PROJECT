# receiver.py
import os
import json
import time
import requests
import base64
import urllib.parse
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.exceptions import InvalidSignature
from hashlib import sha256

# --- Load receiver private key (to decrypt AES key) ---
try:
    with open("receiver_private.pem", "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
except FileNotFoundError:
    print("[-] receiver_private.pem not found. Place the private key in this folder.")
    raise SystemExit(1)
except Exception as e:
    print("[-] Failed to load receiver private key:", e)
    raise SystemExit(1)

# --- Load encrypted blob (JSON containing iv, RSA-encrypted AES key, ciphertext) ---
if not os.path.exists("encrypted_blob.bin"):
    print("[-] encrypted_blob.bin not found. Run sender to create one.")
    raise SystemExit(1)

with open("encrypted_blob.bin", "r") as f:
    blob = json.load(f)

try:
    iv = base64.b64decode(blob["iv"])
    encrypted_key = base64.b64decode(blob["key"])
    ciphertext = base64.b64decode(blob["ciphertext"])
except Exception as e:
    print("[-] Malformed encrypted_blob.bin:", e)
    raise SystemExit(1)

# --- Decrypt AES key with receiver private RSA key ---
try:
    aes_key = priv.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
except Exception as e:
    print("[-] Failed to decrypt AES key:", e)
    raise SystemExit(1)

# --- Decrypt payload with AES-256-CBC ---
try:
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext_bytes = unpadder.update(padded_plain) + unpadder.finalize()

    payload = json.loads(plaintext_bytes.decode())
except Exception as e:
    print("[-] Failed to decrypt or parse payload:", e)
    raise SystemExit(1)

token = payload.get("token")
expiry = payload.get("expiry")
file_hash_expected = payload.get("file_hash")
filename = payload.get("filename")
payload_url = payload.get("url")

# --- Check expiry locally ---
if not token or not expiry:
    print("[-] Malformed payload: missing token/expiry.")
    raise SystemExit(1)

if time.time() > expiry:
    print("❌ Token expired before use!")
    raise SystemExit(1)

# For local testing, if local_url.txt exists prefer it
if os.path.exists("local_url.txt"):
    with open("local_url.txt", "r") as f:
        local_url = f.read().strip()
    use_url = local_url
    print("[*] Using local_url.txt for testing:", use_url)
else:
    use_url = payload_url

if not use_url:
    print("[-] No URL available to download file.")
    raise SystemExit(1)

# Build download URLs. Append token as query param.
def append_token(url, token):
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    # Keep existing query params, add token
    qs["token"] = [token]
    new_query = urllib.parse.urlencode({k: v[0] for k, v in qs.items()})
    new_parsed = parsed._replace(query=new_query)
    return urllib.parse.urlunparse(new_parsed)

download_url = append_token(use_url, token)
download_sig_url = append_token(use_url + ".sig", token)

print(f"[+] Downloading file from: {download_url}")
print(f"[+] Downloading signature from: {download_sig_url}")

out_file = f"downloaded_{filename or 'file'}"
out_sig = out_file + ".sig"

success = True
try:
    r = requests.get(download_url, stream=True, timeout=60)
    if r.status_code != 200:
        print(f"❌ HTTP error while downloading file: {r.status_code}")
        success = False
    else:
        with open(out_file, "wb") as f:
            for chunk in r.iter_content(4096):
                if chunk:
                    f.write(chunk)
except Exception as e:
    print("❌ Download error (file):", e)
    success = False

try:
    r = requests.get(download_sig_url, stream=True, timeout=60)
    if r.status_code != 200:
        print(f"❌ HTTP error while downloading signature: {r.status_code}")
        success = False
    else:
        with open(out_sig, "wb") as f:
            for chunk in r.iter_content(4096):
                if chunk:
                    f.write(chunk)
except Exception as e:
    print("❌ Download error (sig):", e)
    success = False

if not success:
    print("❌ Download failed!")
    raise SystemExit(1)

# Verify SHA-256 hash (if provided)
with open(out_file, "rb") as f:
    file_bytes = f.read()
actual_hash = sha256(file_bytes).hexdigest()

if file_hash_expected:
    if actual_hash != file_hash_expected:
        print("[-] Hash mismatch! File may be corrupted.")
        raise SystemExit(1)
    else:
        print("[+] SHA-256 hash matches expected value.")

# Verify signature with sender_public.pem (if available)
try:
    with open(out_sig, "rb") as f:
        signature = f.read()
except Exception as e:
    print("[-] Failed to read downloaded signature:", e)
    raise SystemExit(1)

try:
    with open("sender_public.pem", "rb") as f:
        sender_pub = serialization.load_pem_public_key(f.read())
except FileNotFoundError:
    print("[-] sender_public.pem not found — cannot verify signature.")
    raise SystemExit(1)
except Exception as e:
    print("[-] Failed to load sender public key:", e)
    raise SystemExit(1)

# The sender signed the hex digest bytes (bytes.fromhex(hash))
try:
    sender_pub.verify(
        signature,
        bytes.fromhex(actual_hash),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("✅ Signature verified! File is authentic and intact.")
    print(f"[+] Saved as: {out_file} and signature {out_sig}")
except InvalidSignature:
    print("❌ Signature verification failed! Possible tampering.")
    raise SystemExit(1)
except Exception as e:
    print("[-] Signature verification error:", e)
    raise SystemExit(1)
