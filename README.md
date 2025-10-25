# PyTorShare - Secure File Sharing with Tor + AES Encryption

A secure file sharing system that combines **Tor anonymity**, **AES-256 encryption**, and **RSA key exchange** for maximum security.

## 🔐 Security Features

- ✅ **Tor Hidden Services** - Anonymous file sharing
- ✅ **AES-256 Encryption** - File content protection
- ✅ **RSA-2048 Key Exchange** - Secure AES key transmission
- ✅ **SHA-256 Hashing** - File integrity verification
- ✅ **Digital Signatures** - File authenticity proof
- ✅ **Token-based Access** - One-time download tokens
- ✅ **Ephemeral Keys** - One-time AES keys per transfer

## 📋 Requirements

- Python 3.7+
- Tor Browser or Tor service running on port 9051

## 🚀 Installation

```bash
pip install -r requirements.txt
```

## 🔑 Setup

1. **Generate RSA keys:**
   ```bash
   python3 generate_keys.py
   ```

2. **Make sure Tor is running:**
   - Start Tor Browser, or
   - Run Tor service with control port 9051

## 📤 Usage - Sender

```bash
python3 sender.py
```

**In the GUI:**
1. Click "Browse" and select a file to share
2. Click "Start Sharing"
3. Share the `encrypted_blob.bin` and `encrypted_aes_key.bin` files with the receiver

**Files created:**
- `encrypted_blob.bin` - Contains token and URL (RSA encrypted)
- `encrypted_aes_key.bin` - Contains AES encryption key (RSA encrypted)
- `{filename}.enc` - AES-encrypted file
- `{filename}.sig` - Digital signature

## 📥 Usage - Receiver

```bash
python3 receiver.py
```

**What happens automatically:**
- Decrypts AES key from `encrypted_aes_key.bin`
- Downloads encrypted file via Tor
- Decrypts file with AES key
- Verifies hash and signature
- Saves decrypted file as `downloaded.txt`

## 🔒 Security Flow

```
SENDER:
  ├─ Generate AES-256 key
  ├─ Encrypt file with AES
  ├─ Encrypt AES key with RSA
  ├─ Create Tor hidden service
  └─ Generate one-time token

NETWORK:
  ├─ Encrypted file over Tor
  ├─ Only accessible with valid token
  └─ Content protected by AES

RECEIVER:
  ├─ Decrypt AES key with RSA
  ├─ Download encrypted file
  ├─ Decrypt file with AES
  ├─ Verify SHA-256 hash
  └─ Verify digital signature
```

## 📁 Project Structure

```
IS-LAB-PROJECT-master/
├── sender.py              # GUI sender application
├── receiver.py            # Command-line receiver
├── file_server.py         # HTTP server with token auth
├── generate_keys.py       # RSA key pair generator
├── check_tor.py           # Tor connection checker
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🎓 Features

- **Hybrid Cryptography** - RSA + AES for optimal security and performance
- **Ephemeral Services** - Temporary Tor hidden services
- **Key Lifecycle Management** - Proper generation, use, and destruction
- **CIA Triad Compliance** - Confidentiality, Integrity, Authentication
- **Industry Standards** - Follows cryptographic best practices

## ⚠️ Important Notes

- Tokens expire in 5 minutes
- Ephemeral AES keys are generated per transfer
- Files are automatically cleaned up after use
- Tor must be running before starting sender

## 🔐 Key Files

- **sender_private.pem** / **sender_public.pem** - Sender's RSA keys
- **receiver_private.pem** / **receiver_public.pem** - Receiver's RSA keys
- **encrypted_blob.bin** - RSA-encrypted token + URL
- **encrypted_aes_key.bin** - RSA-encrypted AES key

## 📝 License

Educational project for Information Security Lab

