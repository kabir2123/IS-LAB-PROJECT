# generate_keys.py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Generate sender keys ---
sender_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open("sender_private.pem", "wb") as f:
    f.write(sender_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
with open("sender_public.pem", "wb") as f:
    f.write(sender_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# --- Generate receiver keys ---
receiver_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open("receiver_private.pem", "wb") as f:
    f.write(receiver_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
with open("receiver_public.pem", "wb") as f:
    f.write(receiver_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("✅ Sender keys: sender_private.pem, sender_public.pem")
print("✅ Receiver keys: receiver_private.pem, receiver_public.pem")