import os
import base64
import dkim

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


KEY_DIR = "keys"
PRIVATE_KEY = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY = os.path.join(KEY_DIR, "public.pem")


def generate_keys():
    os.makedirs(KEY_DIR, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(PRIVATE_KEY, "wb") as file:
        file.write(private_bytes)

    with open(PUBLIC_KEY, "wb") as file:
        file.write(public_bytes)

    return "RSA key pair generated successfully."


def sign_email(email_bytes, domain, selector):
    if not os.path.exists(PRIVATE_KEY):
        raise FileNotFoundError("Generate DKIM keys first.")

    with open(PRIVATE_KEY, "rb") as file:
        private_key = file.read()

    signature = dkim.sign(
        email_bytes,
        selector.encode(),
        domain.encode(),
        private_key,
        canonicalize=(b"relaxed", b"simple")
    )

    return signature + email_bytes


def local_dns_lookup(name, timeout=5):
    if not os.path.exists(PRIVATE_KEY):
        return None

    with open(PRIVATE_KEY, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None
        )

    public_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1
    )

    public_key = base64.b64encode(public_der)

    return b"v=DKIM1; k=rsa; p=" + public_key


def verify_email(signed_email):
    try:
        return dkim.verify(
            signed_email,
            dnsfunc=local_dns_lookup
        )
    except Exception:
        return False
