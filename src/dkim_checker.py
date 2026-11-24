import os
import base64
import dkim

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


KEY_DIR = "keys"
PRIVATE_KEY = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY = os.path.join(KEY_DIR, "public.pem")


def _get_private_key_bytes():
    encoded_key = os.getenv("DKIM_PRIVATE_KEY_B64")

    if encoded_key:
        try:
            private_bytes = base64.b64decode(encoded_key, validate=True)
            serialization.load_pem_private_key(
                private_bytes,
                password=None
            )
            return private_bytes
        except Exception as error:
            raise ValueError("Invalid DKIM private key configuration.") from error

    if not os.path.exists(PRIVATE_KEY):
        raise FileNotFoundError("Generate DKIM keys first.")

    with open(PRIVATE_KEY, "rb") as file:
        return file.read()


def generate_keys():
    if os.getenv("DKIM_PRIVATE_KEY_B64"):
        _get_private_key_bytes()
        return "Configured DKIM key loaded successfully."

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
    private_key = _get_private_key_bytes()

    signature = dkim.sign(
        email_bytes,
        selector.encode(),
        domain.encode(),
        private_key,
        canonicalize=(b"relaxed", b"simple")
    )

    return signature + email_bytes


def local_dns_lookup(name, timeout=5):
    try:
        private_bytes = _get_private_key_bytes()
    except FileNotFoundError:
        return None

    private_key = serialization.load_pem_private_key(
        private_bytes,
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
