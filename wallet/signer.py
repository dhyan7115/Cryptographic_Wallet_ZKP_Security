# from ecdsa import SigningKey, VerifyingKey, SECP256k1


# def sign_message(private_key_hex, message):
#     sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
#     signature = sk.sign(message.encode())
#     return signature.hex()


# def verify_signature(public_key_hex, message, signature_hex):
#     vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
#     return vk.verify(bytes.fromhex(signature_hex), message.encode())
import hashlib
import base64
from ecdsa import SigningKey, VerifyingKey, SECP256k1


# =========================
# SIGN TRANSACTION
# =========================

def sign_transaction(private_key_hex, message_hash):
    """
    Signs a hashed message using the private key.

    :param private_key_hex: hex string of private key
    :param message_hash: SHA256 hash string (hex)
    :return: base64 encoded signature
    """

    # Convert hex private key to SigningKey object
    private_key_bytes = bytes.fromhex(private_key_hex)
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)

    # Sign the hash
    signature = signing_key.sign(message_hash.encode())

    # Encode signature to base64 for storage
    return base64.b64encode(signature).decode()


# =========================
# VERIFY SIGNATURE
# =========================

def verify_signature(public_key_hex, message_hash, signature_b64):
    """
    Verifies a signed message.

    :param public_key_hex: hex string of public key
    :param message_hash: original SHA256 hash string (hex)
    :param signature_b64: base64 encoded signature
    :return: True or False
    """

    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)

        signature = base64.b64decode(signature_b64)

        return verifying_key.verify(signature, message_hash.encode())

    except Exception:
        return False