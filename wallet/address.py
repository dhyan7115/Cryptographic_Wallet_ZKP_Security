import hashlib


def generate_address(public_key_hex):
    """
    Generate wallet address from public key
    """
    public_bytes = bytes.fromhex(public_key_hex)

    sha = hashlib.sha256(public_bytes).digest()
    ripemd = hashlib.new("ripemd160", sha).hexdigest()

    return ripemd