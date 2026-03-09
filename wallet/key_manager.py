from ecdsa import SigningKey, SECP256k1


def generate_keypair():
    """
    Generate ECC key pair (secp256k1)
    """
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()

    private_key = sk.to_string().hex()
    public_key = vk.to_string().hex()

    return private_key, public_key