import json
import os
from cryptography.fernet import Fernet

KEY_FILE = "wallet/master.key"


def _load_or_create_master_key():
    os.makedirs("wallet", exist_ok=True)

    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()

    return Fernet(key)


cipher = _load_or_create_master_key()


def save_wallet(username, private_key, public_key, address):
    encrypted_pk = cipher.encrypt(private_key.encode()).decode()

    data = {
        "public_key": public_key,
        "private_key": encrypted_pk,
        "address": address,
    }

    with open(f"wallet/wallet_{username}.json", "w") as f:
        json.dump(data, f, indent=2)


def load_wallet(username):
    path = f"wallet/wallet_{username}.json"
    if not os.path.exists(path):
        return None

    with open(path, "r") as f:
        data = json.load(f)

    decrypted_pk = cipher.decrypt(data["private_key"].encode()).decode()
    data["private_key"] = decrypted_pk
    return data