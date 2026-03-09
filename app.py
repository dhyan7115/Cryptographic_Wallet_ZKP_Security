import json
import os
import time
import secrets
import random
import hashlib

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
)

from wallet.key_manager import generate_keypair
from wallet.address import generate_address
from wallet.storage import save_wallet, load_wallet
from wallet.signer import sign_transaction, verify_signature

app = Flask(__name__)
app.secret_key = "dev_secret_key"

USERS_FILE = "users.json"
LEDGER_FILE = "ledger.json"

# ZKP PARAMETERS (UNCHANGED)
p = 208351617316091241234326746312124448251235562226470491514186331217050270460481
g = 2

CHALLENGE_TIMEOUT = 60
ZKP_ROUNDS = 5

# USER STORAGE
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)


def load_ledger():
    if not os.path.exists(LEDGER_FILE):
        return {"balances": {}, "transactions": []}
    with open(LEDGER_FILE, "r") as f:
        return json.load(f)


def save_ledger(data):
    with open(LEDGER_FILE, "w") as f:
        json.dump(data, f, indent=4)

# HOME
@app.route("/")
def home():
    return redirect(url_for("login"))

# REGISTER (ZKP + WALLET)
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    secret = request.form.get("secret", "").strip()

    if not username or not secret:
        return "Invalid input"

    secret = int(secret)

    users = load_users()

    if username in users:
        return "User already exists"

    # ZKP public value
    y = pow(g, secret, p)

    # Generate wallet
    private_key, public_key = generate_keypair()
    address = generate_address(public_key)

    users[username] = {
        "zkp_public": y,
        "address": address,
        "public_key": public_key
    }

    save_users(users)
    save_wallet(username, private_key, public_key, address)

    # Initialize balance
    ledger = load_ledger()
    ledger["balances"][address] = 100
    save_ledger(ledger)

    return redirect(url_for("login"))

# LOGIN (UNCHANGED)
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()

    users = load_users()

    if username not in users:
        return "User not found"

    session.clear()
    session["zkp_user"] = username

    return render_template("zkp_auth.html", rounds=ZKP_ROUNDS)

# ZKP CHALLENGE
@app.route("/zkp_challenge", methods=["POST"])
def zkp_challenge():

    if "zkp_user" not in session:
        return jsonify({"error": "session_expired"}), 400

    data = request.get_json()
    t_list = data.get("t")

    if not isinstance(t_list, list) or len(t_list) != ZKP_ROUNDS:
        return jsonify({"error": "invalid_round_count"}), 400

    c_list = [random.randint(1, 10) for _ in range(ZKP_ROUNDS)]

    session["zkp_t"] = t_list
    session["zkp_c"] = c_list
    session["zkp_time"] = time.time()
    session["zkp_nonce"] = secrets.token_hex(16)

    return jsonify({
        "challenge": c_list,
        "nonce": session["zkp_nonce"],
        "rounds": ZKP_ROUNDS
    })

# ZKP VERIFY
@app.route("/zkp_verify", methods=["POST"])
def zkp_verify():

    if "zkp_user" not in session:
        return jsonify({"status": "fail"})

    data = request.get_json()
    s_list = data.get("s")
    client_nonce = data.get("nonce")

    if client_nonce != session.get("zkp_nonce"):
        return jsonify({"status": "fail"})

    username = session["zkp_user"]
    users = load_users()
    y = users[username]["zkp_public"]

    t_list = session["zkp_t"]
    c_list = session["zkp_c"]

    for i in range(ZKP_ROUNDS):
        t = int(t_list[i])
        c = int(c_list[i])
        s = int(s_list[i])

        left = pow(g, s, p)
        right = (t * pow(y, c, p)) % p

        if left != right:
            return jsonify({"status": "fail"})

    session.clear()
    session["user"] = username

    return jsonify({"status": "success"})

# DASHBOARD (NOW WITH BALANCE)
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect(url_for("login"))

    wallet = load_wallet(session["user"])
    ledger = load_ledger()

    balance = ledger["balances"].get(wallet["address"], 0)

    return render_template("dashboard.html", wallet=wallet, balance=balance)

# SEND TOKENS
@app.route("/send", methods=["GET", "POST"])
def send():

    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("send.html")

    recipient = request.form["recipient"]
    amount = int(request.form["amount"])

    wallet = load_wallet(session["user"])
    ledger = load_ledger()

    sender = wallet["address"]

    if ledger["balances"].get(sender, 0) < amount:
        return "Insufficient balance"

    tx_string = f"{sender}{recipient}{amount}"
    tx_hash = hashlib.sha256(tx_string.encode()).hexdigest()

    signature = sign_transaction(wallet["private_key"], tx_hash)    

    if not verify_signature(wallet["public_key"], tx_hash, signature):
        return "Signature verification failed"

    ledger["balances"][sender] -= amount
    ledger["balances"][recipient] = ledger["balances"].get(recipient, 0) + amount

    ledger["transactions"].append({
        "from": sender,
        "to": recipient,
        "amount": amount,
        "hash": tx_hash
    })

    save_ledger(ledger)

    return redirect(url_for("dashboard"))

# TRANSACTIONS
@app.route("/transactions")
def transactions():

    if "user" not in session:
        return redirect(url_for("login"))

    wallet = load_wallet(session["user"])
    ledger = load_ledger()
    address = wallet["address"]

    user_txs = [
        tx for tx in ledger["transactions"]
        if tx["from"] == address or tx["to"] == address
    ]

    return render_template("transactions.html", transactions=user_txs)

# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)