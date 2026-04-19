"""
CipherForge - Web-Based Text Encryption Tool
Backend: Python (Flask) + PyCryptodome
Assignment A2
"""

from flask import Flask, request, jsonify, render_template, session
from functools import wraps
import json
import os
import hashlib
import base64
import string

# ── PyCryptodome imports ──────────────────────────────────────
from Crypto.Cipher import AES, DES3, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA512, SHA1, MD5, SHA3_256, RIPEMD160

app = Flask(__name__)
app.secret_key = "cipherforge_secret_key_2024"

# ── Simple file-based user database ──────────────────────────
DB_FILE = "users.json"

def load_db():
    if not os.path.exists(DB_FILE):
        # Seed admin account
        db = {"admin": {"password": hash_password("admin123"), "messages": []}}
        save_db(db)
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)

def hash_password(password):
    return hashlib.sha256((password + "cf_salt_2024").encode()).hexdigest()


# ── Auth decorator ────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════
#  ENCRYPTION ALGORITHMS
# ══════════════════════════════════════════════════════════════

# ── 1. Caesar Cipher ─────────────────────────────────────────
def caesar_encrypt(text, shift):
    shift = int(shift) % 26
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, 26 - (int(shift) % 26))


# ── 2. Vigenère Cipher ───────────────────────────────────────
def vigenere_encrypt(text, key):
    key = ''.join(c for c in key.lower() if c.isalpha())
    if not key:
        raise ValueError("Vigenère key must contain alphabetic characters")
    result = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

def vigenere_decrypt(text, key):
    key = ''.join(c for c in key.lower() if c.isalpha())
    if not key:
        raise ValueError("Vigenère key must contain alphabetic characters")
    result = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[ki % len(key)]) - ord('a')
            result.append(chr((ord(ch) - base - shift + 26) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)


# ── 3. AES-256 ───────────────────────────────────────────────
def aes_encrypt(text, key):
    if not key:
        raise ValueError("AES-256 requires a secret key")
    # Derive a 32-byte key using SHA-256
    key_bytes = SHA256.new(key.encode()).digest()
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    # Return iv + ciphertext as base64
    return base64.b64encode(iv + ct).decode('utf-8')

def aes_decrypt(text, key):
    if not key:
        raise ValueError("AES-256 requires the same secret key used for encryption")
    try:
        key_bytes = SHA256.new(key.encode()).digest()
        raw = base64.b64decode(text)
        iv = raw[:16]
        ct = raw[16:]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception:
        raise ValueError("Decryption failed: wrong key or corrupted ciphertext")


# ── 4. Triple-DES (3DES) ─────────────────────────────────────
def des3_encrypt(text, key):
    if not key:
        raise ValueError("Triple-DES requires a secret key")
    # Derive a 24-byte key (3DES requirement)
    key_bytes = SHA256.new(key.encode()).digest()[:24]
    iv = get_random_bytes(8)
    cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
    ct = cipher.encrypt(pad(text.encode('utf-8'), DES3.block_size))
    return base64.b64encode(iv + ct).decode('utf-8')

def des3_decrypt(text, key):
    if not key:
        raise ValueError("Triple-DES requires the same key used for encryption")
    try:
        key_bytes = SHA256.new(key.encode()).digest()[:24]
        raw = base64.b64decode(text)
        iv = raw[:8]
        ct = raw[8:]
        cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), DES3.block_size)
        return pt.decode('utf-8')
    except Exception:
        raise ValueError("Decryption failed: wrong key or corrupted ciphertext")


# ── 5. RC4 ───────────────────────────────────────────────────
def rc4_encrypt(text, key):
    if not key:
        raise ValueError("RC4 requires a secret key")
    cipher = ARC4.new(key.encode('utf-8'))
    ct = cipher.encrypt(text.encode('utf-8'))
    return base64.b64encode(ct).decode('utf-8')

def rc4_decrypt(text, key):
    if not key:
        raise ValueError("RC4 requires the same key used for encryption")
    try:
        cipher = ARC4.new(key.encode('utf-8'))
        pt = cipher.decrypt(base64.b64decode(text))
        return pt.decode('utf-8')
    except Exception:
        raise ValueError("Decryption failed: wrong key or corrupted data")


# ── 6. Base64 ────────────────────────────────────────────────
def base64_encrypt(text):
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')

def base64_decrypt(text):
    try:
        return base64.b64decode(text).decode('utf-8')
    except Exception:
        raise ValueError("Invalid Base64 string")


# ── 7. Atbash ────────────────────────────────────────────────
def atbash(text):
    result = []
    for ch in text:
        if ch.islower():
            result.append(chr(ord('z') - (ord(ch) - ord('a'))))
        elif ch.isupper():
            result.append(chr(ord('Z') - (ord(ch) - ord('A'))))
        else:
            result.append(ch)
    return ''.join(result)


# ── 8. ROT-13 ────────────────────────────────────────────────
def rot13(text):
    return caesar_encrypt(text, 13)


# ══════════════════════════════════════════════════════════════
#  HASHING
# ══════════════════════════════════════════════════════════════

def do_hash(text, algorithm):
    algos = {
        "sha256":  lambda: SHA256.new(text.encode()).hexdigest(),
        "sha512":  lambda: SHA512.new(text.encode()).hexdigest(),
        "sha1":    lambda: SHA1.new(text.encode()).hexdigest(),
        "md5":     lambda: MD5.new(text.encode()).hexdigest(),
        "sha3":    lambda: SHA3_256.new(text.encode()).hexdigest(),
        "ripemd":  lambda: RIPEMD160.new(text.encode()).hexdigest(),
    }
    if algorithm not in algos:
        raise ValueError(f"Unknown hash algorithm: {algorithm}")
    return algos[algorithm]()


# ══════════════════════════════════════════════════════════════
#  ROUTES - Pages
# ══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


# ══════════════════════════════════════════════════════════════
#  ROUTES - Auth API
# ══════════════════════════════════════════════════════════════

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    confirm  = data.get("confirm", "")

    if not username or not password:
        return jsonify({"error": "All fields are required"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400

    db = load_db()
    if username in db:
        return jsonify({"error": "Username already exists"}), 409

    db[username] = {"password": hash_password(password), "messages": []}
    save_db(db)
    return jsonify({"message": "Account created successfully"})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "All fields are required"}), 400

    db = load_db()
    if username not in db or db[username]["password"] != hash_password(password):
        return jsonify({"error": "Invalid username or password"}), 401

    session["username"] = username
    return jsonify({"message": "Login successful", "username": username})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route("/api/me")
def me():
    if "username" in session:
        return jsonify({"username": session["username"]})
    return jsonify({"username": None})


# ══════════════════════════════════════════════════════════════
#  ROUTES - Encryption API
# ══════════════════════════════════════════════════════════════

@app.route("/api/encrypt", methods=["POST"])
@login_required
def encrypt():
    data      = request.get_json()
    text      = data.get("text", "")
    algorithm = data.get("algorithm", "")
    key       = data.get("key", "")
    shift     = data.get("shift", 13)

    if not text.strip():
        return jsonify({"error": "Plain text cannot be empty"}), 400
    if not algorithm:
        return jsonify({"error": "Please select an encryption algorithm"}), 400

    try:
        result = None
        if   algorithm == "caesar":   result = caesar_encrypt(text, shift)
        elif algorithm == "vigenere": result = vigenere_encrypt(text, key)
        elif algorithm == "aes":      result = aes_encrypt(text, key)
        elif algorithm == "des":      result = des3_encrypt(text, key)
        elif algorithm == "rc4":      result = rc4_encrypt(text, key)
        elif algorithm == "base64":   result = base64_encrypt(text)
        elif algorithm == "atbash":   result = atbash(text)
        elif algorithm == "rot13":    result = rot13(text)
        else:
            return jsonify({"error": f"Unknown algorithm: {algorithm}"}), 400

        return jsonify({"result": result, "algorithm": algorithm})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/decrypt", methods=["POST"])
@login_required
def decrypt():
    data      = request.get_json()
    text      = data.get("text", "")
    algorithm = data.get("algorithm", "")
    key       = data.get("key", "")
    shift     = data.get("shift", 13)

    if not text.strip():
        return jsonify({"error": "Ciphertext cannot be empty"}), 400
    if not algorithm:
        return jsonify({"error": "Please select an algorithm"}), 400

    try:
        result = None
        if   algorithm == "caesar":   result = caesar_decrypt(text, shift)
        elif algorithm == "vigenere": result = vigenere_decrypt(text, key)
        elif algorithm == "aes":      result = aes_decrypt(text, key)
        elif algorithm == "des":      result = des3_decrypt(text, key)
        elif algorithm == "rc4":      result = rc4_decrypt(text, key)
        elif algorithm == "base64":   result = base64_decrypt(text)
        elif algorithm == "atbash":   result = atbash(text)
        elif algorithm == "rot13":    result = rot13(text)
        else:
            return jsonify({"error": f"Unknown algorithm: {algorithm}"}), 400

        return jsonify({"result": result, "algorithm": algorithm})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/hash", methods=["POST"])
@login_required
def hash_route():
    data      = request.get_json()
    text      = data.get("text", "")
    algorithm = data.get("algorithm", "sha256")

    if not text.strip():
        return jsonify({"error": "Input text cannot be empty"}), 400

    try:
        result = do_hash(text, algorithm)
        return jsonify({"result": result, "algorithm": algorithm})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# ══════════════════════════════════════════════════════════════
#  ROUTES - Saved Messages API
# ══════════════════════════════════════════════════════════════

@app.route("/api/messages", methods=["GET"])
@login_required
def get_messages():
    db = load_db()
    messages = db[session["username"]].get("messages", [])
    return jsonify({"messages": messages})


@app.route("/api/messages", methods=["POST"])
@login_required
def save_message():
    data = request.get_json()
    ciphertext = data.get("ciphertext", "")
    algorithm  = data.get("algorithm", "")

    if not ciphertext:
        return jsonify({"error": "Nothing to save"}), 400

    from datetime import datetime
    db = load_db()
    user = session["username"]
    msg = {
        "id": int(datetime.now().timestamp() * 1000),
        "algorithm": algorithm,
        "ciphertext": ciphertext,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    db[user]["messages"].insert(0, msg)
    save_db(db)
    return jsonify({"message": "Saved successfully", "id": msg["id"]})


@app.route("/api/messages/<int:msg_id>", methods=["DELETE"])
@login_required
def delete_message(msg_id):
    db = load_db()
    user = session["username"]
    db[user]["messages"] = [m for m in db[user]["messages"] if m["id"] != msg_id]
    save_db(db)
    return jsonify({"message": "Deleted"})


# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n🔐 CipherForge Flask Server")
    print("   Running at: http://localhost:5000")
    print("   Demo login: admin / admin123\n")
    app.run(debug=True, port=5000)
