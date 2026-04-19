# CipherForge — Web-Based Text Encryption Tool
### Python (Flask) + PyCryptodome

---

## Project Structure

```
cipherforge/
├── app.py               ← Flask backend (all encryption logic)
├── requirements.txt     ← Python dependencies
├── users.json           ← Auto-created on first run (user database)
├── templates/
│   └── index.html       ← Frontend (HTML, CSS, JavaScript)
└── README.md
```

---

## Tech Stack

| Layer      | Technology                          |
|------------|-------------------------------------|
| Frontend   | HTML5, CSS3, Vanilla JavaScript     |
| Backend    | Python 3, Flask                     |
| Crypto Lib | PyCryptodome                        |
| Storage    | JSON file (server-side user data)   |
| Session    | Flask server-side sessions          |

---

## Setup & Run Instructions

### Step 1 — Install Python dependencies
```bash
pip install -r requirements.txt
```

### Step 2 — Run the Flask server
```bash
python app.py
```

### Step 3 — Open in browser
```
http://localhost:5000
```

### Default demo account
- **Username:** admin
- **Password:** admin123

---

## API Endpoints

| Method | Endpoint              | Description                    |
|--------|-----------------------|--------------------------------|
| POST   | /api/register         | Register a new user            |
| POST   | /api/login            | Login                          |
| POST   | /api/logout           | Logout                         |
| GET    | /api/me               | Get current session user       |
| POST   | /api/encrypt          | Encrypt text (auth required)   |
| POST   | /api/decrypt          | Decrypt text (auth required)   |
| POST   | /api/hash             | Hash text (auth required)      |
| GET    | /api/messages         | Get saved messages             |
| POST   | /api/messages         | Save encrypted message         |
| DELETE | /api/messages/<id>    | Delete a saved message         |

---

## Encryption Algorithms (Backend - PyCryptodome)

| Algorithm     | Library              | Mode    | Security     |
|---------------|----------------------|---------|--------------|
| Caesar Cipher | Custom Python        | —       | Very Low     |
| Vigenère      | Custom Python        | —       | Low–Medium   |
| AES-256       | PyCryptodome (AES)   | CBC     | Very High ✓  |
| Triple-DES    | PyCryptodome (DES3)  | CBC     | Medium       |
| RC4           | PyCryptodome (ARC4)  | Stream  | Low (Legacy) |
| Base64        | Python stdlib        | —       | None         |
| Atbash        | Custom Python        | —       | Very Low     |
| ROT-13        | Custom Python        | —       | Very Low     |

## Hash Functions (Backend - PyCryptodome)

SHA-256, SHA-512, SHA-1, MD5, SHA-3 (256-bit), RIPEMD-160

---
