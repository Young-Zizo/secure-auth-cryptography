from flask import Flask, request, jsonify
import hashlib, os, hmac, time, jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

app = Flask(__name__)

SECRET_KEY = "SUPER_SECRET_KEY"
users_db = {}

# ================= RSA KEYS =================
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# ============== 1) REGISTER =================
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    role = data.get('role', 'user')

    salt = os.urandom(16)
    password_hash = hashlib.sha256(salt + password.encode()).hexdigest()

    users_db[username] = {
        "salt": salt,
        "password_hash": password_hash,
        "role": role
    }

    return jsonify({"msg": "User registered securely"})


# ============== 2) LOGIN =================
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    user = users_db.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 401

    salt = user['salt']
    new_hash = hashlib.sha256(salt + password.encode()).hexdigest()

    if new_hash != user['password_hash']:
        return jsonify({"error": "Wrong password"}), 401

    payload = {
        "username": username,
        "role": user['role'],
        "exp": int(time.time()) + 60
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})


# ============== 3 & 4) TOKEN VERIFY =================
def verify_token(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return "expired"
    except jwt.InvalidTokenError:
        return "invalid"


# ============== 5) HMAC =================
@app.route('/send_message', methods=['POST'])
def send_message():
    auth = request.headers.get("Authorization")
    if not auth:
        return jsonify({"error": "No token"}), 401

    token = auth.split(" ")[1]
    check = verify_token(token)

    if check in ["expired", "invalid"]:
        return jsonify({"error": check}), 401

    message = request.json['message']

    mac = hmac.new(
        SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

    return jsonify({"message": message, "hmac": mac})


# 🔥 VERIFY HMAC (مهم جدًا)
@app.route('/verify_message', methods=['POST'])
def verify_message():
    message = request.json['message']
    received_hmac = request.json['hmac']

    new_hmac = hmac.new(
        SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

    if new_hmac == received_hmac:
        return jsonify({"msg": "Message VALID"})
    else:
        return jsonify({"msg": "Message TAMPERED"}), 400


# ============== 6) DIGITAL SIGNATURE =================
@app.route('/sign_message', methods=['POST'])
def sign_message():
    message = request.json['message'].encode()

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return jsonify({"signature": signature.hex()})


@app.route('/verify_signature', methods=['POST'])
def verify_signature():
    message = request.json['message'].encode()
    signature = bytes.fromhex(request.json['signature'])

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return jsonify({"msg": "Signature VALID"})
    except:
        return jsonify({"msg": "Signature INVALID"}), 400


# ============== 8) ROLE BASED =================
@app.route('/admin_only', methods=['GET'])
def admin_only():
    auth = request.headers.get("Authorization")
    if not auth:
        return jsonify({"error": "No token"}), 401

    token = auth.split(" ")[1]
    check = verify_token(token)

    if check in ["expired", "invalid"]:
        return jsonify({"error": check}), 401

    if check['role'] != 'admin':
        return jsonify({"error": "Access denied"}), 403

    return jsonify({"msg": "Welcome Admin! Full access granted"})


if __name__ == '__main__':
    app.run(debug=True)