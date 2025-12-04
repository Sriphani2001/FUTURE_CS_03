import io, os, uuid
from hashlib import sha256

from flask import Flask, render_template, request, send_file, redirect, url_for, abort, flash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH_MB", "100")) * 1024 * 1024
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY") or os.urandom(32)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {
    e.strip().lower()
    for e in os.getenv("ALLOWED_EXTENSIONS", "txt,pdf,png,jpg,jpeg,gif,zip,docx,xlsx").split(",")
    if e.strip()
}

file_keys = {}  # file_id -> {"name": original_name, "token": fernet_token_str, "hash": sha256_hex}


def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_fernet():
    k = os.getenv("MASTER_KEY")
    if not k:
        raise RuntimeError("MASTER_KEY missing in .env")
    return Fernet(k)


def encrypt_file(src, dst):
    aes_key, iv = os.urandom(32), os.urandom(16)
    with open(src, "rb") as f:
        data = f.read()
    h = sha256(data).hexdigest()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    ct = enc.update(padded) + enc.finalize()

    token = get_fernet().encrypt(aes_key)
    with open(dst, "wb") as f:
        f.write(iv + token + ct)
    return token.decode(), h


def decrypt_file(path, token_str):
    token = token_str.encode()
    with open(path, "rb") as f:
        data = f.read()
    iv, token_len = data[:16], len(token)
    ct = data[16 + token_len :]

    try:
        aes_key = get_fernet().decrypt(token)
    except InvalidToken as e:
        raise RuntimeError("Failed to unwrap AES key") from e

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as e:
        raise RuntimeError("Bad padding (possible tampering)") from e


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            flash("No file selected", "error")
            return redirect(request.url)

        original = secure_filename(f.filename)
        if not allowed_file(original):
            flash("File type not allowed", "error")
            return redirect(request.url)

        temp_path = os.path.join(UPLOAD_FOLDER, "temp_" + uuid.uuid4().hex)
        f.save(temp_path)

        file_id = uuid.uuid4().hex
        out_path = os.path.join(UPLOAD_FOLDER, file_id)

        try:
            token_str, h = encrypt_file(temp_path, out_path)
        except Exception as e:  # noqa: BLE001
            if os.path.exists(temp_path):
                os.remove(temp_path)
            flash(f"Encryption failed: {e}", "error")
            return redirect(request.url)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        file_keys[file_id] = {"name": original, "token": token_str, "hash": h}
        flash("File uploaded and encrypted", "success")
        return redirect(url_for("files"))

    return render_template("upload.html")


@app.route("/files")
def files():
    items = [{"id": fid, "name": meta["name"]} for fid, meta in file_keys.items()]
    return render_template("files.html", files=items)


@app.route("/download/<file_id>")
def download(file_id):
    meta = file_keys.get(file_id)
    if not meta:
        abort(404)

    path = os.path.join(UPLOAD_FOLDER, file_id)
    if not os.path.exists(path):
        abort(404)

    try:
        data = decrypt_file(path, meta["token"])
    except RuntimeError as e:
        flash(f"Decryption failed: {e}", "error")
        abort(500)

    if sha256(data).hexdigest() != meta["hash"]:
        flash("Integrity check failed", "error")
        abort(500)

    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=meta["name"],
        mimetype="application/octet-stream",
    )


if __name__ == "__main__":
    app.run(debug=True)
