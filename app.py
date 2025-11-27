import os
import io
import uuid
import base64
from flask import Flask, render_template, request, send_file, redirect, url_for, abort
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB limit
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# In-memory storage for file metadata (original name + encrypted per-file key token)
# In a real app you would use a database
file_keys = {}

def get_master_fernet():
    master_key = os.getenv("MASTER_KEY")
    if not master_key:
        raise RuntimeError("MASTER_KEY not set in .env file!")
    return Fernet(master_key)

def encrypt_file(input_path, output_path):
    # Generate per-file AES-256 key and IV
    aes_key = os.urandom(32)
    iv = os.urandom(16)

    # Encrypt the file with AES-256-CBC + PKCS7 padding
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    with open(input_path, "rb") as f:
        plaintext = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Encrypt the per-file AES key with the master Fernet key (envelope encryption)
    fernet = get_master_fernet()
    encrypted_aes_key_token = fernet.encrypt(aes_key)   # bytes (Fernet token)

    # Store: IV (16) + encrypted_aes_key_token + ciphertext
    with open(output_path, "wb") as f:
        f.write(iv + encrypted_aes_key_token + ciphertext)

    # Return the Fernet token as string for easy storage
    return encrypted_aes_key_token.decode('utf-8')

def decrypt_to_bytes(encrypted_path, encrypted_key_token_str):
    token_bytes = encrypted_key_token_str.encode('utf-8')

    with open(encrypted_path, "rb") as f:
        file_data = f.read()

    iv = file_data[:16]
    token_len = len(token_bytes)
    ciphertext = file_data[16 + token_len:]

    fernet = get_master_fernet()
    aes_key = fernet.decrypt(token_bytes)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename:
            original_name = secure_filename(file.filename)
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{uuid.uuid4()}")
            file.save(temp_path)

            encrypted_name = str(uuid.uuid4())
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_name)

            key_token_str = encrypt_file(temp_path, encrypted_path)

            file_keys[encrypted_name] = (original_name, key_token_str)

            os.remove(temp_path)
            return redirect(url_for('files'))

    return render_template('upload.html')

@app.route('/files')
def files():
    file_list = [
        {'id': enc_name, 'name': orig_name}
        for enc_name, (orig_name, _) in file_keys.items()
    ]
    return render_template('files.html', files=file_list)

@app.route('/download/<file_id>')
def download(file_id):
    if file_id not in file_keys:
        abort(404)

    original_name, key_token_str = file_keys[file_id]
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)

    decrypted_data = decrypt_to_bytes(encrypted_path, key_token_str)

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=original_name,
        mimetype='application/octet-stream'
    )

if __name__ == '__main__':
    app.run(debug=True)