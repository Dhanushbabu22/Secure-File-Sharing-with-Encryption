from flask import Flask, render_template, request, send_file
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
KEY_FILE = 'aes_key.bin'

for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Persist key
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'rb') as kf:
        key = kf.read()
else:
    key = get_random_bytes(16)
    with open(KEY_FILE, 'wb') as kf:
        kf.write(key)

def encrypt_file(input_path, output_path):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    with open(output_path, 'wb') as f:
        f.write(cipher.iv + ciphertext)

def decrypt_file(input_path, output_path):
    with open(input_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    with open(output_path, 'wb') as f:
        f.write(plaintext)

@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file and uploaded_file.filename != '':
            filename = secure_filename(uploaded_file.filename)
            input_path = os.path.join(UPLOAD_FOLDER, filename)
            encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename + '.enc')
            uploaded_file.save(input_path)
            encrypt_file(input_path, encrypted_path)
            return f'File encrypted successfully! Encrypted file: {filename}.enc'
    return render_template('upload.html')

@app.route('/download/<filename>')
def download(filename):
    # filename should be something like 'example.txt.enc'
    filename = secure_filename(filename)
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename)
    decrypted_path = os.path.join(DECRYPTED_FOLDER, filename.replace('.enc', ''))
    decrypt_file(encrypted_path, decrypted_path)
    return send_file(decrypted_path, as_attachment=True)

if __name__ == '__main__':
    print("Starting Flask app...")
    app.run(debug=True)
