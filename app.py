from flask import Flask, render_template, request, send_file
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Flask app setup
app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'

# Create folders if they don't exist
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# AES Encryption Key
key = get_random_bytes(16)  # 128-bit key

# Encrypt Function
def encrypt_file(input_path, output_path):
    cipher = AES.new(key, AES.MODE_CBC)
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    with open(output_path, 'wb') as f:
        f.write(cipher.iv + ciphertext)

# Decrypt Function
def decrypt_file(input_path, output_path):
    with open(input_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    with open(output_path, 'wb') as f:
        f.write(plaintext)

# 📥 Upload & Encrypt Route
@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            input_path = os.path.join(UPLOAD_FOLDER, uploaded_file.filename)
            encrypted_path = os.path.join(ENCRYPTED_FOLDER, uploaded_file.filename + '.enc')
            uploaded_file.save(input_path)
            encrypt_file(input_path, encrypted_path)
            return f'File encrypted successfully! Encrypted file: {uploaded_file.filename}.enc'
    return render_template('upload.html')

# 📤 Decrypt & Download Route
@app.route('/download/<filename>')
def download(filename):
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename)
    decrypted_path = os.path.join(DECRYPTED_FOLDER, filename.replace('.enc', ''))
    decrypt_file(encrypted_path, decrypted_path)
    return send_file(decrypted_path, as_attachment=True)

if __name__ == '__main__':
    print("Starting Flask app...")  # Debug print
    app.run(debug=True)
