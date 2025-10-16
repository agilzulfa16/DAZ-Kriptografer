from flask import Flask, render_template, request, jsonify, send_file
import base64, io, json, numpy as np, os
from math import gcd

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64MB

# ========== Helper Functions ==========
def mod_inverse(a: int, m: int):
    """Cari invers modulo dari a mod m (Extended Euclidean Algorithm)."""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inverse(matrix, mod):
    """Hitung invers matriks dalam modulo (untuk cipher Hill)."""
    det = int(round(np.linalg.det(matrix))) % mod
    det_inv = mod_inverse(det, mod)
    if det_inv is None:
        return None
    matrix_inv = np.round(np.linalg.inv(matrix) * det).astype(int)
    return (det_inv * matrix_inv) % mod

# ========== Extended Vigenere (Byte-based) ==========
def extended_vigenere_encrypt(data: bytes, key: str) -> bytes:
    key_b = key.encode('utf-8')
    out = bytearray()
    for i, b in enumerate(data):
        out.append((b + key_b[i % len(key_b)]) % 256)
    return bytes(out)

def extended_vigenere_decrypt(data: bytes, key: str) -> bytes:
    key_b = key.encode('utf-8')
    out = bytearray()
    for i, b in enumerate(data):
        out.append((b - key_b[i % len(key_b)]) % 256)
    return bytes(out)

# ========== Vigenere Text Cipher ==========
def vigenere_encrypt(text, key):
    text, key = text.upper(), key.upper()
    res = ""
    for i, ch in enumerate(text):
        if ch.isalpha():
            res += chr(((ord(ch) - 65 + ord(key[i % len(key)]) - 65) % 26) + 65)
        else:
            res += ch
    return res.lower()

def vigenere_decrypt(text, key):
    text, key = text.upper(), key.upper()
    res = ""
    for i, ch in enumerate(text):
        if ch.isalpha():
            res += chr(((ord(ch) - 65 - (ord(key[i % len(key)]) - 65)) % 26) + 65)
        else:
            res += ch
    return res.lower()

# ========== Affine Cipher ==========
def affine_encrypt(text, a, b):
    text = text.upper()
    if gcd(a, 26) != 1:
        return "Error: a dan 26 tidak coprime"
    res = ""
    for ch in text:
        if ch.isalpha():
            res += chr(((a * (ord(ch) - 65) + b) % 26) + 65)
        else:
            res += ch
    return res.lower()

def affine_decrypt(text, a, b):
    text = text.upper()
    if gcd(a, 26) != 1:
        return "Error: a dan 26 tidak coprime"
    a_inv = mod_inverse(a, 26)
    res = ""
    for ch in text:
        if ch.isalpha():
            res += chr((a_inv * ((ord(ch) - 65) - b)) % 26 + 65)
        else:
            res += ch
    return res.lower()

# ========== Hill Cipher ==========
def hill_encrypt(text, matrix):
    text = text.upper().replace(" ", "")
    n = len(matrix)
    while len(text) % n != 0:
        text += "X"
    result = ""
    for i in range(0, len(text), n):
        block = np.array([ord(ch) - 65 for ch in text[i:i+n]])
        enc = np.dot(matrix, block) % 26
        result += ''.join(chr(x + 65) for x in enc)
    return result.lower()

def hill_decrypt(text, matrix):
    text = text.upper().replace(" ", "")
    inv_matrix = matrix_mod_inverse(matrix, 26)
    if inv_matrix is None:
        return "Error: matriks tidak invertibel"
    n = len(matrix)
    result = ""
    for i in range(0, len(text), n):
        block = np.array([ord(ch) - 65 for ch in text[i:i+n]])
        dec = np.dot(inv_matrix, block) % 26
        result += ''.join(chr(int(x) + 65) for x in dec)
    return result.lower()

# ========== Routes ==========
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        cipher_type = request.form.get('cipher_type', '')
        operation = request.form.get('operation', 'encrypt')
        key = request.form.get('key', '')

        if 'file' in request.files and request.files['file'].filename:
            f = request.files['file']
            filename = f.filename
            file_data = f.read()
            file_ext = os.path.splitext(filename)[1].lstrip('.') or "bin"
            is_file = True
        else:
            text = request.form.get('text', '')
            file_data = text.encode('utf-8')
            filename = None
            file_ext = None
            is_file = False

        result_bytes = b''

        # === ENKRIPSI ===
        if operation == 'encrypt':
            if is_file:
                # sisipkan metadata nama dan ekstensi agar bisa dikenali saat dekripsi
                metadata = f"FNAME:{filename};EXT:{file_ext};".encode('utf-8')
                data_to_encrypt = metadata + file_data
                result_bytes = extended_vigenere_encrypt(data_to_encrypt, key)
            else:
                if cipher_type == 'vigenere':
                    result_bytes = vigenere_encrypt(text, key).encode()
                elif cipher_type == 'affine':
                    a = int(request.form.get('affine_a', 5))
                    b = int(request.form.get('affine_b', 8))
                    result_bytes = affine_encrypt(text, a, b).encode()
                elif cipher_type == 'hill':
                    matrix = np.array(json.loads(request.form.get('hill_matrix', '[[6,24,1],[13,16,10],[20,17,15]]')))
                    result_bytes = hill_encrypt(text, matrix).encode()
                else:
                    result_bytes = extended_vigenere_encrypt(file_data, key)

        # === DEKRIPSI ===
        else:
            if is_file:
                decrypted = extended_vigenere_decrypt(file_data, key)

                # baca metadata
                if decrypted.startswith(b'FNAME:'):
                    end_meta = decrypted.find(b';EXT:')
                    end_ext = decrypted.find(b';', end_meta + 5)
                    if end_meta != -1 and end_ext != -1:
                        fname = decrypted[6:end_meta].decode('utf-8', errors='ignore')
                        ext = decrypted[end_meta+5:end_ext].decode('utf-8', errors='ignore')
                        content = decrypted[end_ext+1:]
                        filename = fname or "decrypted"
                        file_ext = ext or "bin"
                        result_bytes = content
                    else:
                        result_bytes = decrypted
                else:
                    result_bytes = decrypted
            else:
                if cipher_type == 'vigenere':
                    result_bytes = vigenere_decrypt(text, key).encode()
                elif cipher_type == 'affine':
                    a = int(request.form.get('affine_a', 5))
                    b = int(request.form.get('affine_b', 8))
                    result_bytes = affine_decrypt(text, a, b).encode()
                elif cipher_type == 'hill':
                    matrix = np.array(json.loads(request.form.get('hill_matrix', '[[6,24,1],[13,16,10],[20,17,15]]')))
                    result_bytes = hill_decrypt(text, matrix).encode()
                else:
                    result_bytes = extended_vigenere_decrypt(file_data, key)

        # === SIAPKAN OUTPUT ===
        result_b64 = base64.b64encode(result_bytes).decode('utf-8')

        if is_file:
            if operation == 'encrypt':
                out_filename = os.path.splitext(filename)[0] + "_encrypted.dat"
            else:
                out_filename = os.path.splitext(filename)[0] + f"_decrypted.{file_ext or 'bin'}"
        else:
            out_filename = f"{operation}_result.txt"

        return jsonify({
            'success': True,
            'result': result_b64,
            'filename': out_filename,
            'is_file': is_file,
            'size': len(result_bytes),
            'result_text': "(file processed)" if is_file else result_bytes.decode('utf-8', errors='ignore')[:500]
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/download', methods=['POST'])
def download():
    try:
        data_b64 = request.form.get('data')
        filename = request.form.get('filename', 'download.dat')
        data = base64.b64decode(data_b64)
        return send_file(
            io.BytesIO(data),
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
