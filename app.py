from flask import Flask, render_template, request, jsonify, send_file
import base64
import io
import json
import os
import numpy as np
from math import gcd

app = Flask(__name__, template_folder='templates')
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64MB

# ======= Konstanta cipher =======
LETTER_ONLY_CIPHERS = {'vigenere', 'autokey', 'playfair', 'affine', 'hill', 'enigma'}
BINARY_SUPPORTED = {'extended_vigenere', 'super'}

# ======= Helper functions =======
def mod_inverse(a: int, m: int):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inverse(matrix, mod):
    det = int(round(np.linalg.det(matrix)))
    det_mod = det % mod
    det_inv = mod_inverse(det_mod, mod)
    if det_inv is None:
        return None
    cof = np.round(det * np.linalg.inv(matrix)).astype(int)
    inv_matrix = (det_inv * cof) % mod
    return inv_matrix

def clean_alpha(s: str) -> str:
    if s is None:
        return ""
    return ''.join([c for c in s.upper() if c.isalpha()])

# ======= Playfair helper & implementation =======
def _build_playfair_square(key: str):
    key = clean_alpha(key).upper().replace('J', 'I')
    seen = set()
    square = []
    for ch in key:
        if ch not in seen:
            seen.add(ch)
            square.append(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.add(ch)
            square.append(ch)
    pos = {}
    for idx, ch in enumerate(square):
        r, c = divmod(idx, 5)
        pos[ch] = (r, c)
    return square, pos

def _prepare_playfair_plaintext(text: str):
    s = clean_alpha(text).upper().replace('J', 'I')
    pairs = []
    i = 0
    while i < len(s):
        a = s[i]
        b = s[i+1] if i+1 < len(s) else None
        if b is None:
            pairs.append(a + 'X')
            i += 1
        elif a == b:
            pairs.append(a + 'X')
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    return pairs

def playfair_encrypt(text: str, key: str) -> str:
    square, pos = _build_playfair_square(key)
    pairs = _prepare_playfair_plaintext(text)
    cipher_pairs = []
    for pair in pairs:
        a, b = pair[0], pair[1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            ca2 = (ca + 1) % 5
            cb2 = (cb + 1) % 5
            cipher_pairs.append(square[ra*5 + ca2] + square[rb*5 + cb2])
        elif ca == cb:
            ra2 = (ra + 1) % 5
            rb2 = (rb + 1) % 5
            cipher_pairs.append(square[ra2*5 + ca] + square[rb2*5 + cb])
        else:
            cipher_pairs.append(square[ra*5 + cb] + square[rb*5 + ca])
    return ''.join(cipher_pairs).lower()

def playfair_decrypt(text: str, key: str) -> str:
    s = clean_alpha(text).upper()
    if len(s) % 2 == 1:
        s += 'X'
    square, pos = _build_playfair_square(key)
    plain_pairs = []
    for i in range(0, len(s), 2):
        a = s[i]
        b = s[i+1]
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            ca2 = (ca - 1) % 5
            cb2 = (cb - 1) % 5
            plain_pairs.append(square[ra*5 + ca2] + square[rb*5 + cb2])
        elif ca == cb:
            ra2 = (ra - 1) % 5
            rb2 = (rb - 1) % 5
            plain_pairs.append(square[ra2*5 + ca] + square[rb2*5 + cb])
        else:
            plain_pairs.append(square[ra*5 + cb] + square[rb*5 + ca])
    plain = ''.join(plain_pairs)
    # heuristik remove filler 'X' between identical letters and trailing X
    cleaned = []
    i = 0
    while i < len(plain):
        if i+2 < len(plain) and plain[i] == plain[i+2] and plain[i+1] == 'X':
            cleaned.append(plain[i])
            i += 2
        else:
            cleaned.append(plain[i])
            i += 1
    result = ''.join(cleaned)
    if result.endswith('X'):
        result = result[:-1]
    return result.lower()

# ======= Cipher implementations =======

def extended_vigenere_encrypt(data: bytes, key: str) -> bytes:
    if not key:
        raise ValueError("Kunci tidak boleh kosong untuk Extended Vigenere.")
    key_b = key.encode('utf-8')
    out = bytearray()
    for i, b in enumerate(data):
        out.append((b + key_b[i % len(key_b)]) % 256)
    return bytes(out)

def extended_vigenere_decrypt(data: bytes, key: str) -> bytes:
    if not key:
        raise ValueError("Kunci tidak boleh kosong untuk Extended Vigenere.")
    key_b = key.encode('utf-8')
    out = bytearray()
    for i, b in enumerate(data):
        out.append((b - key_b[i % len(key_b)]) % 256)
    return bytes(out)

def vigenere_encrypt(text: str, key: str) -> str:
    txt = clean_alpha(text)
    k = clean_alpha(key)
    if not txt:
        return ""
    if not k:
        raise ValueError("Kunci harus berisi huruf A-Z untuk Vigenere.")
    res = []
    for i, ch in enumerate(txt):
        ki = k[i % len(k)]
        enc = ((ord(ch) - 65 + (ord(ki) - 65)) % 26) + 65
        res.append(chr(enc))
    return ''.join(res).lower()

def vigenere_decrypt(text: str, key: str) -> str:
    txt = clean_alpha(text)
    k = clean_alpha(key)
    if not txt:
        return ""
    if not k:
        raise ValueError("Kunci harus berisi huruf A-Z untuk Vigenere.")
    res = []
    for i, ch in enumerate(txt):
        ki = k[i % len(k)]
        dec = ((ord(ch) - 65 - (ord(ki) - 65)) % 26) + 65
        res.append(chr(dec))
    return ''.join(res).lower()

def autokey_encrypt(text: str, key: str) -> str:
    txt = clean_alpha(text)
    k = clean_alpha(key)
    if not txt:
        return ""
    if not k:
        raise ValueError("Kunci harus berisi huruf A-Z untuk Autokey Vigenere.")
    keystream = (k + txt)
    res = []
    for i, ch in enumerate(txt):
        ks = keystream[i]
        enc = ((ord(ch) - 65 + (ord(ks) - 65)) % 26) + 65
        res.append(chr(enc))
    return ''.join(res).lower()

def autokey_decrypt(text: str, key: str) -> str:
    ctext = clean_alpha(text)
    k = clean_alpha(key)
    if not ctext:
        return ""
    if not k:
        raise ValueError("Kunci harus berisi huruf A–Z untuk Autokey Vigenere.")
    keystream = list(k)
    plaintext_chars = []
    for i, ch in enumerate(ctext):
        ks = keystream[i]
        dec_val = ((ord(ch) - 65) - (ord(ks) - 65)) % 26
        pch = chr(dec_val + 65)
        plaintext_chars.append(pch)
        keystream.append(pch)
    return ''.join(plaintext_chars).lower()

def affine_encrypt(text: str, a: int, b: int) -> str:
    txt = clean_alpha(text)
    if gcd(a, 26) != 1:
        return "Error: a dan 26 tidak coprime"
    res = []
    for ch in txt:
        res.append(chr(((a * (ord(ch) - 65) + b) % 26) + 65))
    return ''.join(res).lower()

def affine_decrypt(text: str, a: int, b: int) -> str:
    txt = clean_alpha(text)
    if gcd(a, 26) != 1:
        return "Error: a dan 26 tidak coprime"
    a_inv = mod_inverse(a, 26)
    res = []
    for ch in txt:
        dec = (a_inv * ((ord(ch) - 65) - b)) % 26
        res.append(chr(dec + 65))
    return ''.join(res).lower()

def hill_encrypt(text: str, matrix) -> str:
    txt = clean_alpha(text)
    n = len(matrix)
    if n == 0:
        return ""
    while len(txt) % n != 0:
        txt += "X"
    result = []
    for i in range(0, len(txt), n):
        block = np.array([ord(ch) - 65 for ch in txt[i:i+n]])
        enc = np.dot(matrix, block) % 26
        result += [chr(int(x) + 65) for x in enc]
    return ''.join(result).lower()

def hill_decrypt(text: str, matrix) -> str:
    txt = clean_alpha(text)
    inv_matrix = matrix_mod_inverse(matrix, 26)
    if inv_matrix is None:
        return "Error: matriks tidak invertibel"
    n = len(matrix)
    result = []
    for i in range(0, len(txt), n):
        block = np.array([ord(ch) - 65 for ch in txt[i:i+n]])
        dec = np.dot(inv_matrix, block) % 26
        result += [chr(int(x) + 65) for x in dec]
    return ''.join(result).lower()

# ======= Columnar transposition helpers for SUPER cipher =======
def _column_order(key: str):
    # return list of column indices in order of reading (stable sort)
    return sorted(range(len(key)), key=lambda i: (key[i], i))

def columnar_transpose_with_length_prefix(data: bytes, key: str) -> bytes:
    """
    Prefix 8-byte length, then do columnar transposition.
    """
    if not key:
        raise ValueError("Kunci transposisi (key2) tidak boleh kosong untuk Super cipher.")
    prefix = len(data).to_bytes(8, 'big')
    payload = prefix + data
    cols = len(key)
    rows = (len(payload) + cols - 1) // cols
    pad_len = rows * cols - len(payload)
    payload_padded = payload + b'\x00' * pad_len
    # build matrix rows x cols
    matrix = [payload_padded[i*cols:(i+1)*cols] for i in range(rows)]
    order = _column_order(key)
    out = bytearray()
    for col in order:
        for r in range(rows):
            out.append(matrix[r][col])
    return bytes(out)

def columnar_untranspose_with_length_prefix(data: bytes, key: str) -> bytes:
    """
    Reverse of above. Returns original payload (without padding).
    """
    if not key:
        raise ValueError("Kunci transposisi (key2) tidak boleh kosong untuk Super cipher.")
    cols = len(key)
    if len(data) % cols != 0:
        raise ValueError("Data length is not a multiple of key length during untranspose.")
    rows = len(data) // cols
    order = _column_order(key)
    # create empty matrix
    matrix = [bytearray(cols) for _ in range(rows)]
    idx = 0
    for col in order:
        for r in range(rows):
            matrix[r][col] = data[idx]
            idx += 1
    # read row-wise
    payload_padded = bytearray()
    for r in range(rows):
        payload_padded.extend(matrix[r])
    # first 8 bytes are length
    if len(payload_padded) < 8:
        raise ValueError("Payload too short when reversing transposition.")
    orig_len = int.from_bytes(bytes(payload_padded[:8]), 'big')
    payload = bytes(payload_padded[8:8+orig_len])
    return payload

# ======= Routes =======
@app.route('/')
def index():
    return render_template('index.html', letter_only=list(LETTER_ONLY_CIPHERS), binary_supported=list(BINARY_SUPPORTED))

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        cipher_type = request.form.get('cipher_type', '')
        operation = request.form.get('operation', 'encrypt')
        key = request.form.get('key', '')

        # baca file jika ada
        if 'file' in request.files and request.files['file'].filename:
            f = request.files['file']
            filename = f.filename
            file_data = f.read()
            file_ext = os.path.splitext(filename)[1].lstrip('.').lower() or "bin"
            is_file = True
        else:
            text = request.form.get('text', '')
            file_data = text.encode('utf-8')
            filename = None
            file_ext = None
            is_file = False

        # server-side: jika file dan cipher hanya letter, izinkan hanya .txt
        if is_file and cipher_type in LETTER_ONLY_CIPHERS:
            if file_ext != 'txt':
                return jsonify({
                    'success': False,
                    'error': f"Cipher '{cipher_type}' hanya menerima file teks .txt (A–Z)."
                }), 400
            # decode file bytes ke teks (fallback replace untuk karakter tidak valid)
            try:
                file_text = file_data.decode('utf-8')
            except Exception:
                file_text = file_data.decode('latin-1', errors='replace')
        else:
            file_text = None

        result_bytes = b''
        result_text_display = ""

        # ENKRIPSI
        if operation == 'encrypt':
            if is_file:
                # file encryption: binary-capable ciphers
                if cipher_type == 'extended_vigenere':
                    if not key:
                        return jsonify({'success': False, 'error': 'Kunci tidak boleh kosong untuk enkripsi file.'}), 400
                    metadata = f"FNAME:{filename};EXT:{file_ext};".encode('utf-8')
                    data_to_encrypt = metadata + file_data
                    result_bytes = extended_vigenere_encrypt(data_to_encrypt, key)
                    # for .txt input we will show content below
                elif cipher_type == 'super':
                    key2 = request.form.get('key2', '')
                    if not key:
                        return jsonify({'success': False, 'error': 'Kunci (untuk Extended Vigenere) tidak boleh kosong untuk Super enkripsi.'}), 400
                    if not key2:
                        return jsonify({'success': False, 'error': 'Kunci transposisi (key2) tidak boleh kosong untuk Super enkripsi.'}), 400
                    metadata = f"FNAME:{filename};EXT:{file_ext};".encode('utf-8')
                    data_to_encrypt = metadata + file_data
                    ev = extended_vigenere_encrypt(data_to_encrypt, key)
                    result_bytes = columnar_transpose_with_length_prefix(ev, key2)
                elif cipher_type in LETTER_ONLY_CIPHERS:
                    # treat .txt as plain text; perform letter-only cipher and return .txt
                    # file_text already decoded above
                    if cipher_type == 'vigenere':
                        processed = vigenere_encrypt(file_text, key)
                    elif cipher_type == 'autokey':
                        processed = autokey_encrypt(file_text, key)
                    elif cipher_type == 'playfair':
                        processed = playfair_encrypt(file_text, key)
                    elif cipher_type == 'affine':
                        a = int(request.form.get('affine_a', 5))
                        b = int(request.form.get('affine_b', 8))
                        processed = affine_encrypt(file_text, a, b)
                        if isinstance(processed, str) and processed.startswith("Error"):
                            return jsonify({'success': False, 'error': processed}), 400
                    elif cipher_type == 'hill':
                        matrix = np.array(json.loads(request.form.get('hill_matrix', '[[6,24,1],[13,16,10],[20,17,15]]')))
                        processed = hill_encrypt(file_text, matrix)
                        if isinstance(processed, str) and processed.startswith("Error"):
                            return jsonify({'success': False, 'error': processed}), 400
                    else:
                        # fallback
                        processed = vigenere_encrypt(file_text, key)
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                else:
                    return jsonify({'success': False, 'error': 'Cipher tidak mendukung file binary.'}), 400
            else:
                # text (non-file) encryption
                if cipher_type == 'vigenere':
                    processed = vigenere_encrypt(text, key)
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                elif cipher_type == 'autokey':
                    processed = autokey_encrypt(text, key)
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                elif cipher_type == 'playfair':
                    processed = playfair_encrypt(text, key)
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                elif cipher_type == 'affine':
                    a = int(request.form.get('affine_a', 5))
                    b = int(request.form.get('affine_b', 8))
                    processed = affine_encrypt(text, a, b)
                    if isinstance(processed, str) and processed.startswith("Error"):
                        return jsonify({'success': False, 'error': processed}), 400
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                elif cipher_type == 'hill':
                    matrix = np.array(json.loads(request.form.get('hill_matrix', '[[6,24,1],[13,16,10],[20,17,15]]')))
                    processed = hill_encrypt(text, matrix)
                    if isinstance(processed, str) and processed.startswith("Error"):
                        return jsonify({'success': False, 'error': processed}), 400
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                elif cipher_type == 'extended_vigenere':
                    if not key:
                        return jsonify({'success': False, 'error': 'Kunci tidak boleh kosong untuk Extended Vigenere.'}), 400
                    result_bytes = extended_vigenere_encrypt(text.encode('utf-8'), key)
                    result_text_display = base64.b64encode(result_bytes).decode('utf-8')
                elif cipher_type == 'super':
                    key2 = request.form.get('key2', '')
                    if not key:
                        return jsonify({'success': False, 'error': 'Kunci (untuk Extended Vigenere) tidak boleh kosong untuk Super enkripsi.'}), 400
                    if not key2:
                        return jsonify({'success': False, 'error': 'Kunci transposisi (key2) tidak boleh kosong untuk Super enkripsi.'}), 400
                    ev = extended_vigenere_encrypt(text.encode('utf-8'), key)
                    result_bytes = columnar_transpose_with_length_prefix(ev, key2)
                    result_text_display = base64.b64encode(result_bytes).decode('utf-8')
                else:
                    # fallback: treat as extended vigenere on text
                    if not key:
                        return jsonify({'success': False, 'error': 'Kunci tidak boleh kosong.'}), 400
                    result_bytes = extended_vigenere_encrypt(text.encode('utf-8'), key)
                    result_text_display = base64.b64encode(result_bytes).decode('utf-8')

        # DEKRIPSI
        else:
            if is_file:
                # file decryption
                if cipher_type == 'extended_vigenere':
                    if not key:
                        return jsonify({'success': False, 'error': 'Kunci tidak boleh kosong untuk dekripsi file.'}), 400
                    decrypted = extended_vigenere_decrypt(file_data, key)
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
                elif cipher_type == 'super':
                    key2 = request.form.get('key2', '')
                    if not key:
                        return jsonify({'success': False, 'error': 'Kunci (untuk Extended Vigenere) tidak boleh kosong untuk Super dekripsi.'}), 400
                    if not key2:
                        return jsonify({'success': False, 'error': 'Kunci transposisi (key2) tidak boleh kosong untuk Super dekripsi.'}), 400
                    try:
                        untrans = columnar_untranspose_with_length_prefix(file_data, key2)
                    except Exception as ex:
                        return jsonify({'success': False, 'error': f'Gagal membalik transposisi: {ex}'}), 400
                    try:
                        decrypted = extended_vigenere_decrypt(untrans, key)
                    except Exception as ex:
                        return jsonify({'success': False, 'error': str(ex)}), 400
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
                elif cipher_type in LETTER_ONLY_CIPHERS:
                    # .txt file: treat as text then perform letter-only decryption
                    if cipher_type == 'vigenere':
                        processed = vigenere_decrypt(file_text, key)
                    elif cipher_type == 'autokey':
                        processed = autokey_decrypt(file_text, key)
                    elif cipher_type == 'playfair':
                        processed = playfair_decrypt(file_text, key)
                    elif cipher_type == 'affine':
                        a = int(request.form.get('affine_a', 5))
                        b = int(request.form.get('affine_b', 8))
                        processed = affine_decrypt(file_text, a, b)
                        if isinstance(processed, str) and processed.startswith("Error"):
                            return jsonify({'success': False, 'error': processed}), 400
                    elif cipher_type == 'hill':
                        matrix = np.array(json.loads(request.form.get('hill_matrix', '[[6,24,1],[13,16,10],[20,17,15]]')))
                        processed = hill_decrypt(file_text, matrix)
                        if isinstance(processed, str) and processed.startswith("Error"):
                            return jsonify({'success': False, 'error': processed}), 400
                    else:
                        processed = vigenere_decrypt(file_text, key)
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                else:
                    return jsonify({'success': False, 'error': 'Cipher tidak mendukung file binary.'}), 400
            else:
                # text decryption
                if cipher_type == 'vigenere':
                    processed = vigenere_decrypt(text, key)
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                elif cipher_type == 'autokey':
                    processed = autokey_decrypt(text, key)
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                elif cipher_type == 'playfair':
                    processed = playfair_decrypt(text, key)
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                elif cipher_type == 'affine':
                    a = int(request.form.get('affine_a', 5))
                    b = int(request.form.get('affine_b', 8))
                    processed = affine_decrypt(text, a, b)
                    if isinstance(processed, str) and processed.startswith("Error"):
                        return jsonify({'success': False, 'error': processed}), 400
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                elif cipher_type == 'hill':
                    matrix = np.array(json.loads(request.form.get('hill_matrix', '[[6,24,1],[13,16,10],[20,17,15]]')))
                    processed = hill_decrypt(text, matrix)
                    if isinstance(processed, str) and processed.startswith("Error"):
                        return jsonify({'success': False, 'error': processed}), 400
                    result_bytes = processed.encode('utf-8')
                    result_text_display = processed
                elif cipher_type == 'extended_vigenere':
                    raw_text = request.form.get('text', '')
                    if raw_text is None:
                        raw_text = ''
                    if not key:
                        return jsonify({'success': False, 'error': 'Kunci tidak boleh kosong untuk Extended Vigenere.'}), 400
                    candidate = ''.join(raw_text.split())
                    decoded_bytes = None
                    try:
                        decoded_bytes = base64.b64decode(candidate, validate=True)
                    except Exception:
                        decoded_bytes = raw_text.encode('utf-8')
                    try:
                        decrypted_bytes = extended_vigenere_decrypt(decoded_bytes, key)
                    except Exception as ex:
                        return jsonify({'success': False, 'error': str(ex)}), 400
                    result_bytes = decrypted_bytes
                    try:
                        result_text_display = decrypted_bytes.decode('utf-8')
                    except Exception:
                        result_text_display = "(binary data)"
                elif cipher_type == 'super':
                    key2 = request.form.get('key2', '')
                    if not key:
                        return jsonify({'success': False, 'error': 'Kunci (untuk Extended Vigenere) tidak boleh kosong untuk Super dekripsi.'}), 400
                    if not key2:
                        return jsonify({'success': False, 'error': 'Kunci transposisi (key2) tidak boleh kosong untuk Super dekripsi.'}), 400
                    raw_text = request.form.get('text', '') or ''
                    candidate = ''.join(raw_text.split())
                    try:
                        decoded_bytes = base64.b64decode(candidate, validate=True)
                    except Exception:
                        decoded_bytes = raw_text.encode('utf-8')
                    try:
                        untrans = columnar_untranspose_with_length_prefix(decoded_bytes, key2)
                    except Exception as ex:
                        return jsonify({'success': False, 'error': f'Gagal membalik transposisi: {ex}'}), 400
                    try:
                        decrypted_bytes = extended_vigenere_decrypt(untrans, key)
                    except Exception as ex:
                        return jsonify({'success': False, 'error': str(ex)}), 400
                    result_bytes = decrypted_bytes
                    try:
                        result_text_display = decrypted_bytes.decode('utf-8')
                    except Exception:
                        result_text_display = "(binary data)"
                else:
                    raw_text = request.form.get('text', '')
                    if not key:
                        return jsonify({'success': False, 'error': 'Kunci tidak boleh kosong.'}), 400
                    try:
                        result_bytes = extended_vigenere_decrypt(raw_text.encode('utf-8'), key)
                        try:
                            result_text_display = result_bytes.decode('utf-8')
                        except Exception:
                            result_text_display = "(binary data)"
                    except Exception as ex:
                        return jsonify({'success': False, 'error': str(ex)}), 400

        # If input was a file: show preview for .txt inputs, otherwise keep generic message
        if is_file:
            # For uploaded .txt or letter-only ciphers, show the processed result in preview.
            if (file_ext == 'txt') or (cipher_type in LETTER_ONLY_CIPHERS):
                try:
                    # try to decode as UTF-8 for human preview
                    result_text_display = result_bytes.decode('utf-8')
                except Exception:
                    # fallback: show base64 so user still sees what's inside
                    result_text_display = base64.b64encode(result_bytes).decode('utf-8')
            else:
                result_text_display = "file diproses"

        result_b64 = base64.b64encode(result_bytes).decode('utf-8')
        if is_file:
            if operation == 'encrypt':
                # keep .txt extension for letter-only or use .dat for binary
                base = os.path.splitext(filename)[0]
                if cipher_type in LETTER_ONLY_CIPHERS:
                    out_filename = base + "_encrypted.txt"
                else:
                    out_filename = base + "_encrypted.dat"
            else:
                base = os.path.splitext(filename)[0]
                if cipher_type in LETTER_ONLY_CIPHERS:
                    out_filename = base + "_decrypted.txt"
                else:
                    out_filename = base + f"_decrypted.{file_ext or 'bin'}"
        else:
            out_filename = f"{operation}_result.txt"

        return jsonify({
            'success': True,
            'result': result_b64,
            'filename': out_filename,
            'is_file': is_file,
            'size': len(result_bytes),
            'result_text': result_text_display
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
