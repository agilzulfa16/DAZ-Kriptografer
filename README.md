# DAZ Kriptografer

Aplikasi web sederhana untuk **enkripsi** dan **dekripsi** menggunakan beberapa algoritma klasik dan modern. Dibangun dengan Flask (Python) dan antarmuka web minimal.

---

## Fitur utama

- Mendukung cipher berbasis alfabet (A–Z):
  - Vigenere
  - Auto-Key Vigenere
  - Playfair
  - Affine
  - Hill
  - Enigma (placeholder / opsi di UI)
- Mendukung cipher untuk data biner/text lengkap:
  - Extended Vigenere (operasi byte-wise, 0–255)
  - Super Enkripsi — Extended Vigenere + Columnar Transposition
- Input melalui teks manual ataupun upload file
  - Untuk cipher huruf saja: hanya menerima file `.txt` (semua non-huruf akan dibersihkan)
  - Untuk cipher biner: menerima semua tipe file
- Preview hasil (untuk teks/.txt) dan output Base64 untuk data biner
- Download hasil sebagai file

---

## Struktur proyek

```
project-root/
├─ app.py                  # Flask app (semua logika cipher di sini)
├─ requirements.txt        # Dependensi
├─ templates/
│  └─ index.html           # UI (HTML) — sudah disediakan
├─ static/
│  ├─ css/styles.css       # Styling
│  └─ js/script.js         # Frontend logic
```

---

## Instalasi (lokal)

1. Siapkan Python 3.10+ dan virtualenv (direkomendasikan).

```bash
python -m venv venv
source venv/bin/activate   # macOS / Linux
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

2. Jalankan server Flask:

```bash
python app.py
```

Secara default Flask akan jalan di `http://127.0.0.1:5000`.

> Catatan: `app.run(debug=True)` ada di `app.py`. Untuk deployment produksi, gunakan Gunicorn atau WSGI server.

Contoh menggunakan gunicorn:

```bash
gunicorn --bind 0.0.0.0:8000 app:app
```

---

## File `requirements.txt` Terperinci

Berikut versi yang lebih rinci dan kompatibel lintas platform dari file `requirements.txt`:

```
# Core dependencies
Flask==3.0.3              # Framework web utama
Werkzeug>=3.0.3           # Server & routing Flask
Jinja2>=3.1.4             # Template engine Flask
itsdangerous>=2.2.0       # Utilitas keamanan untuk Flask
click>=8.1.7              # CLI utilities untuk Flask

# Scientific & Matrix operations
numpy==1.26.1             # Untuk operasi matriks (Hill cipher)

# Deployment (opsional)
gunicorn==23.0.0          # WSGI server untuk produksi

# Optional (recommended untuk development)
python-dotenv>=1.0.1      # Mendukung konfigurasi environment file (.env)
```

> Jika ingin menjaga ukuran environment tetap ringan, baris opsional dapat dihapus.

---

## Cara pakai (ringkas)

1. Buka halaman utama.
2. Pilih `Cipher` dan `Enkripsi` atau `Dekripsi`.
3. Pilih `Teks Manual` atau `Upload File`.
   - Untuk cipher *letter-only* (mis. Vigenere, Playfair, Affine, Hill): hanya file `.txt` yang diizinkan.
   - Untuk `extended_vigenere` / `super` bisa mengunggah file biner.
4. Isi kunci (atau parameter seperti matriks Hill / affine a/b).
5. Tekan **Proses** → hasil muncul di panel `Hasil` dan `Base64`.
6. Klik **Download Hasil** untuk menyimpan file terproses.

---

## Endpoint API (singkat)

- `POST /encrypt` — proses enkripsi / dekripsi. Mengembalikan JSON berisi `result` (Base64), `result_text` (preview bila memungkinkan), `filename`, `is_file`, dan `size`.
- `POST /download` — menerima form-data `data` (Base64) dan `filename` untuk mengunduh file.

> `encrypt` menerima baik field `text` (string) maupun file upload `file`.

---

## Catatan teknis & keamanan

- Untuk cipher berbasis huruf, input teks/teks file akan dibersihkan menjadi A–Z (huruf lain dihapus). Playfair menggantikan `J` → `I` mengikuti aturan klasik.
- Extended Vigenere melakukan operasi byte-wise (mod 256) sehingga cocok untuk file biner.
- Super cipher menambahkan prefix 8-byte panjang (big-endian) lalu melakukan transposisi kolom sehingga hasil dapat dikembalikan ke ukuran asli.
- Validasi: Affine memeriksa gcd(a,26)==1; Hill membutuhkan matriks yang invertibel modulo 26.
- UI menampilkan preview teks bila hasil dapat didekode ke UTF-8 — bila tidak, ditunjukkan Base64.

---

## Contoh penggunaan singkat

### Enkripsi teks dengan Vigenere (menggunakan cURL)

```bash
curl -X POST http://127.0.0.1:5000/encrypt \  -F "cipher_type=vigenere" \  -F "operation=encrypt" \  -F "text=HELLO WORLD" \  -F "key=SECRET"
```

### Enkripsi file biner dengan Super (hasil adalah file .dat)

```bash
curl -X POST http://127.0.0.1:5000/encrypt \  -F "cipher_type=super" \  -F "operation=encrypt" \  -F "file=@path/to/image.png" \  -F "key=PASSWORD" \  -F "key2=TRANSKEY"
```

Hasil response akan mengandung `result` (Base64). Gunakan `POST /download` untuk mengunduh file.

---

## Hal yang mungkin ingin diperbaiki / pengembangan

- Implementasi Enigma belum lengkap (saat ini hanya UI placeholder).
- Tambahkan pengujian otomatis (unit tests) untuk semua cipher.
- Tambahkan validasi dan penanganan error yang lebih granular di sisi klien.
- Tambahkan opsi untuk mengatur encoding input file (mis. latin-1) atau fallback otomatis.

---

## Lisensi

Proyek ini tidak menyertakan lisensi — tambahkan `LICENSE` jika ingin mempublikasikan.
