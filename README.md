# DAZ Kriptografer

**DAZ Kriptografer** Singkatan dari Dimas, Agil, Zidan Kriptografer adalah Aplikasi web sederhana untuk **enkripsi** dan **dekripsi** menggunakan beberapa algoritma klasik dan modern. Dibangun dengan Flask (Python) dan antarmuka web minimal.

---

## Fitur utama

- Mendukung cipher berbasis alfabet (A–Z):
  - Vigenere
  - Auto-Key Vigenere
  - Playfair
  - Affine
  - Hill
  - Enigma 
- Mendukung cipher untuk data biner/text lengkap:
  - Extended Vigenere (operasi byte-wise, 0–255)
  - Super Enkripsi(Extended Vigenere + Columnar Transposition)
- Input melalui teks manual ataupun upload file
  - Untuk cipher dengan keterangan 26 alfabet huruf saja: hanya menerima file `.txt` (semua non-huruf akan dibersihkan)
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



---

## Cara menggunakan program

```

## Cara Menggunakan Program

1. Buka halaman utama.
2. Pilih `Cipher` dan `Enkripsi` atau `Dekripsi`.
3. Pilih `Teks Manual` atau `Upload File`.
   - Untuk cipher *letter-only* (mis. Vigenere, Playfair, Affine, Hill): hanya file `.txt` yang diizinkan.
   - Untuk `extended_vigenere` / `super` bisa mengunggah file biner.
4. Isi kunci (atau parameter seperti matriks Hill / affine a/b).
5. Tekan **Proses** → hasil muncul di panel `Hasil` dan `Base64`.
6. Klik **Download Hasil** untuk menyimpan file terproses.

---


## Catatan teknis & keamanan

- Untuk cipher berbasis huruf, input teks/teks file akan dibersihkan menjadi A–Z (huruf lain dihapus). Playfair menggantikan `J` → `I` mengikuti aturan klasik.
- Extended Vigenere melakukan operasi byte-wise (mod 256) sehingga cocok untuk file biner.
- Super cipher menambahkan prefix 8-byte panjang (big-endian) lalu melakukan transposisi kolom sehingga hasil dapat dikembalikan ke ukuran asli.
- Validasi: Affine memeriksa gcd(a,26)==1; Hill membutuhkan matriks yang invertibel modulo 26.


