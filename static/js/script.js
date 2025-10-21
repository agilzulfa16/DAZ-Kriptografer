// static/js/script.js

document.addEventListener('DOMContentLoaded', () => {
    // read lists provided by the server via inline script in template
    const LETTER_ONLY = window.LETTER_ONLY || ['vigenere','autokey','playfair','affine','hill','enigma'];
    const BINARY_SUPPORT = window.BINARY_SUPPORTED || ['extended_vigenere','super'];

    const cipherType = document.getElementById('cipherType');
    const radioText = document.getElementById('radioText');
    const radioFile = document.getElementById('radioFile');
    const labelFileOption = document.getElementById('labelFileOption');
    const fileInputSection = document.getElementById('fileInput');
    const textInputSection = document.getElementById('textInput');
    const fileUpload = document.getElementById('fileUpload');
    const fileNameSpan = document.getElementById('fileName');
    const alertBox = document.getElementById('alertBox');
    const loadingBox = document.getElementById('loadingBox');
    const resultSection = document.getElementById('resultSection');
    const resultBox = document.getElementById('resultBox');
    const base64Box = document.getElementById('base64Box');
    const downloadBtn = document.getElementById('downloadBtn');
    const copyBtn = document.getElementById('copyBtn');
    const resetBtn = document.getElementById('resetBtn');
    const playfairPreview = document.getElementById('playfairPreview');
    const playfairPreviewBox = document.getElementById('playfairPreviewBox');
    const inputText = document.getElementById('inputText');
    const keyInput = document.getElementById('key');
    const keyGroup = document.getElementById('keyGroup');

    // safe-guards: if some elements missing, avoid throwing errors
    function el(id) { return document.getElementById(id); }

    // initialize
    updateCipherSpecificOptions();
    updateFileOptionVisibility();

    // listeners
    if (cipherType) {
        cipherType.addEventListener('change', () => {
            updateCipherSpecificOptions();
            updateFileOptionVisibility();
            updatePlayfairPreviewVisibility();
            updatePlayfairPreview(); // refresh preview if needed
        });
    }

    document.querySelectorAll('input[name="input_type"]').forEach(r => {
        r.addEventListener('change', function () {
            if (this.value === 'text') {
                if (textInputSection) textInputSection.style.display = 'block';
                if (fileInputSection) fileInputSection.style.display = 'none';
            } else {
                // only show file input if option available
                if (labelFileOption && labelFileOption.style.display === 'none') {
                    radioText.checked = true;
                    if (textInputSection) textInputSection.style.display = 'block';
                    if (fileInputSection) fileInputSection.style.display = 'none';
                    alertBox.innerHTML = `<div class="alert alert-danger">⚠️ Opsi Upload File tidak tersedia untuk cipher yang dipilih.</div>`;
                    return;
                }
                if (textInputSection) textInputSection.style.display = 'none';
                if (fileInputSection) fileInputSection.style.display = 'block';
            }
        });
    });

    if (fileUpload) {
        fileUpload.addEventListener('change', function () {
            const f = this.files[0];
            if (f) {
                const ext = '.' + (f.name.split('.').pop() || '').toLowerCase();
                const v = cipherType ? cipherType.value : '';
                // determine allowed extension(s) client-side
                if (LETTER_ONLY.includes(v)) {
                    if (ext !== '.txt') {
                        alertBox.innerHTML = `<div class="alert alert-danger">⚠️ Untuk cipher "${v}" hanya diperbolehkan file .txt. Pilih file lain atau ubah cipher.</div>`;
                        this.value = '';
                        if (fileNameSpan) fileNameSpan.textContent = 'Belum ada file dipilih';
                        return;
                    } else {
                        if (fileNameSpan) fileNameSpan.textContent = f.name;
                        alertBox.innerHTML = `<div class="alert alert-success">✅ File .txt siap diproses. Semua karakter non-A–Z akan dihapus sebelum pemrosesan.</div>`;
                    }
                } else {
                    // allow all other file types for binary-capable ciphers
                    if (fileNameSpan) fileNameSpan.textContent = f.name;
                    alertBox.innerHTML = '';
                }
            } else {
                if (fileNameSpan) fileNameSpan.textContent = 'Belum ada file dipilih';
            }
        });
    }

    // update preview on typing or key change
    if (inputText) inputText.addEventListener('input', updatePlayfairPreview);
    if (keyInput) keyInput.addEventListener('input', updatePlayfairPreview);

    function updateCipherSpecificOptions() {
        document.querySelectorAll('.cipher-options').forEach(opt => opt.classList.remove('show'));
        const v = cipherType ? cipherType.value : '';
        if (v === 'affine') {
            const elAff = document.getElementById('affineOptions');
            if (elAff) elAff.classList.add('show');
        }
        if (v === 'hill') {
            const elHill = document.getElementById('hillOptions');
            if (elHill) elHill.classList.add('show');
        }
        if (v === 'super') {
            const elSuper = document.getElementById('superOptions');
            if (elSuper) elSuper.classList.add('show');
        }
        if (v === 'enigma') {
            const elEnigma = document.getElementById('enigmaOptions');
            if (elEnigma) elEnigma.classList.add('show');
        }

        // Toggle key input visibility & required for Affine and Hill
        if (v === 'affine' || v === 'hill') {
            // Affine & Hill hanya butuh parameter numeric/matrix — sembunyikan input kunci dan tandai tidak required
            if (keyGroup) keyGroup.style.display = 'none';
            if (keyInput) {
                keyInput.required = false;
            }
        } else {
            // untuk cipher lain, tampilkan lagi dan jadikan required
            if (keyGroup) keyGroup.style.display = 'block';
            if (keyInput) {
                keyInput.required = true;
            }
        }
    }

    function updateFileOptionVisibility() {
        const v = cipherType ? cipherType.value : '';
        if (!alertBox) return;
        alertBox.innerHTML = '';
        // For LETTER_ONLY ciphers: allow file upload but restrict to .txt
        if (LETTER_ONLY.includes(v)) {
            if (labelFileOption) labelFileOption.style.display = 'inline-flex';
            if (fileUpload) fileUpload.accept = '.txt';
            const fi = el('fileInfo');
            if (fi) fi.textContent = 'Hanya file .txt (teks) yang diterima; non-huruf akan dibuang.';
            // show gentle warning that content will be cleaned to A–Z
            alertBox.innerHTML = `<div class="alert alert-danger">⚠️  "${v}" Cipher hanya memproses alfabet A–Z. Anda hanya bisa menggunakan kolom input teks dan mengupload file .txt, semua spasi, tanda baca, dan karakter non-huruf akan dihapus saat proses enkripsi.</div>`;
            if (fileInputSection && radioFile && radioFile.checked) {
                // keep file input visible if chosen
                fileInputSection.style.display = 'block';
                textInputSection.style.display = 'none';
            }
        } else {
            if (labelFileOption) labelFileOption.style.display = 'inline-flex';
            if (fileUpload) fileUpload.accept = ''; // allow all
            alertBox.innerHTML = '';
            const fi = el('fileInfo');
            if (fi) fi.textContent = 'File dapat berupa text, gambar, document, atau file binary lainnya';
        }
    }

    function updatePlayfairPreviewVisibility() {
        const v = cipherType ? cipherType.value : '';
        if (!playfairPreview) return;
        if (v === 'playfair') {
            playfairPreview.style.display = 'block';
        } else {
            playfairPreview.style.display = 'none';
        }
    }

    // client-side cleaning and pairing to match server logic for Playfair preview
    function clientCleanAlpha(s) {
        if (!s) return '';
        return s.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I');
    }

    function preparePlayfairPairs(s) {
        // s should be already cleaned and uppercase with J->I
        const pairs = [];
        let i = 0;
        while (i < s.length) {
            const a = s[i];
            const b = (i+1 < s.length) ? s[i+1] : null;
            if (b === null) {
                pairs.push(a + 'X');
                i += 1;
            } else if (a === b) {
                pairs.push(a + 'X');
                i += 1;
            } else {
                pairs.push(a + b);
                i += 2;
            }
        }
        return pairs;
    }

    function updatePlayfairPreview() {
        if (!playfairPreviewBox) return;
        if (!cipherType || cipherType.value !== 'playfair') return;
        const raw = inputText ? inputText.value || '' : '';
        const key = keyInput ? keyInput.value || '' : '';
        const cleaned = clientCleanAlpha(raw);
        const pairs = preparePlayfairPairs(cleaned);
        let html = `<div style="font-family: monospace; white-space: pre-wrap;">CLEANED: ${cleaned}\n\nPAIRS:\n${pairs.join(' ')}</div>`;
        if (!cleaned) html = '<div class="muted">Masukkan teks untuk melihat preview pembersihan dan pasangan (digraph).</div>';
        playfairPreviewBox.innerHTML = html;
    }

    // initial visibility
    updatePlayfairPreviewVisibility();

    // form submit handler
    const form = document.getElementById('cipherForm');
    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (alertBox) alertBox.innerHTML = '';
            if (resultSection) resultSection.classList.remove('show');
            if (loadingBox) loadingBox.classList.add('show');

            const formData = new FormData(form);

            try {
                const resp = await fetch('/encrypt', { method: 'POST', body: formData });
                const data = await resp.json();
                if (loadingBox) loadingBox.classList.remove('show');

                if (data.success) {
                    if (resultBox) resultBox.textContent = data.result_text ? data.result_text : '(no preview)';
                    if (base64Box) base64Box.textContent = data.result ? data.result : '';
                    if (resultSection) resultSection.classList.add('show');
                    window.__daz_result_base64 = data.result;
                    window.__daz_filename = data.filename || 'download.dat';
                    if (alertBox) alertBox.innerHTML = '<div class="alert alert-success">✅ Proses berhasil!</div>';
                } else {
                    if (alertBox) alertBox.innerHTML = `<div class="alert alert-danger">❌ Error: ${data.error}</div>`;
                }
            } catch (err) {
                if (loadingBox) loadingBox.classList.remove('show');
                if (alertBox) alertBox.innerHTML = `<div class="alert alert-danger">❌ Error: ${err.message}</div>`;
            }
        });
    }

    // download
    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            const result = window.__daz_result_base64;
            const filename = window.__daz_filename || 'download.dat';
            if (!result) { alert('Tidak ada data untuk didownload'); return; }
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/download';
            const dataInput = document.createElement('input');
            dataInput.type = 'hidden'; dataInput.name = 'data'; dataInput.value = result;
            const fnInput = document.createElement('input');
            fnInput.type = 'hidden'; fnInput.name = 'filename'; fnInput.value = filename;
            form.appendChild(dataInput); form.appendChild(fnInput);
            document.body.appendChild(form);
            form.submit();
            document.body.removeChild(form);
        });
    }

    // copy
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const result = window.__daz_result_base64;
            if (!result) { alert('Tidak ada data untuk dicopy'); return; }
            navigator.clipboard.writeText(result).then(() => {
                alert('✅ Base64 berhasil dicopy ke clipboard!');
            }).catch(() => alert('❌ Gagal copy ke clipboard'));
        });
    }

    // reset
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            if (form) form.reset();
            if (resultSection) resultSection.classList.remove('show');
            if (alertBox) alertBox.innerHTML = '';
            if (fileNameSpan) fileNameSpan.textContent = 'Belum ada file dipilih';
            document.querySelectorAll('.cipher-options').forEach(opt => opt.classList.remove('show'));
            if (labelFileOption) labelFileOption.style.display = 'inline-flex';
            if (textInputSection) textInputSection.style.display = 'block';
            if (fileInputSection) fileInputSection.style.display = 'none';
            if (playfairPreview) playfairPreview.style.display = 'none';
            if (playfairPreviewBox) playfairPreviewBox.innerHTML = '';
            window.__daz_result_base64 = null;
            window.__daz_filename = null;

            // restore key field visibility & required flag
            if (keyGroup) keyGroup.style.display = 'block';
            if (keyInput) keyInput.required = true;
        });
    }
});
