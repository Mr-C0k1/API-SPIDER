# API-SPIDER 🕷️

**API-SPIDER** adalah tool sederhana untuk melakukan **API endpoint hunting** dan **automatic fuzzing** secara otomatis. Tool ini membantu menemukan hidden API endpoints dan menguji kerentanan dasar seperti parameter injection atau response anomali.

> **Warning**: Tool ini hanya untuk tujuan edukasi dan pengujian pada target yang kamu miliki izinnya (authorized testing). Penulis tidak bertanggung jawab atas penyalahgunaan.

## Fitur Utama

- **API Hunting**: Mencari endpoint API potensial menggunakan wordlist (daftar_kata.txt).
- **Automatic Fuzzing**: Fuzzing otomatis pada parameter API dengan payload beragam.
- Dukungan request via Python (`api_hunter.py`) dan curl script (`apihunter-curl.sh`).
- Mudah dikustomisasi wordlist dan payload.

## File dalam Repository

- `api_hunter.py`      : Script utama Python untuk API hunting dan fuzzing.
- `apihunter-curl.sh`  : Versi alternatif menggunakan curl untuk request cepat.
- `auto_fuzzer.py`     : Script fuzzing otomatis pada endpoint yang ditemukan.
- `daftar_kata.txt`    : Wordlist default (bisa diganti dengan wordlist lain seperti SecLists).
- `LISENSI`            : Lisensi proyek (GPL-3.0).
- `README.md`          : File ini.

## Persyaratan

- Python 3.x
- Library Python: `requests` (install dengan `pip install requests`)
- Untuk script curl: `curl` dan `bash`

## Cara Instalasi

'''instalasi'''
git clone https://github.com/Tuan-Kok1/API-SPIDER.git
cd API-SPIDER
pip install requests  # jika belum terinstall

# Cara Penggunaan
1. API Hunting Dasar
' python api_hunter.py -u https://target.com -w daftar_kata.txt ' >> API Hunting Dasar
' python auto_fuzzer.py -u https://target.com/api/endpoint -w daftar_kata.txt ' >> Automatic Fuzzing
' chmod +x apihunter-curl.sh
./apihunter-curl.sh https://target.com daftar_kata.txt ' >> Menggunakan Curl Script

note!!!: Tambahkan opsi lain sesuai kebutuhan (lihat --help pada tiap script).

Contoh Output
Tool akan menampilkan endpoint yang memberikan response berbeda (misalnya 200 vs 404) dan potensi parameter yang bisa difuzz.
Kontribusi
Selamat datang untuk kontribusi! Fork repo ini, buat branch baru, dan submit Pull Request.

Tambah wordlist lebih lengkap
Tambah payload untuk fuzzing spesifik (SQLi, XSS, dll)
Perbaiki bug atau tambah fitur

Lisensi
Proyek ini dilisensikan di bawah GNU General Public License v3.0 - lihat file LISENSI untuk detail.

Dibuat oleh Tuan-Kok1
Jika ada pertanyaan, buka Issue di repository ini!
🕷️ Happy Hunting! 🕷️"
