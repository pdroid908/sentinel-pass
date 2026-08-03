# SentinelPass

SentinelPass adalah aplikasi web berbasis Go yang membantu pengguna mengecek apakah password mereka pernah muncul di kebocoran data publik, sekaligus menyediakan generator password acak yang kuat.

Project ini dibangun dengan fokus pada dua hal: keamanan dan pengalaman pengguna. Di sisi backend, SentinelPass menggunakan bahasa Go dengan Gin untuk menangani API secara cepat dan sederhana. Di sisi frontend, aplikasi ini menyajikan antarmuka ringan yang langsung bisa dipakai tanpa konfigurasi rumit.

## Masalah yang Diselesaikan

Banyak pengguna masih memakai password yang lemah, berulang, atau pernah bocor tanpa disadari. SentinelPass membantu menjawab pertanyaan penting berikut:

1. Apakah password ini pernah muncul di kebocoran data publik?
2. Seberapa sering password tersebut terdeteksi bocor?
3. Jika perlu password baru, bagaimana cara membuat password yang lebih kuat dengan cepat?

Dengan pendekatan k-anonymity dari Have I Been Pwned, aplikasi ini hanya mengirim sebagian kecil hash password ke API eksternal. Artinya, proses pengecekan tetap menjaga privasi pengguna lebih baik dibanding mengirim password mentah.

## Kenapa Project Ini Menarik

Untuk kebutuhan portofolio, project ini menunjukkan beberapa hal yang biasanya dicari recruiter atau tim hiring:

- Problem solving di domain security dan data protection.
- Integrasi backend Go dengan API eksternal.
- Implementasi alur request-response yang jelas dan ringan.
- Pemahaman privacy-aware design melalui pendekatan hash prefix.
- Kemampuan membuat produk end-to-end: backend, frontend, dan deployment.

## Fitur Utama

- Cek password terhadap database kebocoran publik menggunakan Have I Been Pwned.
- Generator password acak yang menggunakan `crypto/rand`.
- Tampilan frontend modern, minimal, dan responsif.
- API JSON untuk integrasi program lain.
- Dukungan local server dan serverless handler untuk deployment.

## Cara Kerja Singkat

1. User memasukkan password.
2. Backend menghitung SHA-1 hash password.
3. Hanya 5 karakter awal hash yang dikirim ke endpoint HIBP.
4. Server membandingkan suffix hash dari hasil API dengan hash lengkap milik user.
5. Jika cocok, aplikasi menampilkan bahwa password pernah bocor beserta jumlah kemunculannya.

Pendekatan ini membuat sistem lebih aman karena password tidak dikirim secara mentah ke layanan eksternal.

## Tech Stack

- Go 1.26.4
- Gin Web Framework
- HTML + React UMD
- Tailwind CSS via CDN
- Have I Been Pwned Passwords API

## Struktur Project

- `main.go` - entry point untuk menjalankan server lokal.
- `api/index.go` - handler serverless untuk deployment, misalnya di Vercel.
- `index.html` - frontend utama aplikasi.
- `vercel.json` - konfigurasi deployment serverless.

## Endpoint API

### `POST /api/check-password`

Request:

```json
{
  "password": "password-yang-ingin-dicek"
}
```

Response sukses:

```json
{
  "password": "password-yang-ingin-dicek",
  "full_hash": "...",
  "prefix": "ABCDE",
  "suffix": "...",
  "matched_suffix": "...",
  "is_pwned": true,
  "pwned_count": 1234,
  "message": "⚠️ BAHAYA! Password ini ditemukan di kebocoran data sebanyak 1234 kali!"
}
```

### `GET /api/generate-password`

Response:

```json
{
  "generated_password": "A1b2C3d4E5f6G7h8"
}
```

## Menjalankan Secara Lokal

### 1. Pastikan Go sudah terpasang

```bash
go version
```

### 2. Jalankan server

```bash
go run main.go
```

Atau:

```bash
go run .
```

### 3. Buka aplikasi

Buka browser ke:

```text
http://localhost:8080
```

## Deployment

Project ini juga disiapkan untuk environment serverless melalui `api/index.go`. Jika dideploy ke platform seperti Vercel, handler tersebut dapat dipakai sebagai function entry point.

## Catatan Keamanan

- Password tidak disimpan ke database.
- Password tidak dikirim secara mentah ke HIBP.
- Generator password memakai `crypto/rand`, bukan pseudo-random biasa.
- Aplikasi dirancang untuk memberi feedback cepat dan transparan kepada user.

## Ringkasan

SentinelPass adalah project kecil yang relevan untuk menunjukkan kemampuan membangun aplikasi Go yang praktis, aman, dan punya value nyata. Cocok untuk portofolio karena menggabungkan backend API, integrasi security service, UI yang usable, dan alur penggunaan yang mudah dipahami.
