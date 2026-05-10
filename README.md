# 🔐 CryptoSuite — Multi-Algorithm File Encryption System

> A Streamlit-based web app to encrypt and decrypt any file using five cryptographic algorithms: **Triple DES**, **AES**, **RSA**, **ECC**, and **ElGamal**.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-FF4B4B?logo=streamlit&logoColor=white)
![PyCryptodome](https://img.shields.io/badge/PyCryptodome-3.20%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📌 Overview

CryptoSuite is an Information Security course project that demonstrates practical implementation of classical and modern cryptographic algorithms. It supports both **symmetric** and **asymmetric** encryption, includes **live benchmarking**, and provides an **educational reference** for each algorithm — all through a clean browser UI.

---

## ✨ Features

- 🔒 Encrypt & decrypt **any file type** (text, PDF, images, video, binaries)
- ⚙️ **5 cryptographic algorithms** in one app
- 🎲 Auto key generation (symmetric & asymmetric key pairs)
- 📊 **Performance benchmarking** with charts across algorithms and data sizes
- 📚 Algorithm reference page with pros, cons, and technical specs
- 📥 Download encrypted/decrypted files directly from the browser

---

## 📁 Project Structure

```
IS_project/
├── app.py                  # Streamlit UI — main entry point
├── crypto_algorithms.py    # All 5 cryptographic algorithm classes
├── test_algorithms.py      # Quick verification tests
└── requirements.txt        # Python dependencies
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.8+
- pip

### 1. Clone the repository
```bash
git clone https://github.com/your-username/IS_project.git
cd IS_project
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the app
```bash
streamlit run app.py
```

The app will open automatically at **http://localhost:8501**

---

## 🖥️ How to Use

1. Open the app and go to **🔒 Encrypt / Decrypt** from the sidebar
2. Select an algorithm from the dropdown
3. Click **Generate Key** (symmetric) or **Generate Key Pair** (asymmetric)
4. Upload any file using the file uploader
5. Click **Encrypt File** or **Decrypt File**
6. Download the result

> ⚠️ **Important:** Save your key after generating it. You must use the same key and algorithm to decrypt the file later.

---

## 🔐 Supported Algorithms

| Algorithm | Type | Key Size | Mode | Best For |
|-----------|------|----------|------|----------|
| **Triple DES** | Symmetric | 168-bit | CBC | Legacy banking systems |
| **AES** | Symmetric | 256-bit | CBC | General-purpose encryption |
| **RSA** | Asymmetric | 2048-bit | OAEP | Key exchange, signatures |
| **ECC** | Asymmetric (Hybrid) | 256-bit (P-256) | ECIES | Mobile / IoT / TLS 1.3 |
| **ElGamal** | Asymmetric (Hybrid) | 1024-bit prime | Hybrid+AES | Academic / PGP-style |

### Symmetric (Triple DES & AES)
Same key used for encryption and decryption. Fast and efficient for large files.

### Asymmetric (RSA, ECC, ElGamal)
Public key encrypts, private key decrypts. No shared secret needed.
- **RSA** — data is chunked (190 bytes/chunk) to handle files of any size
- **ECC** — pure-Python P-256 implementation using ECIES (EC key exchange + AES)
- **ElGamal** — hybrid scheme: AES encrypts the data, ElGamal encrypts the AES key

---

## 📂 Supported File Types

All algorithms operate on **raw bytes**, so any file type works:

- 📄 Text files (`.txt`, `.csv`, `.json`, `.xml`)
- 📝 Documents (`.pdf`, `.docx`, `.xlsx`, `.pptx`)
- 🖼️ Images (`.jpg`, `.png`, `.bmp`, `.gif`)
- 🎵 Audio & Video (`.mp3`, `.mp4`, `.wav`)
- 📦 Archives & Binaries (`.zip`, `.exe`, `.bin`, any format)

---

## 📊 Performance Benchmarking

Go to the **📊 Performance** page to compare algorithms:

- Select data sizes: 1 KB, 10 KB, 50 KB, 100 KB
- Select which algorithms to benchmark
- View results as a table and bar charts

**Expected speed order (fastest → slowest):**
```
AES > Triple DES > ECC > ElGamal > RSA
```

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `streamlit` | Web UI framework |
| `pycryptodome` | Triple DES, AES, RSA implementations |
| `pandas` | Benchmark results table |
| `matplotlib` | Performance charts |

Install all at once:
```bash
pip install streamlit pycryptodome pandas matplotlib
```

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: streamlit` | Run `pip install -r requirements.txt` |
| `ModuleNotFoundError: Crypto` | Run `pip install pycryptodome` |
| `streamlit: command not found` | Run `python -m streamlit run app.py` |
| Decryption fails / corrupted output | Use the exact same key and algorithm used to encrypt |
| App doesn't open in browser | Go to `http://localhost:8501` manually |

---

## 🧪 Running Tests

Verify all 5 algorithms work correctly before launching the app:

```bash
python test_algorithms.py
```

Expected output:
```
✅ Triple DES  — PASSED
✅ AES         — PASSED
✅ RSA         — PASSED
✅ ECC         — PASSED
✅ ElGamal     — PASSED
```

---

## 🎓 Course Information

| | |
|---|---|
| **Subject** | Information Security (IS) |
| **Project** | Multi-Algorithm File Encryption & Decryption System |
| **Algorithms** | Triple DES, AES, RSA, ECC (P-256 / secp256r1), ElGamal |

---

## 📄 License

This project is for educational purposes as part of an Information Security course.

---

<p align="center">Built with Python · PyCryptodome · Streamlit</p>
