#  CryptoKit — Cryptography Toolkit

A futuristic, cyber-themed full-stack cryptography web application built with **Python/Flask** and a modern, responsive frontend. This project implements multiple core cryptographic standards, including Symmetric/Asymmetric encryption, data encoding, and secure hashing.

---
 **Developed for:** Alexandria University — Cryptography Course Project.
---

##  Features & Supported Algorithms

CryptoKit provides a unified and interactive dashboard divided into 4 main cryptographic zones:

### 1. Symmetric Encryption
Secure data encryption and decryption with block-cipher modes utilizing proper padding (`PKCS7`):
* **AES** (Supports key sizes of 16, 24, or 32 bytes)
* **DES** (Strict 8-byte key validation)
* **3DES** (Triple DES supporting 16 or 24-byte keys)

### 2.  Asymmetric Encryption (Public-Key)
Full implementation of public-key cryptography via **RSA**:
* On-the-fly RSA Key Generation (supports customized bit sizes, e.g., 2048-bit).
* Session-based secure storage for generated keys.
* Secure text encryption and decryption using optimal asymmetric encryption padding (**PKCS1_OAEP**).

### 3.  Encoding & Decoding
Quick tools to transform data into safe formats or alternative representations:
* **Base64**
* **Hexadecimal (Hex)**
* **URL Encoding**

### 4.  Hashing & Digital Fingerprints
Generate one-way cryptographic secure digests with optional salt generation:
* **SHA-256**
* **SHA-512**
* **Salted Hashing** (Generates a dynamic 16-character hex salt automatically for advanced security).

---

##  Tech Stack & Dependencies

* **Backend:** Python 3.x, Flask (Session-handling & Routing)
* **Cryptography Core:** `pycryptodome` (Handles AES, DES, RSA, Padding)
* **Frontend:** Semantic HTML5, Custom CSS3 (High-fidelity dark/neon glow theme with responsive grid layout), Vanilla JavaScript (Asynchronous `Fetch API` communicating with Flask backend).

---
