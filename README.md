# 🔐 PGP Email Simulation (Python)

This project simulates a secure email communication system based on PGP (Pretty Good Privacy) principles using Python.  
It enables encrypted and integrity-verified communication between sender and receiver using a hybrid RSA + AES encryption scheme over TCP sockets.

---

## 💡 Overview

The program supports:
- User mode selection 
- Secure transmission of plaintext messages or `.txt` files
- Local or LAN-based communication between two devices
  
---

## 🧩 Features

- **Asymmetric encryption**: RSA (2048-bit) for secure key exchange  
- **Symmetric encryption**: AES-256 for fast and secure data encryption  
- **Hashing**: SHA-256 for integrity check via digital signature  
- **Compression**: zlib to reduce payload size  
- **Hybrid encryption structure** (PGP-like)
- Works across **two separate computers on the same network**
- Allows **sending and receiving encrypted text or text files**

