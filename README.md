# Securem
### ✅ Securem is a lightweight, console-based messenger built with C++ and libsodium that supports end-to-end encrypted communication over TCP sockets. It works cross-platform (Windows and Linux) and is designed for educational purposes only.
---

## 🚀 Features

- End-to-end encryption (E2EE) using libsodium
- Simple TCP socket connection (client/server)
- Console interface for lightweight communication
- Cross-platform support

---

## ⚠️ Disclaimer

This project is for educational and experimental use only.  
The author does **not** take any responsibility for misuse or damage caused by using this software.

---

## 🔧 Requirements

- `libsodium` library
- C++17 or later
- `g++`, `clang++`, or MSVC

---

## 🛠️ Build & Run

### Linux:
```bash
sudo apt install libsodium-dev
g++ -std=c++17 main.cpp -o securem -lsodium
./securem
```

### Windows:

Use MSVC or MinGW with preinstalled libsodium. Example:

g++ -std=c++17 main.cpp -o securem.exe -lsodium

---

## 🏃Running the program

If you don't want to build the project yourself, download the pre-compiled archive (release.zip) from the /bin folder.
The archive includes the executable (securem.exe for Windows or securem for Linux) and all necessary files, such as libsodium.dll for Windows.
Extract the archive, then run the executable.

---
## ⚙ How it works

- Runs in server or client mode  
- Server waits for connection, sends a 4-digit PIN to client  
- Both sides verify PIN and derive symmetric key using libsodium's generic hash  
- Messages are encrypted with crypto_secretbox (XSalsa20 + Poly1305)  
- Each message is sent with a random nonce prefix  
- Supports graceful exit with special exit tag  
- Console-based interface with color-coded input/output

---

### 📁 Files

- `main.cpp` – source code  
- `.gitignore` – exclude build files, OS cache, etc.  
- `LICENSE` – open source license (MIT by default)  
- `/bin/release.zip` – pre-compiled archive including executables and required files (`securem.exe`, `libsodium.dll` for Windows)
