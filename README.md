# Securem

### ✅ Securem is a lightweight, console-based messenger built with C++ and libsodium that supports end-to-end encrypted communication over TCP sockets. It works cross-platform (Windows and Linux), operates only on local networks (LAN), and is designed for educational purposes only.

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

```bash
g++ -std=c++17 main.cpp -o securem.exe -lsodium
```

---

## 🏃 Running the program

If you don't want to build the project yourself, download the pre-compiled archive (`release.zip`) from the `/bin` folder.  
The archive includes the executable (`securem.exe` for Windows or `securem` for Linux) and all necessary files, such as `libsodium.dll` for Windows.  
Extract the archive, then run the executable.

---

## ⚙ How it works

- Runs in **server** or **client** mode  
- The **server** waits for a connection from the client  
- Server generates and sends a **4-digit PIN code** to the client  
- Both sides verify the PIN and derive a symmetric encryption key using libsodium's generic hash function  
- Messages are encrypted with `crypto_secretbox` (XSalsa20 stream cipher + Poly1305 MAC)  
- Each message is sent with a **random nonce** prefix for security  
- Supports **graceful exit** with a special exit tag (`__exit__`)  
- Console-based interface with **color-coded** input and output for clarity  
- **Works only on local network (LAN):**  
  - Run one instance as the **server** on one machine  
  - Run another instance as the **client** on a different machine connected to the same local network  
  - Client connects using the **local IP address** of the server in your network  
  - Server creates a **PIN code** that the client must enter exactly to establish a secure connection  

---

### 📁 Files

- `main.cpp` – source code  
- `.gitignore` – excludes build files, OS cache, etc.  
- `LICENSE` – open source license (MIT by default)  
- `/bin/release.zip` – pre-compiled archive including executables and required files (`securem.exe`, `libsodium.dll` for Windows)  
