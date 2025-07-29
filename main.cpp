/*
 * Securem — simple console messenger with E2EE
 * Author: feql
 * GitHub: https://github.com/feqle/securem
 * License: MIT License
 *
 * © 2025 feqle. All rights reserved.
 */

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <csignal>
#include <atomic>
#include <cstdlib>
#include <cstdio>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib,"Ws2_32.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include <sodium.h>

#define PORT 5554
#define BUFFER_SIZE 4096

#ifdef _WIN32
#define CLOSESOCKET closesocket
#else
#define CLOSESOCKET close
#endif

// ANSI color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_BLUE    "\033[34m"

std::atomic<bool> running{ true };
int sockfd = -1;
int connfd = -1;
std::string username = "User";

// Close sockets and mark stop flag
void cleanup() {
    running = false;
#ifdef _WIN32
    if (connfd != -1) CLOSESOCKET(connfd);
    if (sockfd != -1) CLOSESOCKET(sockfd);
    WSACleanup();
#else
    if (connfd != -1) CLOSESOCKET(connfd);
    if (sockfd != -1) CLOSESOCKET(sockfd);
#endif
}

// Ctrl+C handler
void signal_handler(int) {
    std::cout << "\n[!] Exit...\n";

    // If connected, try to send exit message
    if (connfd != -1) {
        const char exit_tag[] = "__exit__";
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

        std::vector<unsigned char> cipher(crypto_secretbox_MACBYTES + sizeof(exit_tag));
        crypto_secretbox_easy(cipher.data(), (const unsigned char*)exit_tag, sizeof(exit_tag) - 1, nonce, (unsigned char*)nullptr);
        // NOTE: Key is not available here, so this is mostly symbolic
    }
    cleanup();
    exit(0);
}

// Clear terminal screen
void clear_screen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

// Send buffer securely (prefix with length)
void secure_send(int fd, const unsigned char* msg, size_t len) {
    uint32_t len_net = htonl((uint32_t)len);
    send(fd, (char*)&len_net, sizeof(len_net), 0);
    send(fd, (const char*)msg, (int)len, 0);
}

// Receive buffer securely (based on prefixed length)
bool secure_recv(int fd, std::vector<unsigned char>& buf) {
    uint32_t len_net;
    int r = recv(fd, (char*)&len_net, sizeof(len_net), MSG_WAITALL);
    if (r <= 0) return false;
    uint32_t len = ntohl(len_net);
    if (len > BUFFER_SIZE) return false;
    buf.resize(len);
    r = recv(fd, (char*)buf.data(), len, MSG_WAITALL);
    return r > 0;
}

// Encrypt message with SecretBox
void encrypt_message(const unsigned char* key, const unsigned char* nonce,
    const unsigned char* msg, size_t msg_len,
    std::vector<unsigned char>& cipher) {
    cipher.resize(msg_len + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(cipher.data(), msg, msg_len, nonce, key);
}

// Decrypt message with SecretBox
bool decrypt_message(const unsigned char* key, const unsigned char* nonce,
    const unsigned char* cipher, size_t cipher_len,
    std::vector<unsigned char>& msg) {
    if (cipher_len < crypto_secretbox_MACBYTES) return false;
    msg.resize(cipher_len - crypto_secretbox_MACBYTES);
    return crypto_secretbox_open_easy(msg.data(), cipher, cipher_len, nonce, key) == 0;
}

// Generate random nonce
void generate_nonce(unsigned char* nonce) {
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
}

// Sending thread loop
void send_loop(int fd, const unsigned char* key) {
    while (running) {
        std::cout << COLOR_GREEN << "> " << COLOR_RESET;
        std::string line;
        if (!std::getline(std::cin, line)) {
            running = false;
            break;
        }

        // If user types "exit", send special exit tag and break
        if (line == "exit") {
            std::string tag = "__exit__";
            unsigned char nonce[crypto_secretbox_NONCEBYTES];
            generate_nonce(nonce);

            std::vector<unsigned char> cipher;
            encrypt_message(key, nonce, (const unsigned char*)tag.data(), tag.size(), cipher);

            std::vector<unsigned char> sendbuf;
            sendbuf.insert(sendbuf.end(), nonce, nonce + crypto_secretbox_NONCEBYTES);
            sendbuf.insert(sendbuf.end(), cipher.begin(), cipher.end());
            secure_send(fd, sendbuf.data(), sendbuf.size());

            running = false;
            break;
        }

        // Add username prefix
        line = username + ": " + line;

        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        generate_nonce(nonce);

        std::vector<unsigned char> cipher;
        encrypt_message(key, nonce, (const unsigned char*)line.data(), line.size(), cipher);

        std::vector<unsigned char> sendbuf;
        sendbuf.insert(sendbuf.end(), nonce, nonce + crypto_secretbox_NONCEBYTES);
        sendbuf.insert(sendbuf.end(), cipher.begin(), cipher.end());
        secure_send(fd, sendbuf.data(), sendbuf.size());
    }
}

// Receiving thread loop
void recv_loop(int fd, const unsigned char* key) {
    while (running) {
        std::vector<unsigned char> recvbuf;
        if (!secure_recv(fd, recvbuf)) {
            running = false;
            break;
        }

        if (recvbuf.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
            running = false;
            break;
        }

        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        std::copy(recvbuf.begin(), recvbuf.begin() + crypto_secretbox_NONCEBYTES, nonce);

        std::vector<unsigned char> decrypted;
        if (!decrypt_message(key, nonce,
            recvbuf.data() + crypto_secretbox_NONCEBYTES,
            recvbuf.size() - crypto_secretbox_NONCEBYTES,
            decrypted)) {
            std::cout << COLOR_BLUE << "\n[!] Failed to decrypt message\n> " << COLOR_RESET;
            continue;
        }

        std::string msg(decrypted.begin(), decrypted.end());

        // Handle exit tag
        if (msg == "__exit__") {
            std::cout << COLOR_BLUE << "\n[Friend has left the chat]" << COLOR_RESET << std::endl;
            running = false;
            break;
        }

        // Display received message
        std::cout << "\n" << COLOR_BLUE << msg << COLOR_RESET
            << "\n" << COLOR_GREEN << "> " << COLOR_RESET;
    }

    // Final cleanup and clear terminal
    cleanup();
    clear_screen();
    std::cout << "Session ended, chat cleared.\n";
}

// Entry point
int main() {
    signal(SIGINT, signal_handler);

    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }
#endif

    clear_screen();

    std::cout << "Enter your username (or leave empty for default): ";
    std::getline(std::cin, username);
    if (username.empty()) username = "User";

    char mode;
    do {
        std::cout << "Choose mode: (s)erver or (c)lient: ";
        std::cin >> mode;
        std::cin.ignore();
    } while (mode != 's' && mode != 'c');

    std::string pin;
    unsigned char key[crypto_secretbox_KEYBYTES];

    if (mode == 's') {
        // --- SERVER MODE ---
        std::cout << "Enter 4-digit PIN: ";
        std::getline(std::cin, pin);
        if (pin.size() != 4) {
            std::cerr << "PIN must be exactly 4 digits\n";
            cleanup();
            return 1;
        }

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(PORT);

        bind(sockfd, (sockaddr*)&addr, sizeof(addr));
        listen(sockfd, 1);

        std::cout << "Waiting for connection...\n";
        connfd = accept(sockfd, nullptr, nullptr);
        std::cout << "Client connected!\n";

        // Send PIN
        secure_send(connfd, (const unsigned char*)pin.data(), pin.size());

        // Receive PIN back from client
        std::vector<unsigned char> recvpin;
        secure_recv(connfd, recvpin);
        std::string client_pin(recvpin.begin(), recvpin.end());
        if (client_pin != pin) {
            std::cerr << "PIN mismatch\n";
            cleanup();
            return 1;
        }
        std::cout << "PIN verified!\n";

        // Derive encryption key from PIN
        crypto_generichash(key, sizeof(key),
            (const unsigned char*)pin.data(), pin.size(),
            nullptr, 0);

        connfd = connfd;
    }
    else {
        // --- CLIENT MODE ---
        std::cout << "Enter server IP: ";
        std::string ip;
        std::getline(std::cin, ip);

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(PORT);
        inet_pton(AF_INET, ip.c_str(), &(addr.sin_addr));

        if (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "Connect failed\n";
            cleanup();
            return 1;
        }
        connfd = sockfd;
        std::cout << "Connected!\n";

        // Receive PIN from server
        std::vector<unsigned char> recvpin;
        secure_recv(sockfd, recvpin);
        std::string server_pin(recvpin.begin(), recvpin.end());

        // Confirm PIN
        std::string input_pin;
        do {
            std::cout << "Enter received PIN: ";
            std::getline(std::cin, input_pin);
        } while (input_pin != server_pin);

        // Send PIN back
        secure_send(sockfd, (const unsigned char*)input_pin.data(), input_pin.size());
        std::cout << "PIN verified!\n";

        // Derive encryption key
        crypto_generichash(key, sizeof(key),
            (const unsigned char*)input_pin.data(), input_pin.size(),
            nullptr, 0);
    }

    // Start chat threads
    std::thread t_recv(recv_loop, connfd, key);
    std::thread t_send(send_loop, connfd, key);
    t_recv.join();
    t_send.join();

    cleanup();
    clear_screen();
    std::cout << "Session ended, chat cleared.\n";
    return 0;
}