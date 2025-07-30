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

#define PORT 49152
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

// Close sockets and stop the application
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

        if (msg == "__exit__") {
            std::cout << COLOR_BLUE << "\n[Friend has left the chat]" << COLOR_RESET << std::endl;
            running = false;
            break;
        }

        std::cout << "\n" << COLOR_BLUE << msg << COLOR_RESET
            << "\n" << COLOR_GREEN << "> " << COLOR_RESET;
    }

    cleanup();
    clear_screen();
    std::cout << "Session ended, chat cleared.\n";
}

// Display short fingerprint of the public key
void print_fingerprint(const unsigned char* pubkey) {
    unsigned char fp[5];
    crypto_generichash(fp, sizeof(fp), pubkey, crypto_kx_PUBLICKEYBYTES, nullptr, 0);

    std::cout << "Fingerprint: ";
    for (int i = 0; i < 5; ++i) {
        printf("%02X", fp[i]);
        if (i < 4) std::cout << "-";
    }
    std::cout << std::endl;
}

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

    unsigned char session_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char session_tx[crypto_kx_SESSIONKEYBYTES];

    if (mode == 's') {
        // --- SERVER MODE ---
        std::string pin;
        do {
            std::cout << "Enter 4-digit PIN: ";
            std::getline(std::cin, pin);
        } while (pin.size() != 4);

        // Generate server key pair
        unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
        unsigned char server_sk[crypto_kx_SECRETKEYBYTES];

        if (crypto_kx_keypair(server_pk, server_sk) != 0) {
            std::cerr << "Failed to generate server keypair\n";
            return 1;
        }

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(PORT);
        print_fingerprint(server_pk);

        if (bind(sockfd, (sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "Bind failed\n";
            cleanup();
            return 1;
        }
        listen(sockfd, 1);

        std::cout << "Waiting for connection...\n";
        connfd = accept(sockfd, nullptr, nullptr);
        if (connfd < 0) {
            std::cerr << "Accept failed\n";
            cleanup();
            return 1;
        }
        std::cout << "Client connected!\n";

        // Send server's public key
        secure_send(connfd, server_pk, crypto_kx_PUBLICKEYBYTES);

        // Send PIN to client
        secure_send(connfd, (const unsigned char*)pin.data(), pin.size());

        // Receive client's public key
        std::vector<unsigned char> client_pk_vec;
        if (!secure_recv(connfd, client_pk_vec) || client_pk_vec.size() != crypto_kx_PUBLICKEYBYTES) {
            std::cerr << "Failed to receive client public key\n";
            cleanup();
            return 1;
        }
        unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
        memcpy(client_pk, client_pk_vec.data(), crypto_kx_PUBLICKEYBYTES);

        // Receive PIN from client
        std::vector<unsigned char> recvpin;
        if (!secure_recv(connfd, recvpin)) {
            std::cerr << "Failed to receive PIN\n";
            cleanup();
            return 1;
        }
        std::string client_pin(recvpin.begin(), recvpin.end());
        if (client_pin != pin) {
            std::cerr << "PIN mismatch\n";
            cleanup();
            return 1;
        }
        std::cout << "PIN verified!\n";

        // Receive client's IP address
        std::vector<unsigned char> ip_buf;
        if (!secure_recv(connfd, ip_buf)) {
            std::cerr << "Failed to receive client IP\n";
            cleanup();
            return 1;
        }
        std::string client_ip(ip_buf.begin(), ip_buf.end());
        std::cout << "Connected client IP: " << client_ip << std::endl;

        // Generate session keys (server)
        if (crypto_kx_server_session_keys(session_rx, session_tx, server_pk, server_sk, client_pk) != 0) {
            std::cerr << "Failed to create session keys\n";
            cleanup();
            return 1;
        }

        // Use tx key for sending, rx for receiving
        std::thread t_recv(recv_loop, connfd, session_rx);
        std::thread t_send(send_loop, connfd, session_tx);
        t_recv.join();
        t_send.join();

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

        // Receive server's public key
        std::vector<unsigned char> server_pk_vec;
        if (!secure_recv(sockfd, server_pk_vec) || server_pk_vec.size() != crypto_kx_PUBLICKEYBYTES) {
            std::cerr << "Failed to receive server public key\n";
            cleanup();
            return 1;
        }
        unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
        memcpy(server_pk, server_pk_vec.data(), crypto_kx_PUBLICKEYBYTES);

        // Display server key fingerprint
        print_fingerprint(server_pk);

        // Ask user to verify the fingerprint manually
        std::string confirm;
        std::cout << "Does the fingerprint match the server's? (y/n): ";
        std::getline(std::cin, confirm);
        if (confirm != "y") {
            std::cerr << "Fingerprint mismatch. Aborting.\n";
            cleanup();
            return 1;
        }

        // Receive PIN from server
        std::vector<unsigned char> recvpin;
        if (!secure_recv(sockfd, recvpin)) {
            std::cerr << "Failed to receive PIN\n";
            cleanup();
            return 1;
        }
        std::string server_pin(recvpin.begin(), recvpin.end());

        // Generate client key pair
        unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
        unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
        crypto_kx_keypair(client_pk, client_sk);

        // Send client's public key
        secure_send(sockfd, client_pk, crypto_kx_PUBLICKEYBYTES);

        // Limit PIN entry attempts
        int attempts = 3;
        bool pin_ok = false;
        while (attempts--) {
            std::string input_pin;
            std::cout << "Enter received PIN: ";
            std::getline(std::cin, input_pin);

            if (input_pin == server_pin) {
                secure_send(sockfd, (const unsigned char*)input_pin.data(), input_pin.size());
                pin_ok = true;
                break;
            }
            std::cout << "Incorrect PIN. Attempts left: " << attempts << "\n";
        }
        if (!pin_ok) {
            std::cerr << "Too many failed attempts. Aborting.\n";
            cleanup();
            return 1;
        }

        // Retrieve client's local IP address (as seen by the server)
        sockaddr_in local_addr;
        socklen_t addr_len = sizeof(local_addr);
        getsockname(sockfd, (sockaddr*)&local_addr, &addr_len);
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        // Send client's IP to server
        secure_send(sockfd, (const unsigned char*)client_ip, strlen(client_ip));

        // Generate session keys (client)
        if (crypto_kx_client_session_keys(session_rx, session_tx, client_pk, client_sk, server_pk) != 0) {
            std::cerr << "Failed to create session keys\n";
            cleanup();
            return 1;
        }

        // Start chat threads
        std::thread t_recv(recv_loop, connfd, session_rx);
        std::thread t_send(send_loop, connfd, session_tx);
        t_recv.join();
        t_send.join();
    }

    cleanup();
    clear_screen();
    std::cout << "Session ended, chat cleared.\n";
    return 0;
}
