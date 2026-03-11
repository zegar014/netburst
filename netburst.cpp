#include <iostream>
#include <cstring>
#include <string>
#include <cstdlib>
#include <ctime>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <thread>
#include <chrono>

std::string lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return result;
}
std::string upper(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c){ return std::toupper(c); });
    return result;
}

int main() {
    std::string ip_input, ip;
    int port = 0;
    int pk;
    int LEN = 0;
    std::string mt;
    double tm;
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    srand(time(NULL));

    std::cout << "IP address: "; std::cin >> ip_input;

    size_t close_bracket = ip_input.find(']');
    size_t last_colon = ip_input.find_last_of(':');
    if (ip_input[0] == '[' && close_bracket != std::string::npos) {
        ip = ip_input.substr(1, close_bracket - 1);
        if (ip_input.length() > close_bracket + 1 && ip_input[close_bracket + 1] == ':') {
            try {
                port = std::stoi(ip_input.substr(close_bracket + 2));
            } catch (...) { port = 0; }
        }
    } else if (last_colon != std::string::npos && ip_input.find_first_of(':') == last_colon) {
        ip = ip_input.substr(0, last_colon);
        try {
            port = std::stoi(ip_input.substr(last_colon + 1));
        } catch (...) { port = 0; }
    } else {
        ip = ip_input;
        std::cout << "Port: "; std::cin >> port;
    }

    if (port < 1 || port > 65535) {
        std::cerr << "Invalid port.\n";
        return 1;
    }

    std::cout << "Method: "; std::cin >> mt;
    std::string lmt = lower(mt);
    
    if (lmt != "syn" && lmt != "udp" && lmt != "tcp") {
        std::cerr << "Invalid method.\n";
        return 1;
    }

    if (lmt != "syn"){
        std::cout << "Packet size: "; std::cin >> LEN;
    }
    std::cout << "Packet amount: "; std::cin >> pk;
    std::cout << "Timeout: "; std::cin >> tm;

    int family = (ip.find(':') != std::string::npos) ? AF_INET6 : AF_INET;

    if (lmt == "udp"){
        int sock = socket(family, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("socket");
            return 1;
        }

        if (family == AF_INET) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
                std::cerr << "Invalid IP address.\n";
                close(sock); return 1;
            }
            for(int x = 0; x < pk; x++) {
                char message[LEN];
                for(int i = 0; i < LEN; i++) message[i] = charset[rand() % 62];
                sendto(sock, message, LEN, 0, (struct sockaddr*)&addr, sizeof(addr));
                std::cout << "Sent " << LEN << " bytes to " << ip << ":" << port << " by UDP\n";
                if (tm > 0) std::this_thread::sleep_for(std::chrono::duration<double>(tm));
            }
        } else {
            sockaddr_in6 addr{};
            addr.sin6_family = AF_INET6;
            addr.sin6_port = htons(port);
            if (inet_pton(AF_INET6, ip.c_str(), &addr.sin6_addr) <= 0) {
                std::cerr << "Invalid IP address.\n";
                close(sock); return 1;
            }
            for(int x = 0; x < pk; x++) {
                char message[LEN];
                for(int i = 0; i < LEN; i++) message[i] = charset[rand() % 62];
                sendto(sock, message, LEN, 0, (struct sockaddr*)&addr, sizeof(addr));
                std::cout << "Sent " << LEN << " bytes to [" << ip << "]:" << port << " by UDP\n";
                if (tm > 0) std::this_thread::sleep_for(std::chrono::duration<double>(tm));
            }
        }
        close(sock);
    }
    else if (lmt == "tcp") {
        int sock = socket(family, SOCK_STREAM, 0);
        if (sock < 0) { perror("socket"); return 1; }

        if (family == AF_INET) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
            if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                perror("connect"); close(sock); return 1;
            }
        } else {
            sockaddr_in6 addr{};
            addr.sin6_family = AF_INET6;
            addr.sin6_port = htons(port);
            inet_pton(AF_INET6, ip.c_str(), &addr.sin6_addr);
            if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                perror("connect"); close(sock); return 1;
            }
        }

        for(int x = 0; x < pk; x++) {
            char message[LEN + 1];
            for(int i = 0; i < LEN; i++) message[i] = charset[rand() % 62];
            message[LEN] = '\0';
            if (send(sock, message, LEN, 0) < 0) { perror("send"); break; }
            std::cout << "Sent " << LEN << " bytes by TCP\n";
            if (tm > 0) std::this_thread::sleep_for(std::chrono::duration<double>(tm));
        }
        close(sock);
    }
    else if (lmt == "syn") {
        for(int x = 0; x < pk; x++) {
            int sock = socket(family, SOCK_STREAM, 0);
            if (sock < 0) { perror("socket"); break; }

            int res = -1;
            if (family == AF_INET) {
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
                res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
            } else {
                sockaddr_in6 addr{};
                addr.sin6_family = AF_INET6;
                addr.sin6_port = htons(port);
                inet_pton(AF_INET6, ip.c_str(), &addr.sin6_addr);
                res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
            }

            if (res == 0) std::cout << "Handshake successful by SYN\n";
            else std::cout << "Connection refused by SYN\n";

            close(sock);
            if (tm > 0) std::this_thread::sleep_for(std::chrono::duration<double>(tm));
        }
    }
    return 0;
}