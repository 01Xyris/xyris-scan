#define YAML_CPP_STATIC_DEFINE 
#include "TlsScanner.h"
#include <psapi.h>
#include <ws2tcpip.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "Psapi.lib")

TlsScanner::TlsScanner(const Config config) : config(config) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        exit(1);
    }
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

std::vector<MIB_TCPROW_OWNER_PID> TlsScanner::getTcpConnections() const {
    std::vector<MIB_TCPROW_OWNER_PID> connections;
    PMIB_TCPTABLE_OWNER_PID tcpTable;
    ULONG size = 0;
    DWORD ret = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (ret != ERROR_INSUFFICIENT_BUFFER) {
        return connections;
    }

    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if ((ret = GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) != NO_ERROR) {
        free(tcpTable);
        return connections;
    }

    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
        connections.push_back(tcpTable->table[i]);
    }

    free(tcpTable);
    return connections;
}

std::string TlsScanner::getProcessName(DWORD pid) const {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return "";

    TCHAR processName[MAX_PATH] = TEXT("<unknown>");
    HMODULE hMod;
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleBaseName(hProcess, hMod, processName, sizeof(processName) / sizeof(TCHAR));
    }

    CloseHandle(hProcess);
    std::wstring wstr(processName);
    return std::string(wstr.begin(), wstr.end());
}

bool TlsScanner::ScanTlsCertificate(const std::string ip, const std::string port) const {
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        return false;
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {

        SSL_CTX_free(ctx);
        return false;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    }

    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* result = nullptr;

    if (getaddrinfo(ip.c_str(), port.c_str(), &hints, &result) != 0) {
        closesocket(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    }

    if (connect(sock, result->ai_addr, result->ai_addrlen) != 0) {

        freeaddrinfo(result);
        closesocket(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    }

    freeaddrinfo(result);

    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return false;
    }

    bool badCertFound = false;
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char* subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);

        if (subj && issuer) {
            if (isBadEntry(subj) || isBadEntry(issuer)) {
                badCertFound = true;
        
            }
        }

        X509_free(cert);
    }


    SSL_shutdown(ssl);
    closesocket(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return badCertFound;
}

bool TlsScanner::isBadEntry(const std::string entry) const {
    for (const auto& badEntry : config.getBadEntries()) {
        if (entry.find(badEntry) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void TlsScanner::ScanConnections()  {
    auto connections = getTcpConnections();
    for (const auto& conn : connections) {
        if (conn.dwState == MIB_TCP_STATE_ESTAB) {
            char ip[INET_ADDRSTRLEN];
            InetNtopA(AF_INET, &conn.dwRemoteAddr, ip, INET_ADDRSTRLEN);
            std::string port = std::to_string(ntohs((u_short)conn.dwRemotePort));
            std::string processName = getProcessName(conn.dwOwningPid);

            if (processName.empty()) {
                processName = "<unknown>";
            }

            if (ScanTlsCertificate(ip, port)) {
                std::cout << "Process: " << processName << " (PID: " << conn.dwOwningPid << ")\n";
                std::cout << "IP: " << ip << ":" << port << "\n";
                std::cout << "------------------------\n";
            }
        }
    }

    WSACleanup();
}
