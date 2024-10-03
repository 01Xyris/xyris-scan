#pragma once
#include <string>
#include <vector>
#include <WinSock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iphlpapi.h>
#include "Config.h"

class TlsScanner {
public: 
	TlsScanner(const Config config);
	void ScanConnections();
	const std::wstring getResults() const;
private:
	const Config config;
	std::vector<MIB_TCPROW_OWNER_PID> getTcpConnections() const;
	std::string getProcessName(DWORD pid) const;
	bool ScanTlsCertificate(const std::string ip, const std::string port) const;
	bool isBadEntry(const std::string entry) const;

	std::wstring results;

};