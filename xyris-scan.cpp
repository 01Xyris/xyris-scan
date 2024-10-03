#define YAML_CPP_STATIC_DEFINE 
#include "Config.h"
#include "TlsScanner.h"
#include <filesystem>

int main() {
	std::filesystem::path config_folder = "../templates";
	Config config(config_folder);
	TlsScanner scanner(config);

	scanner.ScanConnections();
}