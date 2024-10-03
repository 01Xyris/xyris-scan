#define YAML_CPP_STATIC_DEFINE 
#include "Config.h"
#include <yaml-cpp/yaml.h>

#pragma comment(lib, "yaml-cpp.lib")
Config::Config(const std::filesystem::path& config_folder) {
	loadConfig(config_folder);
}

void Config::loadConfig(const std::filesystem::path config_folder) {
	for (const auto& entry : std::filesystem::directory_iterator(config_folder)) {
		if (entry.path().extension() == ".yaml") {
			try {
				YAML::Node config = YAML::LoadFile(entry.path().string());
				if (config["bad_entries"]) {
					for (const auto& item : config["bad_entries"]) {
						badEntries.push_back(item.as<std::string>());
					}
				}
			}
			catch (std::exception e) {
				std::cerr << "Failed to load config from " << entry.path();
			}
		}
	}
}

const std::vector<std::string> Config::getBadEntries() const {
	return badEntries;
}