#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <iostream>

class Config {
public:
    Config(const std::filesystem::path& config_folder);
    const std::vector<std::string> getBadEntries() const;

private:
    std::vector<std::string> badEntries;
    void loadConfig(const std::filesystem::path config_folder);
};
