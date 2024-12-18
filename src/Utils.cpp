#include <fstream>
#include <iomanip>
#include <stdexcept>

#include "cryptofw/Utils.hpp"
#include "CryptoProCsp.hpp"
#include "VipNetCsp.hpp"


void Utils::SaveDataToFile(const Blob& data, const std::string& file_path) {
    std::ofstream outfile(file_path, std::ios::out | std::ios::binary);
    outfile.write(reinterpret_cast<const char*>(&data[0]), data.size());
}

Blob Utils::ReadDataFromFile(const std::string& file_path) {
	std::ifstream instream(file_path, std::ios::in | std::ios::binary);
	Blob data((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());

	if (instream.fail()) {
		throw std::runtime_error("File " + file_path + " does not exist");
	}

	return data;
}

std::ostream& operator<<(std::ostream& out, const Blob& blob) {
	for (auto byte : blob) {
		out << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(byte) << ' ';
	}
	return out;
}
