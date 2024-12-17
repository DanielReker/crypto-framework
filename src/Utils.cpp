#include <fstream>
#include <iomanip>

#include "cryptofw/Utils.hpp"
#include "CryptoProCsp.hpp"
#include "MscapiCsp.hpp"


std::shared_ptr<ICsp> Utils::GetCryptoProCsp() {
    return std::make_shared<CryptoProCsp>(L"http://pki.tax.gov.ru/tsp/tsp.srf");
}

std::shared_ptr<ICsp> Utils::GetVipNetCsp() {
    return std::make_shared<MscapiCsp>("Infotecs");
}

void Utils::SaveDataToFile(const Blob& data, const std::string& file_path) {
    std::ofstream outfile(file_path, std::ios::out | std::ios::binary);
    outfile.write(reinterpret_cast<const char*>(&data[0]), data.size());
}

std::ostream& operator<<(std::ostream& out, const Blob& blob) {
	for (auto byte : blob) {
		out << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(byte) << ' ';
	}
	return out;
}
