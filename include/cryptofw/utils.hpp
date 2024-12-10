#pragma once

#include <memory>
#include <string>

#include "cryptofw/ICsp.hpp"


class Utils {
public:
	// TODO: Make separate class for managing CSPs
	static std::shared_ptr<ICsp> GetCryptoProCsp();
	static std::shared_ptr<ICsp> GetVipNetCsp();

	// TODO: Move to Blob implementation
	static void SaveDataToFile(const Blob& data, const std::string& file_path);
};

// TODO: Move to Blob implementation
std::ostream& operator<<(std::ostream& out, const Blob& blob);
