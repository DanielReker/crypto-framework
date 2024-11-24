#include <memory>

#include <cryptofw/utils.hpp>
#include <cryptofw/CryptoProCsp.hpp>
#include <cryptofw/VipNetCsp.hpp>

std::ostream& operator<<(std::ostream& out, const Blob& blob) {
	for (auto byte : blob) {
		out << std::hex << static_cast<int>(byte);
	}
	return out;
}

std::shared_ptr<ICsp> GetSomeCSP() {
	srand(time(nullptr));
	if (rand() % 2 == 0) return std::make_shared<CryptoProCsp>();
	else return std::make_shared<VipNetCsp>();
}
