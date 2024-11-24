#include <memory>

#include <cryptofw/utils.hpp>
#include <cryptofw/CryptoProCsp.hpp>

std::ostream& operator<<(std::ostream& out, const Blob& blob) {
	for (auto byte : blob) {
		out << std::hex << static_cast<int>(byte);
	}
	return out;
}

std::shared_ptr<ICsp> GetSomeCSP() {
	return std::make_shared<CryptoProCsp>();
}
