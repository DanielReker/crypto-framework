#include "cryptofw/CryptoFramework.hpp"

#include "CryptoProCsp.hpp"
#include "VipNetCsp.hpp"


#include <stdexcept>


bool CryptoFramework::IsCspAvailable(CspType csp) {
	return !!GetCspInstance(csp);
}

std::shared_ptr<ICsp> CryptoFramework::GetCspInstance(CspType csp) {
	std::shared_ptr<ICsp> result;
	std::string printable_csp_name;

	switch (csp) {

	case CspType::kCryptoProCsp:
		result = CryptoProCsp::GetInstance();
		printable_csp_name = "CryptoPro CSP";
		break;

	case CspType::kVipNetCsp:
		result = VipNetCsp::GetInstance();
		printable_csp_name = "ViPNet CSP";
		break;

	}

	if (!result)
		throw std::runtime_error(printable_csp_name + " is not available");
	
	return result;
}
