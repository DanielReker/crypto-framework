#include <iostream>

#include "cryptofw/ICsp.hpp"
#include <cryptofw/ICertificate.hpp>
#include <cryptofw/utils.hpp>
#include <cryptofw/CryptoProCsp.hpp>
#include <cryptofw/VipnetCsp.hpp>
#include <cryptofw/CryptoProCertificate.hpp>

int main(int argc, char* argv[]) {
	srand(time(nullptr));
	setlocale(LC_ALL, "rus");
	
	std::cout << "Hello from demo app\n";

	std::shared_ptr<VipNetCsp> csp1 = std::make_shared<VipNetCsp>();
	for (const auto& cert : csp1->GetCertificates()) {
		std::cout << "Vipnet certificate, subject: " << cert->GetSubjectName() << '\n';
	}

	std::shared_ptr<CryptoProCsp> csp2 = std::make_shared<CryptoProCsp>();
	for (const auto& cert : csp2->GetCertificates()) {
		std::cout << "CryptoPro certificate, subject: " << cert->GetSubjectName() << '\n';
	}
	std::cout << "END!";
	return 0;
	//auto certificates = csp->GetCertificates();

	//const auto& cert = certificates[rand() % certificates.size()];

	//const auto& encryptedData = cert->Encrypt({ 0xAA, 0xBB, 0xCC, 0xDD });
	//std::cout << "Encrypted data: " << encryptedData << '\n';
	//const auto& decryptedData = cert->Decrypt(encryptedData);
	//std::cout << "Decrypted data: " << decryptedData << '\n';

	//cert->VerifyCades(cert->SignCades({ 0xAA, 0xBB, 0xCC, 0xDD }, CadesType::kBes), CadesType::kBes);
	//cert->VerifyXades(cert->SignXades({ 0xAA, 0xBB, 0xCC, 0xDD }, XadesType::kBes), XadesType::kBes);
}