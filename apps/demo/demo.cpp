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
	std::shared_ptr<ICsp> csp = csp1;

	for (const auto& cert : csp->GetCertificates()) {
		std::cout << "Имя субъекта сертифката: " <<cert->GetSubjectName() << '\n';
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