#include <iostream>

#include "cryptofw/ICsp.hpp"
#include <cryptofw/ICertificate.hpp>
#include <cryptofw/utils.hpp>


int main(int argc, char* argv[]) {
	srand(time(nullptr));
	
	std::cout << "Hello from demo app\n";

	std::shared_ptr<ICsp> csp = GetSomeCSP();

	for (const auto& cert : csp->GetCertificates()) {
		std::cout << cert->GetSubjectName() << '\n';
	}

	auto certificates = csp->GetCertificates();

	const auto& cert = certificates[rand() % certificates.size()];

	const auto& encryptedData = cert->Encrypt({ 0xAA, 0xBB, 0xCC, 0xDD });
	std::cout << "Encrypted data: " << encryptedData << '\n';
	const auto& decryptedData = cert->Decrypt(encryptedData);
	std::cout << "Decrypted data: " << decryptedData << '\n';

	cert->VerifyCades(cert->SignCades({ 0xAA, 0xBB, 0xCC, 0xDD }, CadesType::kBes), CadesType::kBes);
	cert->VerifyXades(cert->SignXades({ 0xAA, 0xBB, 0xCC, 0xDD }, XadesType::kBes), XadesType::kBes);
}