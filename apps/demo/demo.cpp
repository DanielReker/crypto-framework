#include <iostream>
#include <filesystem>

#include "cryptofw/ICsp.hpp"
#include "cryptofw/ICertificate.hpp"
#include "cryptofw/Blob.hpp"
#include <cryptofw/utils.hpp>


void DemonstrateCsp(std::shared_ptr<ICsp> csp, const std::string& name) {
	try {
		std::cout << "Demonstrating " << name << ":\n";

		for (const auto& cert : csp->GetCertificates()) {
			std::cout << name << " certificate, subject: " << cert->GetSubjectName() << '\n';
		}

		std::filesystem::create_directory(name);
		Blob file = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
		SaveDataToFile(file, name + "/file.dat");
		std::cout << "File: " << file << '\n';

		const auto& certs = csp->GetCertificates();
		if (certs.size() == 0) {
			std::cout << "No " << name << " certificates found\n";
			return;
		}

		const auto& cert = certs[0];

		const auto& cades_bes_detached = cert->SignCades(file, CadesType::kBes, true);
		SaveDataToFile(cades_bes_detached, name + "/cadesBesDetached.p7s");
		std::cout << (csp->VerifyCades(cades_bes_detached, CadesType::kBes) ? "Valid" : "Invalid") << '\n';

		const auto& cades_bes_attached = cert->SignCades(file, CadesType::kBes, false);
		SaveDataToFile(cades_bes_attached, name + "/cadesBesAttached.p7s");
		std::cout << (csp->VerifyCades(cades_bes_attached, CadesType::kBes) ? "Valid" : "Invalid") << '\n';

		const auto& cades_xl_detached = cert->SignCades(file, CadesType::kXLongType1, true);
		SaveDataToFile(cades_xl_detached, name + "/cadesXlDetached.p7s");
		std::cout << (csp->VerifyCades(cades_xl_detached, CadesType::kXLongType1) ? "Valid" : "Invalid") << '\n';

		const auto& cades_xl_attached = cert->SignCades(file, CadesType::kXLongType1, false);
		SaveDataToFile(cades_xl_attached, name + "/cadesXlAttached.p7s");
		std::cout << (csp->VerifyCades(cades_xl_attached, CadesType::kXLongType1) ? "Valid" : "Invalid") << '\n';

		const auto& encrypted = cert->Encrypt(file);
		SaveDataToFile(encrypted, name + "/encrypted.p7e");

		const auto& decrypted = cert->Decrypt(encrypted);
		SaveDataToFile(decrypted, name + "/decrypted.dat");
		std::cout << "Decrypted: " << file << '\n';


		SaveDataToFile(cert->SignXades(file, XadesType::kBes), name + "/xadesBes.p7s");
	}
	catch (const std::exception& e) {
		std::cout << "Exception during demonstration of " << name << ": " << e.what() << '\n';
	}
}


int main(int argc, char* argv[]) {
	srand(time(nullptr));
	setlocale(LC_ALL, "rus");
	
	std::cout << "Hello from CryptoFramework demo app!\n";

	DemonstrateCsp(GetCryptoProCsp(), "CryptoPro");
	DemonstrateCsp(GetVipNetCsp(), "VipNet");
}