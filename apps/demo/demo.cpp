#include <iostream>
#include <filesystem>

#include <cryptofw/CryptoFramework.hpp>
#include <cryptofw/ICsp.hpp>
#include <cryptofw/ICertificate.hpp>
#include <cryptofw/Blob.hpp>
#include <cryptofw/Utils.hpp>
#include <cryptofw/CspType.hpp>


void DemonstrateCsp(CspType csp_type, const std::string& name) {
	std::cout << "\n\n";

	// Get CSP instance
	std::shared_ptr<ICsp> csp;
	try {
		csp = CryptoFramework::GetCspInstance(csp_type);
	}
	catch (const std::exception& e) {
		// Selected CSP is not available
		std::cout << e.what() << '\n';
		return;
	}

	std::cout << "Demonstrating " << name << ":\n\n";

	// Get available certificates of seleted CSP
	const auto& certs = csp->GetCertificates();

	if (certs.size() == 0) {
		std::cout << "No " << name << " certificates found\n";
		return;
	}

	std::cout << certs.size() << " certificates of " << name << " available:\n";
	for (int i = 0; i < certs.size(); i++) {
		const auto& cert = certs[i];
		std::cout << "  - Certificate #" << i + 1 << ", subject: " << cert->GetSubjectName() << '\n';
	}
	

	// Select one of available certificates randomly
	int cert_number = rand() % certs.size();
	const auto& cert = certs[cert_number];
	std::cout << "\nRandomly selected certificate #" << cert_number + 1 << " to work with\n";

	// Prepare data to work with
	std::filesystem::create_directory(name);
	Blob file;
	try {
		file = Utils::ReadDataFromFile(name + "/hello.txt");
	}
	catch (const std::exception& e) {
		std::cout << e.what() << ", setting default data\n";
		file = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
		Utils::SaveDataToFile(file, name + "/hello.txt");
	}
	std::cout << "\nFile data: " << file << '\n';

	// Encryption/decryption
	try {
		std::cout << "\nEncrypting data...\n";
		const auto& encrypted = cert->Encrypt(file);
		Utils::SaveDataToFile(encrypted, name + "/encrypted.p7e");
		std::cout << "Encrypted data size: " << std::dec << encrypted.size() << '\n';

		std::cout << "\nDecrypting data...\n";
		const auto& decrypted = cert->Decrypt(encrypted);
		Utils::SaveDataToFile(decrypted, name + "/decrypted.dat");
		std::cout << "Decrypted data: " << decrypted << '\n';
	}
	catch (const std::exception& e) {
		std::cout << "Exception during work with encryption/decryption: " << e.what() << '\n';
	}

	// CAdES-BES
	try {
		std::cout << "\nCreating detached CAdES-BES signature...\n";
		const auto& cades_bes_detached = cert->SignCades(file, CadesType::kBes, true);
		Utils::SaveDataToFile(cades_bes_detached, name + "/cadesBesDetached.p7s");

		std::cout << "\nVerifying detached CAdES-BES signature...\n";
		if (csp->VerifyCadesDetached(cades_bes_detached, file, CadesType::kBes)) {
			std::cout << "Detached CAdES-BES signature is VALID" << '\n';
		}
		else {
			std::cout << "Detached CAdES-BES signature is INVALID" << '\n';
		}

		std::cout << "\nCreating attached CAdES-BES signature...\n";
		const auto& cades_bes_attached = cert->SignCades(file, CadesType::kBes, false);
		Utils::SaveDataToFile(cades_bes_attached, name + "/cadesBesAttached.p7s");

		std::cout << "\nVerifying attached CAdES-BES signature...\n";
		if (csp->VerifyCadesAttached(cades_bes_attached, CadesType::kBes)) {
			std::cout << "Attached CAdES-BES signature is VALID" << '\n';
		}
		else {
			std::cout << "Attached CAdES-BES signature is INVALID" << '\n';
		}
	}
	catch (const std::exception& e) {
		std::cout << "Exception during work with CAdES-BES: " << e.what() << '\n';
	}

	// CAdES-X Long Type 1

	// TSP (Time Stamp Protocol) server
	std::wstring tsp_server_url = L"http://pki.tax.gov.ru/tsp/tsp.srf";

	try {
		std::cout << "\nCreating detached CAdES-X Long Type 1 signature...\n";
		const auto& cades_xl_detached = cert->SignCades(file, CadesType::kXLongType1, true, tsp_server_url);
		Utils::SaveDataToFile(cades_xl_detached, name + "/cadesXlDetached.p7s");

		std::cout << "\nVerifying detached CAdES-X Long Type 1 signature...\n";
		if (csp->VerifyCadesDetached(cades_xl_detached, file, CadesType::kXLongType1)) {
			std::cout << "Detached CAdES-X Long Type 1 signature is VALID" << '\n';
		}
		else {
			std::cout << "Detached CAdES-X Long Type 1 signature is INVALID" << '\n';
		}

		std::cout << "\nCreating attached CAdES-X Long Type 1 signature...\n";
		const auto& cades_xl_attached = cert->SignCades(file, CadesType::kXLongType1, false, tsp_server_url);
		Utils::SaveDataToFile(cades_xl_attached, name + "/cadesXlAttached.p7s");

		std::cout << "\nVerifying attached CAdES-X Long Type 1 signature...\n";
		if (csp->VerifyCadesAttached(cades_xl_attached, CadesType::kXLongType1)) {
			std::cout << "Attached CAdES-X Long Type 1 signature is VALID" << '\n';
		}
		else {
			std::cout << "Attached CAdES-X Long Type 1 signature is INVALID" << '\n';
		}
	}
	catch (const std::exception& e) {
		std::cout << "Exception during working CAdES-X Long Type 1: " << e.what() << '\n';
	}
}


int main(int argc, char* argv[]) {
	srand(time(nullptr));
	setlocale(LC_ALL, "rus");
	
	std::cout << "Hello from CryptoFramework demo app!\n";

	DemonstrateCsp(CspType::kCryptoProCsp, "CryptoPro_CSP");
	DemonstrateCsp(CspType::kVipNetCsp, "ViPNet_CSP");
}