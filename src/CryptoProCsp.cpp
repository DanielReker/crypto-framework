#include <iostream>

#include "cryptofw/CryptoProCsp.hpp"
#include "cryptofw/CryptoProCertificate.hpp"
#include "cryptofw/utils.hpp"

CryptoProCsp::CryptoProCsp() {
	auto certs = FindProviderCertificates("Crypto-Pro");
	for (auto context : certs) {
		certificates_.push_back(std::make_shared<CryptoProCertificate>(*this, GetCertificateSubject(context), context));
	}
}

std::vector<std::shared_ptr<ICertificate>> CryptoProCsp::GetCertificates() {
	return { certificates_.begin(), certificates_.end() };
}

Blob CryptoProCsp::EncryptWithCertificate(const Blob& data, const CryptoProCertificate& cert) const {
	std::cout << "CryptoPro encryption is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Data: " << data << '\n';
	return { 0x11, 0x22, 0x33 };
}

Blob CryptoProCsp::DecryptWithCertificate(const Blob& encrypted_data, const CryptoProCertificate& cert) const {
	std::cout << "CryptoPro decryption is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Encrypted data: " << encrypted_data << '\n';
	return { 0x11, 0x22, 0x33 };
}

Blob CryptoProCsp::SignCadesWithCertificate(const Blob& data, CadesType type, const CryptoProCertificate& cert) const {
	std::cout << "CryptoPro CAdES signing is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Data: " << data << '\n';
	return { 0x11, 0x22, 0x33 };
}

bool CryptoProCsp::VerifyCadesWithCertificate(const Blob& signature, CadesType type, const CryptoProCertificate& cert) const {
	std::cout << "CryptoPro CAdES verification is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Signature: " << signature << '\n';
	return false;
}

Blob CryptoProCsp::SignXadesWithCertificate(const Blob& data, XadesType type, const CryptoProCertificate& cert) const {
	std::cout << "CryptoPro XAdES signing is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Data: " << data << '\n';
	return { 0x11, 0x22, 0x33 };
}

bool CryptoProCsp::VerifyXadesWithCertificate(const Blob& signature, XadesType type, const CryptoProCertificate& cert) const {
	std::cout << "CryptoPro XAdES verification is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Signature: " << signature << '\n';
	return false;
}