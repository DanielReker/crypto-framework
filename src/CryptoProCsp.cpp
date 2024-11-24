#include <iostream>

#include "cryptofw/CryptoProCsp.hpp"
#include "cryptofw/CryptoProCertificate.hpp"
#include "cryptofw/utils.hpp"

CryptoProCsp::CryptoProCsp() {
	certificates_.push_back(std::make_shared<CryptoProCertificate>(*this, "Ivanov Ivan Ivanovich"));
	certificates_.push_back(std::make_shared<CryptoProCertificate>(*this, "Petrov Petr Petrovich"));
}

std::vector<std::shared_ptr<ICertificate>> CryptoProCsp::GetCertificates() {
	std::cout << "CryptoPro certificates list is not implemented\n";
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