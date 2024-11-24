#include <iostream>

#include "cryptofw/VipNetCsp.hpp"
#include "cryptofw/VipNetCertificate.hpp"
#include "cryptofw/utils.hpp"

VipNetCsp::VipNetCsp() {
	//certificates_.push_back(std::make_shared<VipNetCertificate>(*this, "Vasiliev Vasiliy Vasilievich"));
	//certificates_.push_back(std::make_shared<VipNetCertificate>(*this, "Sidorov Sidor Sidorovich"));
	//certificates_.push_back(std::make_shared<VipNetCertificate>(*this, "Nikolaev Nikolay Nikolaevich"));
}

std::vector<std::shared_ptr<ICertificate>> VipNetCsp::GetCertificates() {
	auto certificatesContextList = FindProviderCertificates("Infotecs");
	for (auto context : certificatesContextList) {
		std::string name = GetCertificateSubject(context);
		certificates_.push_back(std::make_shared<VipNetCertificate>(*this, GetCertificateSubject(context)));
	}
	return { certificates_.begin(), certificates_.end() };
}

Blob VipNetCsp::EncryptWithCertificate(const Blob& data, const VipNetCertificate& cert) const {
	std::cout << "VipNet encryption is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Data: " << data << '\n';
	return { 0x11, 0x22, 0x33 };
}

Blob VipNetCsp::DecryptWithCertificate(const Blob& encrypted_data, const VipNetCertificate& cert) const {
	std::cout << "VipNet decryption is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Encrypted data: " << encrypted_data << '\n';
	return { 0x11, 0x22, 0x33 };
}

Blob VipNetCsp::SignCadesWithCertificate(const Blob& data, CadesType type, const VipNetCertificate& cert) const {
	std::cout << "VipNet CAdES signing is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Data: " << data << '\n';
	return { 0x11, 0x22, 0x33 };
}

bool VipNetCsp::VerifyCadesWithCertificate(const Blob& signature, CadesType type, const VipNetCertificate& cert) const {
	std::cout << "VipNet CAdES verification is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Signature: " << signature << '\n';
	return false;
}

Blob VipNetCsp::SignXadesWithCertificate(const Blob& data, XadesType type, const VipNetCertificate& cert) const {
	std::cout << "VipNet XAdES signing is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Data: " << data << '\n';
	return { 0x11, 0x22, 0x33 };
}

bool VipNetCsp::VerifyXadesWithCertificate(const Blob& signature, XadesType type, const VipNetCertificate& cert) const {
	std::cout << "VipNet XAdES verification is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Signature: " << signature << '\n';
	return false;
}