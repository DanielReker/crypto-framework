#include <iostream>

#include "cryptofw/VipNetCsp.hpp"
#include "cryptofw/VipNetCertificate.hpp"
#include "cryptofw/utils.hpp"

VipNetCsp::VipNetCsp() {
	auto certs = FindProviderCertificates("Infotecs");
	for (auto context : certs) {
		certificates_.push_back(std::make_shared<VipNetCertificate>(*this, GetCertificateSubject(context), context));
	}
}

std::vector<std::shared_ptr<ICertificate>> VipNetCsp::GetCertificates() {
	return { certificates_.begin(), certificates_.end() };
}

Blob VipNetCsp::SignCadesBes(PCCERT_CONTEXT cert, bool detached, const Blob& data) const {
    if (!cert) {
        throw "Invalid parameter: cert is null.";
    }

    CRYPT_SIGN_MESSAGE_PARA sign_param;
    memset(&sign_param, 0, sizeof(sign_param));
    sign_param.cbSize = sizeof(sign_param);
    sign_param.dwMsgEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
    sign_param.pSigningCert = cert;
    sign_param.HashAlgorithm.pszObjId = const_cast<LPSTR>(GetHashOid(cert));
    sign_param.cMsgCert = 1;
    sign_param.rgpMsgCert = &cert;

    FILETIME ts;
    GetSystemTimeAsFileTime(&ts);

    DWORD tsLen = 0;
    if (!CryptEncodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, szOID_RSA_signingTime, &ts, NULL, &tsLen)) {
        throw "First CryptEncodeObject() call failed.";
    }

    std::vector<uint8_t> tsBuf(tsLen);
    if (!CryptEncodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, szOID_RSA_signingTime, &ts, tsBuf.data(), &tsLen)) {
        throw "Second CryptEncodeObject() call failed.";
    }

    CRYPT_ATTR_BLOB tsBlob = { tsLen, tsBuf.data() };
    CRYPT_ATTRIBUTE tsAttr = { const_cast<LPSTR>(szOID_RSA_signingTime), 1, &tsBlob };
    sign_param.cAuthAttr = 1;
    sign_param.rgAuthAttr = &tsAttr;

    const BYTE* messagePtr = data.data();
    DWORD messageSize = static_cast<DWORD>(data.size());
    DWORD signSize = 0;

    if (!CryptSignMessage(&sign_param, detached, 1, &messagePtr, &messageSize, NULL, &signSize)) {
        throw "First CryptSignMessage() failed.";
    }

    std::vector<uint8_t> signature(signSize);

    if (!CryptSignMessage(&sign_param, detached, 1, &messagePtr, &messageSize, signature.data(), &signSize)) {
        throw "Second CryptSignMessage() failed.";
    }

    return signature;
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

Blob VipNetCsp::SignCadesWithCertificate(const Blob& data, CadesType type, const VipNetCertificate& cert, bool detached) const {
    switch (type) {
    case CadesType::kBes:
        return SignCadesBes(cert.GetCertContext(), detached, data);
    default:
        throw std::logic_error("Only CAdES BES is supported by ViPNet CSP");
    }
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