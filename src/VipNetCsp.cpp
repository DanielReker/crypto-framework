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
        throw std::runtime_error("Invalid parameter: cert is null.");
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

    DWORD ts_len = 0;
    if (!CryptEncodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, szOID_RSA_signingTime, &ts, NULL, &ts_len)) {
        throw std::runtime_error("First CryptEncodeObject() call failed.");
    }

    std::vector<uint8_t> ts_buf(ts_len);
    if (!CryptEncodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, szOID_RSA_signingTime, &ts, ts_buf.data(), &ts_len)) {
        throw std::runtime_error("Second CryptEncodeObject() call failed.");
    }

    CRYPT_ATTR_BLOB ts_blob = { ts_len, ts_buf.data() };
    CRYPT_ATTRIBUTE ts_attr = { const_cast<LPSTR>(szOID_RSA_signingTime), 1, &ts_blob };
    sign_param.cAuthAttr = 1;
    sign_param.rgAuthAttr = &ts_attr;

    const BYTE* message_ptr = data.data();
    DWORD message_size = static_cast<DWORD>(data.size());
    DWORD sign_size = 0;

    if (!CryptSignMessage(&sign_param, detached, 1, &message_ptr, &message_size, NULL, &sign_size)) {
        throw std::runtime_error("First CryptSignMessage() failed.");
    }

    std::vector<uint8_t> signature(sign_size);

    if (!CryptSignMessage(&sign_param, detached, 1, &message_ptr, &message_size, signature.data(), &sign_size)) {
        throw std::runtime_error("Second CryptSignMessage() failed.");
    }

    return signature;
}

Blob VipNetCsp::EncryptWithCertificate(const Blob& data, const VipNetCertificate& cert) const {
    return EncryptData(cert.GetCertContext(), data);
}

Blob VipNetCsp::DecryptWithCertificate(const Blob& encrypted_data, const VipNetCertificate& cert) const {
    return DecryptData(cert.GetCertContext(), encrypted_data);
}

Blob VipNetCsp::SignCadesWithCertificate(const Blob& data, CadesType type, const VipNetCertificate& cert, bool detached) const {
    switch (type) {
    case CadesType::kBes:
        return SignCadesBes(cert.GetCertContext(), detached, data);
    default:
        throw std::logic_error("Only CAdES BES is supported by ViPNet CSP");
    }
}

bool VipNetCsp::VerifyCades(const Blob& signature, CadesType type) const {
	std::cout << "VipNet CAdES verification is not implemented\n";
	return false;
}

Blob VipNetCsp::SignXadesWithCertificate(const Blob& data, XadesType type, const VipNetCertificate& cert) const {
	std::cout << "VipNet XAdES signing is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Data: " << data << '\n';
	return { 0x11, 0x22, 0x33 };
}

bool VipNetCsp::VerifyXades(const Blob& signature, XadesType type) const {
	std::cout << "VipNet XAdES verification is not implemented\n";
	return false;
}