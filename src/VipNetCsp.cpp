#include <iostream>

#include "VipNetCsp.hpp"
#include "VipNetCertificate.hpp"
#include "private_utils.hpp"

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

bool VipNetCsp::VerifyDetachedSignVipnet(const Blob& signature, const Blob& message) const {
    CRYPT_VERIFY_MESSAGE_PARA verify_params;
    memset(&verify_params, 0, sizeof(verify_params));
    verify_params.cbSize = sizeof(verify_params);
    verify_params.dwMsgAndCertEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

    const BYTE* message_ptr = &message[0];
    DWORD message_size = (DWORD)message.size();
    PCCERT_CONTEXT cert = NULL;

    if (!CryptVerifyDetachedMessageSignature(&verify_params, 0, &signature[0], (DWORD)signature.size(),
        1, &message_ptr, &message_size, &cert)) {
        return false;
    }

    char cert_name[512] = { 0 };
    if (!CertNameToStr(X509_ASN_ENCODING, &cert->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, cert_name,
        sizeof(cert_name))) {
        return false;
    }

    CertFreeCertificateContext(cert);
    return true;
}
bool VipNetCsp::VerifyAttachedSignVipnet(const Blob& signature) const {
    std::vector<BYTE> message;
    CRYPT_VERIFY_MESSAGE_PARA verify_param;
    memset(&verify_param, 0, sizeof(verify_param));
    verify_param.cbSize = sizeof(verify_param);
    verify_param.dwMsgAndCertEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

    DWORD message_size = 0;
    if (!CryptVerifyMessageSignature(&verify_param, 0, &signature[0], (DWORD)signature.size(), NULL, &message_size,
        NULL)) {
        return false;
    }

    PCCERT_CONTEXT cert = NULL;
    message.resize(message_size);
    if (!CryptVerifyMessageSignature(&verify_param, 0, &signature[0], (DWORD)signature.size(), &message[0],
        &message_size, &cert)) {
        return false;
    }

    char cert_name[512] = { 0 };
    if (!CertNameToStr(X509_ASN_ENCODING, &cert->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, cert_name,
        sizeof(cert_name))) {
        return false;
    }

    CertFreeCertificateContext(cert);

    return true;
}
bool VipNetCsp::VerifyCadesAttached(const Blob& signature, CadesType type) const {
    if (type != CadesType::kBes) {
        throw std::logic_error("VipNet CSP only supports CAdES BES signatures");
    }
    else return VerifyAttachedSignVipnet(signature);
}

bool VipNetCsp::VerifyCadesDetached(const Blob& signature, const Blob& source, CadesType type) const {
    if (type != CadesType::kBes) {
        throw std::logic_error("VipNet CSP only supports CAdES BES signatures");
    }
    else return VerifyDetachedSignVipnet(signature, source);
}
