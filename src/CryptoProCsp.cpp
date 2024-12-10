#include <iostream>
#include <cades.h>
#include "CryptoProCsp.hpp"
#include "CryptoProCertificate.hpp"
#include "private_utils.hpp"

CryptoProCsp::CryptoProCsp() {
	auto certs = FindProviderCertificates("Crypto-Pro");
	for (auto context : certs) {
		certificates_.push_back(std::make_shared<CryptoProCertificate>(*this, GetCertificateSubject(context), context));
	}
}

Blob CryptoProCsp::SignCadesBes(PCCERT_CONTEXT context, const Blob& data, bool detached) const {
    CRYPT_SIGN_MESSAGE_PARA sign_para = { sizeof(sign_para) };
    sign_para.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    sign_para.pSigningCert = context;
    sign_para.HashAlgorithm.pszObjId = (LPSTR)GetHashOid(context);

    CADES_SIGN_PARA cades_sign_para = { sizeof(cades_sign_para) };
    cades_sign_para.dwCadesType = CADES_BES;

    CADES_SIGN_MESSAGE_PARA para = { sizeof(para) };
    para.pSignMessagePara = &sign_para;
    para.pCadesSignPara = &cades_sign_para;

    const uint8_t* pb_to_be_signed[] = { &data[0] };
    DWORD cb_to_be_signed[] = { (DWORD)data.size() };

    CERT_CHAIN_PARA chain_para = { sizeof(chain_para) };
    PCCERT_CHAIN_CONTEXT p_chain_context = NULL;

    std::vector<PCCERT_CONTEXT> certs;

    if (CertGetCertificateChain(
        NULL,
        context,
        NULL,
        NULL,
        &chain_para,
        0,
        NULL,
        &p_chain_context
    )) {
        for (DWORD i = 0; i < p_chain_context->rgpChain[0]->cElement - 1; ++i) {
            certs.push_back(p_chain_context->rgpChain[0]->rgpElement[i]->pCertContext);
        }
    }
    if (certs.size() > 0) {
        sign_para.cMsgCert = (DWORD)certs.size();
        sign_para.rgpMsgCert = &certs[0];
    }

    PCRYPT_DATA_BLOB p_signed_message = 0;
    if (!CadesSignMessage(&para, detached, 1, pb_to_be_signed, cb_to_be_signed, &p_signed_message)) {
        throw std::runtime_error("CadesSignMessage() failed");

    }
    if (p_chain_context) {
        CertFreeCertificateChain(p_chain_context);
    }

    Blob message(p_signed_message->cbData);
    copy(p_signed_message->pbData, p_signed_message->pbData + p_signed_message->cbData, message.begin());

    if (!CadesFreeBlob(p_signed_message)) {
        throw std::runtime_error("CadesFreeBlob() failed");
    }
    return message;
}

Blob CryptoProCsp::SignCadesXLong1(PCCERT_CONTEXT context, const Blob& data, bool detached) const {
    CRYPT_SIGN_MESSAGE_PARA sign_param = { sizeof(sign_param) };
    sign_param.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    sign_param.pSigningCert = context;
    sign_param.HashAlgorithm.pszObjId = (LPSTR)GetHashOid(context);

    CADES_SERVICE_CONNECTION_PARA tsp_connection_para = { sizeof(tsp_connection_para) };
    tsp_connection_para.wszUri = SERVICE_URL_2012;

    CADES_SIGN_PARA cades_sign_para = { sizeof(cades_sign_para) };
    cades_sign_para.dwCadesType = CADES_X_LONG_TYPE_1;
    cades_sign_para.pTspConnectionPara = &tsp_connection_para;

    CADES_SIGN_MESSAGE_PARA para = { sizeof(para) };
    para.pSignMessagePara = &sign_param;
    para.pCadesSignPara = &cades_sign_para;

    const uint8_t* pb_to_be_signed[] = { &data[0] };
    DWORD cb_to_be_signed[] = { (DWORD)data.size() };
    PCRYPT_DATA_BLOB p_signed_message = 0;


    if (!CadesSignMessage(&para, detached, 1, pb_to_be_signed, cb_to_be_signed, &p_signed_message)) {
        throw std::runtime_error("CadesSignMessage() failed");
    }

    Blob message(p_signed_message->cbData);
    copy(p_signed_message->pbData, p_signed_message->pbData + p_signed_message->cbData, message.begin());

    if (!CadesFreeBlob(p_signed_message)) {
        throw std::runtime_error("CadesFreeBlob() failed");
    }

    return message;
}

std::vector<std::shared_ptr<ICertificate>> CryptoProCsp::GetCertificates() {
	return { certificates_.begin(), certificates_.end() };
}

Blob CryptoProCsp::EncryptWithCertificate(const Blob& data, const CryptoProCertificate& cert) const {
    return EncryptData(cert.GetCertContext(), data);
}

Blob CryptoProCsp::DecryptWithCertificate(const Blob& encrypted_data, const CryptoProCertificate& cert) const {
    return DecryptData(cert.GetCertContext(), encrypted_data);
}

Blob CryptoProCsp::SignCadesWithCertificate(const Blob& data, CadesType type, const CryptoProCertificate& cert, bool detached) const {
    switch (type) {
    case CadesType::kBes:
        return SignCadesBes(cert.GetCertContext(), data, detached);
    case CadesType::kXLongType1:
        return SignCadesXLong1(cert.GetCertContext(), data, detached);
    default:
        throw std::runtime_error("Invalid type");
    }
}

bool CryptoProCsp::VerifyCadesXLong1Attached(const Blob& signature) const {
    CRYPT_VERIFY_MESSAGE_PARA crypt_verify_params = { sizeof(crypt_verify_params) };
    crypt_verify_params.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFICATION_PARA cades_verify_params = { sizeof(cades_verify_params) };
    cades_verify_params.dwCadesType = CADES_X_LONG_TYPE_1;

    CADES_VERIFY_MESSAGE_PARA verify_params = { sizeof(verify_params) };
    verify_params.pVerifyMessagePara = &crypt_verify_params;
    verify_params.pCadesVerifyPara = &cades_verify_params;

    PCADES_VERIFICATION_INFO p_verify_info_attached = 0;
    PCRYPT_DATA_BLOB p_content = 0;
    if (!CadesVerifyMessage(&verify_params, 0, &signature[0], (unsigned long)signature.size(), &p_content, &p_verify_info_attached)) {
        return false;
    }

    bool result = (p_verify_info_attached->dwStatus == CADES_VERIFY_SUCCESS);
    if (!CadesFreeVerificationInfo(p_verify_info_attached)) {
        throw std::runtime_error("Failed to free verification info");
    }
    if (!CadesFreeBlob(p_content)) {
        throw std::runtime_error("Failed to free blob");
    }
    return result;
}

bool CryptoProCsp::VerifyCadesXLong1Detached(const Blob& signature, const Blob& message) const {
    CRYPT_VERIFY_MESSAGE_PARA crypt_verify_params = { sizeof(crypt_verify_params) };
    crypt_verify_params.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFICATION_PARA cades_verify_params = { sizeof(cades_verify_params) };
    cades_verify_params.dwCadesType = CADES_X_LONG_TYPE_1;

    CADES_VERIFY_MESSAGE_PARA verify_params = { sizeof(verify_params) };
    verify_params.pVerifyMessagePara = &crypt_verify_params;
    verify_params.pCadesVerifyPara = &cades_verify_params;

    const BYTE* message_ptr = &message[0];
    DWORD message_size = (DWORD)message.size();

    PCADES_VERIFICATION_INFO p_verify_info_detached = 0;
    PCRYPT_DATA_BLOB p_content = 0;
    if (!CadesVerifyDetachedMessage(&verify_params, 0, &signature[0], (unsigned long)signature.size(), 1,
        &message_ptr, &message_size, &p_verify_info_detached)) {
        return false;
    }

    bool result = (p_verify_info_detached->dwStatus == CADES_VERIFY_SUCCESS);
    if (!CadesFreeVerificationInfo(p_verify_info_detached)) {
        throw std::runtime_error("Failed to free verification info");
    }
    return result;
}
bool CryptoProCsp::VerifyCadesBesAttached(const Blob& signature) const {
    CRYPT_VERIFY_MESSAGE_PARA crypt_verify_params = { sizeof(crypt_verify_params) };
    crypt_verify_params.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFICATION_PARA cades_verify_params = { sizeof(cades_verify_params) };
    cades_verify_params.dwCadesType = CADES_BES;

    CADES_VERIFY_MESSAGE_PARA verify_para = { sizeof(verify_para) };
    verify_para.pVerifyMessagePara = &crypt_verify_params;
    verify_para.pCadesVerifyPara = &cades_verify_params;

    PCADES_VERIFICATION_INFO p_verify_info_attached = 0;
    PCRYPT_DATA_BLOB p_content = 0;
    if (!CadesVerifyMessage(&verify_para, 0, &signature[0], (unsigned long)signature.size(), &p_content, &p_verify_info_attached)) {
        return false;
    }

    bool result = (p_verify_info_attached->dwStatus == CADES_VERIFY_SUCCESS);
    if (!CadesFreeVerificationInfo(p_verify_info_attached)) {
        CadesFreeBlob(p_content);
    }
    if (!CadesFreeBlob(p_content)) {
        throw std::runtime_error("Fail to free blob");
    }
    return result;
}

bool CryptoProCsp::VerifyCadesBesDetached(const Blob& signature, const Blob& message) const {
    CRYPT_VERIFY_MESSAGE_PARA crypt_verify_params = { sizeof(crypt_verify_params) };
    crypt_verify_params.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFICATION_PARA cades_verify_params = { sizeof(cades_verify_params) };
    cades_verify_params.dwCadesType = CADES_BES;

    CADES_VERIFY_MESSAGE_PARA verify_para = { sizeof(verify_para) };
    verify_para.pVerifyMessagePara = &crypt_verify_params;
    verify_para.pCadesVerifyPara = &cades_verify_params;

    const BYTE* message_ptr = &message[0];
    DWORD message_size = (DWORD)message.size();

    PCADES_VERIFICATION_INFO p_verify_info_detached = 0;
    PCRYPT_DATA_BLOB p_content = 0;
    if (!CadesVerifyDetachedMessage(&verify_para, 0, &signature[0], (unsigned long)signature.size(), 1,
        &message_ptr, &message_size, &p_verify_info_detached)) {
        return false;
    }

    bool result = (p_verify_info_detached->dwStatus == CADES_VERIFY_SUCCESS);
    if (!CadesFreeVerificationInfo(p_verify_info_detached)) {
        throw std::runtime_error("Failed to free verification info");
    }
    return result;
}



bool CryptoProCsp::VerifyCadesAttached(const Blob& signature, CadesType type) const {
    switch (type) {
    case CadesType::kXLongType1:
        return VerifyCadesXLong1Attached(signature);
    case CadesType::kBes:
        return VerifyCadesBesAttached(signature);
    default:
        throw std::runtime_error("Invalid signature type");
    }
}

bool CryptoProCsp::VerifyCadesDetached(const Blob& signature, const Blob& source, CadesType type) const {
    switch (type) {
    case CadesType::kXLongType1:
        return VerifyCadesXLong1Detached(signature, source);
    case CadesType::kBes:
        return VerifyCadesBesDetached(signature, source);
    default:
        throw std::runtime_error("Invalid signature type");
    }
}

Blob CryptoProCsp::SignXadesWithCertificate(const Blob& data, XadesType type, const CryptoProCertificate& cert) const {
    throw std::logic_error("CryptoPro XAdES signing is not implemented yet");
}

bool CryptoProCsp::VerifyXades(const Blob& signature, XadesType type) const {
    throw std::logic_error("CryptoPro XAdES verification is not implemented yet");
}