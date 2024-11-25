#include <iostream>
#include <cades.h>
#include "cryptofw/CryptoProCsp.hpp"
#include "cryptofw/CryptoProCertificate.hpp"
#include "cryptofw/utils.hpp"

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

bool CryptoProCsp::VerifyCades(const Blob& signature, CadesType type) const {
	std::cout << "CryptoPro CAdES verification is not implemented\n";
	return false;
}

Blob CryptoProCsp::SignXadesWithCertificate(const Blob& data, XadesType type, const CryptoProCertificate& cert) const {
	std::cout << "CryptoPro XAdES signing is not implemented\n";
	std::cout << "Certificate subject: " << cert.GetSubjectName() << '\n';
	std::cout << "Data: " << data << '\n';
	return { 0x11, 0x22, 0x33 };
}

bool CryptoProCsp::VerifyXades(const Blob& signature, XadesType type) const {
	std::cout << "CryptoPro XAdES verification is not implemented\n";
	return false;
}