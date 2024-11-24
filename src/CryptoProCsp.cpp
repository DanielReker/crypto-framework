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

    const uint8_t* pbToBeSigned[] = { &data[0] };
    DWORD cbToBeSigned[] = { (DWORD)data.size() };

    CERT_CHAIN_PARA		ChainPara = { sizeof(ChainPara) };
    PCCERT_CHAIN_CONTEXT	pChainContext = NULL;

    std::vector<PCCERT_CONTEXT> certs;

    if (CertGetCertificateChain(
        NULL,
        context,
        NULL,
        NULL,
        &ChainPara,
        0,
        NULL,
        &pChainContext)) {

        for (DWORD i = 0; i < pChainContext->rgpChain[0]->cElement - 1; ++i)
        {
            certs.push_back(pChainContext->rgpChain[0]->rgpElement[i]->pCertContext);
        }
    }
    if (certs.size() > 0)
    {
        sign_para.cMsgCert = (DWORD)certs.size();
        sign_para.rgpMsgCert = &certs[0];
    }

    PCRYPT_DATA_BLOB pSignedMessage = 0;
    if (!CadesSignMessage(&para, detached, 1, pbToBeSigned, cbToBeSigned, &pSignedMessage)) {
        throw std::runtime_error("CadesSignMessage() failed");

    }
    if (pChainContext)
        CertFreeCertificateChain(pChainContext);

    Blob message(pSignedMessage->cbData);
    copy(pSignedMessage->pbData, pSignedMessage->pbData + pSignedMessage->cbData, message.begin());

    if (!CadesFreeBlob(pSignedMessage)) {
        throw std::runtime_error("CadesFreeBlob() failed");
    }
    return message;
}


Blob CryptoProCsp::SignCadesXLong1(PCCERT_CONTEXT context, const Blob& data, bool detached) const {
    CRYPT_SIGN_MESSAGE_PARA signPara = { sizeof(signPara) };
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = context;
    signPara.HashAlgorithm.pszObjId = (LPSTR)GetHashOid(context);

    CADES_SERVICE_CONNECTION_PARA tspConnectionPara = { sizeof(tspConnectionPara) };
    tspConnectionPara.wszUri = SERVICE_URL_2012;

    CADES_SIGN_PARA cadesSignPara = { sizeof(cadesSignPara) };
    cadesSignPara.dwCadesType = CADES_X_LONG_TYPE_1;
    cadesSignPara.pTspConnectionPara = &tspConnectionPara;

    CADES_SIGN_MESSAGE_PARA para = { sizeof(para) };
    para.pSignMessagePara = &signPara;
    para.pCadesSignPara = &cadesSignPara;

    const uint8_t* pbToBeSigned[] = { &data[0] };
    DWORD cbToBeSigned[] = { (DWORD)data.size() };
    PCRYPT_DATA_BLOB pSignedMessage = 0;


    if (!CadesSignMessage(&para, detached, 1, pbToBeSigned, cbToBeSigned, &pSignedMessage)) {
        throw std::runtime_error("CadesSignMessage() failed");
    }

    Blob message(pSignedMessage->cbData);
    copy(pSignedMessage->pbData, pSignedMessage->pbData + pSignedMessage->cbData, message.begin());

    if (!CadesFreeBlob(pSignedMessage)) {
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
    switch (type)
    {
    case CadesType::kBes:
        return SignCadesBes(cert.GetCertContext(), data, detached);
    case CadesType::kXLongType1:
        return SignCadesXLong1(cert.GetCertContext(), data, detached);
    default:
        return { 0x11, 0x22, 0x33 };
    }
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