#pragma warning(disable:4996)

#include "cryptofw/TestClass.hpp"


#include <iterator>
#include <vector>
#include <iostream>
#include <wchar.h>
#include <cstdlib>

#include <tchar.h>

#include "cades.h"

using namespace std;

#define SERVICE_URL_2001 L"http://pki.tax.gov.ru/tsp/tsp.srf"
#define SERVICE_URL_2012 L"http://pki.tax.gov.ru/tsp/tsp.srf"

PCCERT_CONTEXT GetRecipientCert(HCERTSTORE hCertStore, wchar_t* pSubject) {
    wchar_t* subject(pSubject);
    PCCERT_CONTEXT pCertContext(0);
    DWORD dwSize(0);
    CRYPT_KEY_PROV_INFO* pKeyInfo(0);

    int mustFree;
    DWORD dwKeySpec = 0;
    HCRYPTPROV hProv;

    for (;;) {
        if (subject) {
            pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_STR_W, subject, pCertContext);
            if (pCertContext)
                return pCertContext;
        }
        else {
            pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_ANY, 0, pCertContext);
        }

        if (pCertContext) {
            if (!CryptAcquireCertificatePrivateKey(pCertContext, 0, 0, &hProv, &dwKeySpec, &mustFree)) {
                if (mustFree)
                    CryptReleaseContext(hProv, 0);
                continue;
            }

            if (!(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &dwSize))) {
                cout << "Certificate property was not got" << endl;
                return 0;
            }

            if (pKeyInfo)
                free(pKeyInfo);

            pKeyInfo = (CRYPT_KEY_PROV_INFO*)malloc(dwSize);

            if (!pKeyInfo) {
                cout << "Error occured during the time of memory allocating" << endl;
                return 0;
            }

            if (!(CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pKeyInfo, &dwSize))) {
                free(pKeyInfo);
                cout << "Certificate property was not got" << endl;
                return 0;
            }

            if (mustFree)
                CryptReleaseContext(hProv, 0);
            free(pKeyInfo);
            return pCertContext;

        }
        else {
            cout << "Certificate with private key was not found" << endl;
            return 0;
        }
    }
}

template<typename T>
int SaveVectorToFile(const char* filename, vector<T>& buffer) {
    if (buffer.empty()) {
        cout << "There is nothing to save" << endl;
        return -1;
    }

    FILE* f = fopen(filename, "wb");
    if (!f) {
        cout << "Opening file " << filename << " failed" << endl;
        return -1;
    }

    size_t count = fwrite(&buffer[0], sizeof(T), buffer.size(), f);
    fclose(f);
    if (count != buffer.size()) {
        cout << "Error occured during saving to file " << filename << endl;
        return -1;
    }
    return 0;
}

int ReadFileToVector(const char* filename, vector<unsigned char>& buffer) {
    enum {
        bytesSize = 512
    };

    unsigned long bytesRead(1);
    char buf[bytesSize];

    FILE* f = fopen(filename, "r+b");

    if (!f) {
        cout << "Opening file " << filename << " failed" << endl;
        return -1;
    }

    while (!feof(f)) {
        bytesRead = (unsigned long)fread(buf, 1, bytesSize, f);

        if (bytesSize != bytesRead && ferror(f)) {
            fclose(f);
            return -1;
        }
        std::copy(buf, buf + bytesRead, std::back_inserter(buffer));
    }
    fclose(f);

    return 0;
}

const char* GetHashOid(PCCERT_CONTEXT pCert) {
    const char* pKeyAlg = pCert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    if (strcmp(pKeyAlg, szOID_CP_GOST_R3410EL) == 0)
    {
        return szOID_CP_GOST_R3411;
    }
    else if (strcmp(pKeyAlg, szOID_CP_GOST_R3410_12_256) == 0)
    {
        return szOID_CP_GOST_R3411_12_256;
    }
    else if (strcmp(pKeyAlg, szOID_CP_GOST_R3410_12_512) == 0)
    {
        return szOID_CP_GOST_R3411_12_512;
    }
    return NULL;
}

int TestClass::helloCryptoPro(int argc, char *argv[], const std::string& test_message) {
    std::cout << "Hello from CryptoFramework: " << test_message << '\n';

    HCERTSTORE hStoreHandle = CertOpenSystemStore(0, _TEXT("MY"));

    if (!hStoreHandle) {
        cout << "Store handle was not got" << endl;
        return -1;
    }

    wchar_t *wa = NULL;
    if (argc > 1) {
        size_t len = strlen(argv[1]) + 1;
        wa = new wchar_t[len];
        mbstowcs(wa, argv[1], len);
    }

    PCCERT_CONTEXT context = GetRecipientCert(hStoreHandle, wa);
    if (wa) delete[] wa;

    if (!context) {
        cout << "There is no certificate with a CERT_KEY_CONTEXT_PROP_ID " << endl
             << "property and an AT_KEYEXCHANGE private key available." << endl
             << "While the message could be sign, in this case, it could" << endl
             << "not be verify in this program." << endl
             << "For more information, read the documentation http://cpdn.cryptopro.ru/" << endl;
        return -1;
    }

    CRYPT_SIGN_MESSAGE_PARA signPara = {sizeof(signPara)};
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = context;
    signPara.HashAlgorithm.pszObjId = (LPSTR) GetHashOid(context);

    CADES_SIGN_PARA cadesSignPara = {sizeof(cadesSignPara)};
    cadesSignPara.dwCadesType = CADES_BES;

    CADES_SIGN_MESSAGE_PARA para = {sizeof(para)};
    para.pSignMessagePara = &signPara;
    para.pCadesSignPara = &cadesSignPara;

    vector<unsigned char> data(10, 25);
    const unsigned char *pbToBeSigned[] = {&data[0]};
    DWORD cbToBeSigned[] = {(DWORD) data.size()};


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

	for (DWORD i = 0; i < pChainContext->rgpChain[0]->cElement-1; ++i)
	{
	    certs.push_back(pChainContext->rgpChain[0]->rgpElement[i]->pCertContext);
	}
    }
    if (certs.size() > 0)
    {
	signPara.cMsgCert = (DWORD)certs.size();
	signPara.rgpMsgCert = &certs[0];
    }


    PCRYPT_DATA_BLOB pSignedMessage = 0;
    if (!CadesSignMessage(&para, 0, 1, pbToBeSigned, cbToBeSigned, &pSignedMessage)) {
        cout << "CadesSignMessage() failed" << endl;
        return -1;
    }
    if (pChainContext)
	CertFreeCertificateChain(pChainContext);

    vector<unsigned char> message(pSignedMessage->cbData);
    copy(pSignedMessage->pbData, pSignedMessage->pbData + pSignedMessage->cbData, message.begin());

    if (SaveVectorToFile<unsigned char>("sign.dat", message)) {
        cout << "Signature was not saved" << endl;
        return -1;
    }

    cout << "Signature was saved successfully" << endl;

    if (!CadesFreeBlob(pSignedMessage)) {
        cout << "CadesFreeBlob() failed" << endl;
        return -1;
    }

    if (!CertCloseStore(hStoreHandle, 0)) {
        cout << "Certificate store handle was not closed." << endl;
        return -1;
    }

    if (context)
        CertFreeCertificateContext(context);

    return 0;
}   
