#include <memory>
#include <string>
#include <vector>
#include <iostream>
#include <functional>

#include <cryptofw/utils.hpp>
#include <cryptofw/CryptoProCsp.hpp>
#include <cryptofw/VipNetCsp.hpp>
#include <windows.h>
#include <wincrypt.h>

#include <cades.h>


std::ostream& operator<<(std::ostream& out, const Blob& blob) {
	for (auto byte : blob) {
		out << std::hex << static_cast<int>(byte);
	}
	return out;
}

std::shared_ptr<ICsp> GetCryptoProCsp() {
    return std::make_shared<CryptoProCsp>();
}

std::shared_ptr<ICsp> GetVipNetCsp() {
    return std::make_shared<VipNetCsp>();
}

bool IsProviderCertificate(PCCERT_CONTEXT p_cert_context, const std::string& target_provider) {
    DWORD dw_prov_name_size = 0;
    if (!CertGetCertificateContextProperty(p_cert_context, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dw_prov_name_size)) {
        return false;
    }

    CRYPT_KEY_PROV_INFO* p_prov_info = (CRYPT_KEY_PROV_INFO*)malloc(dw_prov_name_size);
    if (!p_prov_info) {
        return false;
    }

    if (!CertGetCertificateContextProperty(p_cert_context, CERT_KEY_PROV_INFO_PROP_ID, p_prov_info, &dw_prov_name_size)) {
        free(p_prov_info);
        return false;
    }

    std::string provider_name;
    int len = WideCharToMultiByte(CP_UTF8, 0, p_prov_info->pwszProvName, -1, NULL, 0, NULL, NULL);
    if (len > 0) {
        provider_name.resize(len - 1);
        WideCharToMultiByte(CP_UTF8, 0, p_prov_info->pwszProvName, -1, &provider_name[0], len, NULL, NULL);
    }
    free(p_prov_info);

    return provider_name.find(target_provider) != std::string::npos;
}

std::string GetCertificateSubject(PCCERT_CONTEXT p_cert_context) {
    if (!p_cert_context) {
        return "";
    }

    DWORD dw_size = CertGetNameStringA(
        p_cert_context,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        NULL,
        0
    );

    if (dw_size <= 1) {
        return "";
    }

    std::string subject_name(dw_size - 1, '\0');
    CertGetNameStringA(
        p_cert_context,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        &subject_name[0],
        dw_size
    );

    return subject_name;
}

std::vector<PCCERT_CONTEXT> FindProviderCertificates(const std::string& target_provider) {
    std::vector<PCCERT_CONTEXT> cert_contexts;

    HCERTSTORE h_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if (!h_store) {
        std::cerr << "Fail" << std::endl;
        return cert_contexts;
    }

    PCCERT_CONTEXT p_cert_context = NULL;

    while (true) {
        p_cert_context = CertFindCertificateInStore(
            h_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            NULL,
            p_cert_context
        );

        if (p_cert_context == NULL) {
            break;
        }

        if (IsProviderCertificate(p_cert_context, target_provider)) {
            PCCERT_CONTEXT p_dup_cert_context = CertDuplicateCertificateContext(p_cert_context);
            if (p_dup_cert_context) {
                cert_contexts.push_back(p_dup_cert_context);
            }
            else {
                std::cerr << "Fail to dup" << std::endl;
            }
        }
    }

    return cert_contexts;
}

const char* GetHashOid(PCCERT_CONTEXT p_cert) {
    const char* GOST_R3410_12_256 = "1.2.643.7.1.1.1.1";
    const char* GOST_R3410EL = "1.2.643.2.2.19";
    const char* GOST_R3410_12_512 = "1.2.643.7.1.1.1.2";
    const char* GOST_R3411 = "1.2.643.2.2.9";
    const char* GOST_R3411_12_256 = "1.2.643.7.1.1.2.2";
    const char* GOST_R3411_12_512 = "1.2.643.7.1.1.2.3";
    const char* pKeyAlg = p_cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    if (strcmp(pKeyAlg, GOST_R3410EL) == 0)
    {
        return GOST_R3411;
    }
    else if (strcmp(pKeyAlg, GOST_R3410_12_256) == 0)
    {
        return GOST_R3411_12_256;
    }
    else if (strcmp(pKeyAlg, GOST_R3410_12_512) == 0)
    {
        return GOST_R3411_12_512;
    }
    return NULL;
}

void SaveDataToFile(const Blob& data, const std::string& file_path) {
    std::ofstream outfile(file_path, std::ios::out | std::ios::binary);
    outfile.write(reinterpret_cast<const char*>(&data[0]), data.size());
}

Blob EncryptData(PCCERT_CONTEXT cert, const Blob& sourceData)
{
    Blob encryptedData;
    // std::cout << "\nEncrypting data. Source data size = " << sourceData.size() << ".\n";

    CRYPT_ENCRYPT_MESSAGE_PARA encryptParam;
    memset(&encryptParam, 0, sizeof(encryptParam));
    encryptParam.cbSize = sizeof(encryptParam);
    encryptParam.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    encryptParam.ContentEncryptionAlgorithm.pszObjId = (LPSTR)"1.2.643.2.2.21";

    DWORD encryptedDataSize = 0;

    if (!CryptEncryptMessage(&encryptParam, 1, &cert, &sourceData[0], (DWORD)sourceData.size(), NULL,
        &encryptedDataSize))
    {
        throw "First CryptEncryptMessage() call failed.";
    }

    encryptedData.resize(encryptedDataSize);

    if (!CryptEncryptMessage(&encryptParam, 1, &cert, &sourceData[0], (DWORD)sourceData.size(), &encryptedData[0],
        &encryptedDataSize))
    {
        throw "Second CryptEncryptMessage() call failed.";
    }

    return encryptedData;
}

Blob DecryptData(PCCERT_CONTEXT cert, const Blob& encryptedData)
{
    Blob decryptedData;
    std::cout << "\nDecrypting data. Encrypted data size = " << encryptedData.size() << ".\n";

    CRYPT_DECRYPT_MESSAGE_PARA decryptParam;
    memset(&decryptParam, 0, sizeof(decryptParam));
    decryptParam.cbSize = sizeof(decryptParam);
    decryptParam.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    // Create a temporary store to hold the certificate context
    HCERTSTORE hCertStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!hCertStore)
    {
        throw "Failed to create certificate store.";
    }

    // Add the certificate to the store
    if (!CertAddCertificateContextToStore(hCertStore, cert, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
    {
        throw "Failed to add certificate to store.";
    }

    decryptParam.cCertStore = 1;  // Specify we are using one certificate store
    decryptParam.rghCertStore = &hCertStore;  // Pass the certificate store handle

    DWORD decryptedDataSize = 0;

    if (!CryptDecryptMessage(&decryptParam, &encryptedData[0], (DWORD)encryptedData.size(), NULL, &decryptedDataSize, NULL))
    {
        throw "First CryptDecryptMessage() failed.";
    }

    decryptedData.resize(decryptedDataSize);

    if (!CryptDecryptMessage(&decryptParam, &encryptedData[0], (DWORD)encryptedData.size(), &decryptedData[0], &decryptedDataSize, NULL))
    {
        throw "Second CryptDecryptMessage() failed.";
    }

    decryptedData.resize(decryptedDataSize);

    // Clean up the certificate store
    CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);

    return decryptedData;
}

std::shared_ptr<ICsp> GetAvailableCsp(){
    static std::vector<std::pair<std::string, std::function<ICsp*()>>> providers{
        {"Crypto-Pro", [](){return new CryptoProCsp();}},
        {"Infotecs", [](){return new VipNetCsp();}}
    };

    DWORD       cbName;
    DWORD       dwType;
    DWORD       dwIndex;
    CHAR        *pszName = NULL; 

    dwIndex = 0;
    while(CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {
        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName))) {
           printf("ERROR - LocalAlloc failed\n");
           exit(1);
        }
        
        if (CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pszName, &cbName)) {
            for(const auto& prov : providers){
                if(std::string(pszName).find(prov.first) != std::string::npos)
                    return std::shared_ptr<ICsp>(prov.second());
            }
        }
        else {
            printf("ERROR - CryptEnumProviders failed.\n");
            exit(1);
        }
        LocalFree(pszName);
    }
}