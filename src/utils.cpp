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
        throw std::runtime_error("Invlid certificate context");
    }

    DWORD dw_size = CertGetNameStringA(
        p_cert_context,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        NULL,
        0
    );

    // TODO: Refactor
    if (dw_size <= 1) {
        throw std::runtime_error("Broken");
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

    // TODO: Check other stores
    HCERTSTORE h_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if (!h_store) {
        throw std::runtime_error("Fail to open certificates store");
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

Blob EncryptData(PCCERT_CONTEXT cert, const Blob& source_data) {
    Blob encrypted_data;

    CRYPT_ENCRYPT_MESSAGE_PARA encrypt_param;
    memset(&encrypt_param, 0, sizeof(encrypt_param));
    encrypt_param.cbSize = sizeof(encrypt_param);
    encrypt_param.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    encrypt_param.ContentEncryptionAlgorithm.pszObjId = (LPSTR)"1.2.643.2.2.21";

    DWORD encrypted_data_size = 0;

    if (!CryptEncryptMessage(&encrypt_param, 1, &cert, &source_data[0], (DWORD)source_data.size(), NULL,
        &encrypted_data_size)) {
        throw std::runtime_error("First CryptEncryptMessage() call failed.");
    }

    encrypted_data.resize(encrypted_data_size);

    if (!CryptEncryptMessage(&encrypt_param, 1, &cert, &source_data[0], (DWORD)source_data.size(), &encrypted_data[0],
        &encrypted_data_size)) {
        throw std::runtime_error("Second CryptEncryptMessage() call failed.");
    }

    return encrypted_data;
}

Blob DecryptData(PCCERT_CONTEXT cert, const Blob& encrypted_data)
{
    Blob decrypted_data;

    CRYPT_DECRYPT_MESSAGE_PARA decrypt_param;
    memset(&decrypt_param, 0, sizeof(decrypt_param));
    decrypt_param.cbSize = sizeof(decrypt_param);
    decrypt_param.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    HCERTSTORE h_cert_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!h_cert_store) {
        throw std::runtime_error("Failed to create certificate store.");
    }

    if (!CertAddCertificateContextToStore(h_cert_store, cert, CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
        throw std::runtime_error("Failed to add certificate to store.");
    }

    decrypt_param.cCertStore = 1;
    decrypt_param.rghCertStore = &h_cert_store;

    DWORD decrypted_data_size = 0;

    if (!CryptDecryptMessage(&decrypt_param, &encrypted_data[0], (DWORD)encrypted_data.size(), NULL, &decrypted_data_size, NULL)) {
        throw std::runtime_error("First CryptDecryptMessage() failed.");
    }

    decrypted_data.resize(decrypted_data_size);

    if (!CryptDecryptMessage(&decrypt_param, &encrypted_data[0], (DWORD)encrypted_data.size(), &decrypted_data[0], &decrypted_data_size, NULL)) {
        throw std::runtime_error("Second CryptDecryptMessage() failed.");
    }

    decrypted_data.resize(decrypted_data_size);

    CertCloseStore(h_cert_store, CERT_CLOSE_STORE_FORCE_FLAG);

    return decrypted_data;
}

std::shared_ptr<ICsp> GetAvailableCsp(){
    static std::vector<std::pair<std::string, std::shared_ptr<ICsp>>> providers = {
        {"Crypto-Pro", std::make_shared<CryptoProCsp>()},
        {"Infotecs", std::make_shared<VipNetCsp>()}
    };

    DWORD cb_name;
    DWORD dw_type;
    DWORD dw_index;
    CHAR *pszName = NULL; 

    dw_index = 0;
    while (CryptEnumProviders(dw_index, NULL, 0, &dw_type, NULL, &cb_name)) {
        if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cb_name))) {
           throw std::runtime_error("LocalAlloc failed\n");
        }
        
        if (CryptEnumProviders(dw_index++, NULL, 0, &dw_type, pszName, &cb_name)) {
            for(const auto& prov : providers){
                if(std::string(pszName).find(prov.first) != std::string::npos)
                    return prov.second;
            }
        }
        else {
            throw std::runtime_error("CryptEnumProviders failed.\n");
        }
        LocalFree(pszName);
    }
}

bool VerifyCadesBes(const Blob& signature) {
    const BYTE* pbSignedBlob = &signature[0];
    DWORD cbSignedBlob = signature.size();
    BYTE* pbDecodedData = NULL;
    DWORD cbDecodedData;
    PCCERT_CONTEXT pSignerCert = NULL;
    CRYPT_VERIFY_MESSAGE_PARA verifyParams;

    if (!pbSignedBlob || cbSignedBlob == 0) {
        throw std::invalid_argument("Invalid signature");
    }

    ZeroMemory(&verifyParams, sizeof(verifyParams));
    verifyParams.cbSize = sizeof(verifyParams);
    verifyParams.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    if (!CryptVerifyMessageSignature(&verifyParams, 0, pbSignedBlob, cbSignedBlob, NULL, &cbDecodedData, &pSignerCert)) {
        //throw std::runtime_error("Failed to get decoded message size");
        return false;
    }

    pbDecodedData = (BYTE*)malloc(cbDecodedData);
    if (!pbDecodedData) {
        if (pSignerCert) CertFreeCertificateContext(pSignerCert);
        throw std::runtime_error("Failed to allocate memory for decoded data");
    }

    if (!CryptVerifyMessageSignature(&verifyParams, 0, pbSignedBlob, cbSignedBlob, pbDecodedData, &cbDecodedData, &pSignerCert)) {
        free(pbDecodedData);
        if (pSignerCert) CertFreeCertificateContext(pSignerCert);
        //throw std::runtime_error("Signature verification failed");
        return false;
    }

    free(pbDecodedData);
    if (pSignerCert) CertFreeCertificateContext(pSignerCert);

    return true;
}