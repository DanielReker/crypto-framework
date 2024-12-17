#include <vector>
#include <string>

#include <windows.h>
#include <wincrypt.h>

#include <cades.h>

#include "cryptofw-backend.h"


const char* _GetErrorMessage(_Error error) {
    static const std::vector<std::string> error_messages = {
        "OK", // E_OK
        "Failed to open certificates store", // E_MSCAPI_CERT_STORE_OPEN_FAIL
        "Invlid certificate context", // E_MSCAPI_INVALID_CERT_CONTEXT
        "Unknown error" // E_UNKNOWN
    };

    return error_messages[error].c_str();
}


_Error _GetMscapiCspCertificates(const char* csp_name, _MscapiCertificatesList* out) {
    std::vector<PCCERT_CONTEXT> cert_contexts;

    // TODO: Check other stores
    HCERTSTORE h_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if (!h_store) {
        return E_MSCAPI_CERT_STORE_OPEN_FAIL;
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

        bool certificateBelongToCsp;
        _DoesMscapiCertificateBelongToCsp((_MscapiCertificate*)p_cert_context, csp_name, &certificateBelongToCsp);
        if (certificateBelongToCsp) {
            PCCERT_CONTEXT p_dup_cert_context = CertDuplicateCertificateContext(p_cert_context);
            if (p_dup_cert_context) {
                cert_contexts.push_back(p_dup_cert_context);
            }
        }
    }

    out->count = cert_contexts.size();
    PCCERT_CONTEXT* data = new PCCERT_CONTEXT[out->count];
    std::copy(cert_contexts.begin(), cert_contexts.end(), data);
    out->certificates = (_MscapiCertificate**)data;

    return E_OK;
}

_Error _DoesMscapiCertificateBelongToCsp(_MscapiCertificate* certificate, const char* csp_name, bool* result) {
    std::string target_provider(csp_name);

    DWORD dw_prov_name_size = 0;
    if (!CertGetCertificateContextProperty((PCCERT_CONTEXT)certificate, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dw_prov_name_size)) {
        *result = false;
        return E_OK;
    }

    CRYPT_KEY_PROV_INFO* p_prov_info = (CRYPT_KEY_PROV_INFO*)malloc(dw_prov_name_size);
    if (!p_prov_info) {
        *result = false;
        return E_OK;
    }

    if (!CertGetCertificateContextProperty((PCCERT_CONTEXT)certificate, CERT_KEY_PROV_INFO_PROP_ID, p_prov_info, &dw_prov_name_size)) {
        free(p_prov_info);
        *result = false;
        return E_OK;
    }

    std::string provider_name;
    int len = WideCharToMultiByte(CP_UTF8, 0, p_prov_info->pwszProvName, -1, NULL, 0, NULL, NULL);
    if (len > 0) {
        provider_name.resize(len - 1);
        WideCharToMultiByte(CP_UTF8, 0, p_prov_info->pwszProvName, -1, &provider_name[0], len, NULL, NULL);
    }
    free(p_prov_info);

    *result = provider_name.find(target_provider) != std::string::npos;
    return E_OK;
}

_Error _GetMscapiCertificateSubject(_MscapiCertificate* certificate, char** out) {
    if (!certificate) {
        return E_MSCAPI_INVALID_CERT_CONTEXT;
    }

    DWORD dw_size = CertGetNameStringA(
        (PCCERT_CONTEXT)certificate,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        NULL,
        0
    );

    // TODO: Refactor
    if (dw_size <= 1) {
        return E_UNKNOWN;
    }

    *out = new char[dw_size];
    CertGetNameStringA(
        (PCCERT_CONTEXT)certificate,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        *out,
        dw_size
    );

    return E_OK;
}

const char* _MscapiGetHashOid(_MscapiCertificate* p_cert) {
    const char* GOST_R3410_12_256 = "1.2.643.7.1.1.1.1";
    const char* GOST_R3410EL = "1.2.643.2.2.19";
    const char* GOST_R3410_12_512 = "1.2.643.7.1.1.1.2";
    const char* GOST_R3411 = "1.2.643.2.2.9";
    const char* GOST_R3411_12_256 = "1.2.643.7.1.1.2.2";
    const char* GOST_R3411_12_512 = "1.2.643.7.1.1.2.3";
    const char* p_key_alg = ((PCCERT_CONTEXT)p_cert)->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
    if (strcmp(p_key_alg, GOST_R3410EL) == 0)
    {
        return GOST_R3411;
    }
    else if (strcmp(p_key_alg, GOST_R3410_12_256) == 0)
    {
        return GOST_R3411_12_256;
    }
    else if (strcmp(p_key_alg, GOST_R3410_12_512) == 0)
    {
        return GOST_R3411_12_512;
    }
    return NULL;
}


_Error _MscapiEncryptData(_MscapiCertificate* cert, _Blob source_data, _Blob* out) {
    PCCERT_CONTEXT mscapi_cert = (PCCERT_CONTEXT)cert;

    CRYPT_ENCRYPT_MESSAGE_PARA encrypt_param;
    memset(&encrypt_param, 0, sizeof(encrypt_param));
    encrypt_param.cbSize = sizeof(encrypt_param);
    encrypt_param.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    encrypt_param.ContentEncryptionAlgorithm.pszObjId = (LPSTR)"1.2.643.2.2.21";

    DWORD encrypted_data_size = 0;

    if (!CryptEncryptMessage(&encrypt_param, 1, &mscapi_cert, (BYTE*)source_data.data, static_cast<DWORD>(source_data.size), NULL,
        &encrypted_data_size)) {
        return E_UNKNOWN;
    }

    out->size = encrypted_data_size;
    out->data = new uint8_t[encrypted_data_size];

    if (!CryptEncryptMessage(&encrypt_param, 1, &mscapi_cert, (BYTE*)source_data.data, static_cast<DWORD>(source_data.size), (BYTE*)out->data,
        &encrypted_data_size)) {
        return E_UNKNOWN;
    }

    return E_OK;
}


_Error _MscapiDecryptData(_MscapiCertificate* cert, _Blob encrypted_data, _Blob* out) {
    PCCERT_CONTEXT mscapi_cert = (PCCERT_CONTEXT)cert;

    CRYPT_DECRYPT_MESSAGE_PARA decrypt_param;
    memset(&decrypt_param, 0, sizeof(decrypt_param));
    decrypt_param.cbSize = sizeof(decrypt_param);
    decrypt_param.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    HCERTSTORE h_cert_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!h_cert_store) {
        //throw std::runtime_error("Failed to create certificate store.");
        return E_UNKNOWN;
    }

    if (!CertAddCertificateContextToStore(h_cert_store, mscapi_cert, CERT_STORE_ADD_REPLACE_EXISTING, NULL)) {
        //throw std::runtime_error("Failed to add certificate to store.");
        return E_UNKNOWN;
    }

    decrypt_param.cCertStore = 1;
    decrypt_param.rghCertStore = &h_cert_store;

    DWORD decrypted_data_size = 0;

    if (!CryptDecryptMessage(&decrypt_param, (BYTE*)encrypted_data.data, (DWORD)encrypted_data.size, NULL, &decrypted_data_size, NULL)) {
        return E_UNKNOWN;
    }

    out->size = decrypted_data_size;
    out->data = new uint8_t[decrypted_data_size];

    if (!CryptDecryptMessage(&decrypt_param, (BYTE*)encrypted_data.data, (DWORD)encrypted_data.size, (BYTE*)out->data, &decrypted_data_size, NULL)) {
        return E_UNKNOWN;
    }

    out->size = decrypted_data_size;

    CertCloseStore(h_cert_store, CERT_CLOSE_STORE_FORCE_FLAG);

    return E_OK;
}

_Error _MscapiSignCadesBes(_MscapiCertificate* cert, bool detached, _Blob data, _Blob* out) {
    PCCERT_CONTEXT mscapi_cert = (PCCERT_CONTEXT)cert;
    
    if (!cert) {
        return E_MSCAPI_INVALID_CERT_CONTEXT;
    }

    CRYPT_SIGN_MESSAGE_PARA sign_param;
    memset(&sign_param, 0, sizeof(sign_param));
    sign_param.cbSize = sizeof(sign_param);
    sign_param.dwMsgEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
    sign_param.pSigningCert = mscapi_cert;
    sign_param.HashAlgorithm.pszObjId = const_cast<LPSTR>(_MscapiGetHashOid(cert));
    sign_param.cMsgCert = 1;
    sign_param.rgpMsgCert = &mscapi_cert;

    FILETIME ts;
    GetSystemTimeAsFileTime(&ts);

    DWORD ts_len = 0;
    if (!CryptEncodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, szOID_RSA_signingTime, &ts, NULL, &ts_len)) {
        return E_UNKNOWN;
    }

    std::vector<uint8_t> ts_buf(ts_len);
    if (!CryptEncodeObject(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, szOID_RSA_signingTime, &ts, ts_buf.data(), &ts_len)) {
        return E_UNKNOWN;
    }

    CRYPT_ATTR_BLOB ts_blob = { ts_len, ts_buf.data() };
    CRYPT_ATTRIBUTE ts_attr = { const_cast<LPSTR>(szOID_RSA_signingTime), 1, &ts_blob };
    sign_param.cAuthAttr = 1;
    sign_param.rgAuthAttr = &ts_attr;

    const BYTE* message_ptr = data.data;
    DWORD message_size = static_cast<DWORD>(data.size);
    DWORD sign_size = 0;

    if (!CryptSignMessage(&sign_param, detached, 1, &message_ptr, &message_size, NULL, &sign_size)) {
        return E_UNKNOWN;
    }

    std::vector<uint8_t> signature(sign_size);

    if (!CryptSignMessage(&sign_param, detached, 1, &message_ptr, &message_size, signature.data(), &sign_size)) {
        return E_UNKNOWN;
    }

    out->size = signature.size();
    out->data = new uint8_t[out->size];
    std::copy(signature.begin(), signature.end(), out->data);

    return E_OK;
}

_Error _MscapiVerifyCadesBesDetached(_Blob signature, _Blob message, bool* out) {
    CRYPT_VERIFY_MESSAGE_PARA verify_params;
    memset(&verify_params, 0, sizeof(verify_params));
    verify_params.cbSize = sizeof(verify_params);
    verify_params.dwMsgAndCertEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

    const BYTE* message_ptr = message.data;
    DWORD message_size = static_cast<DWORD>(message.size);
    PCCERT_CONTEXT cert = NULL;

    if (!CryptVerifyDetachedMessageSignature(
        &verify_params, 0, signature.data, static_cast<DWORD>(signature.size),
        1, &message_ptr, &message_size, &cert
    )) {
        *out = false;
        return E_OK;
    }

    char cert_name[512] = { 0 };
    if (!CertNameToStr(X509_ASN_ENCODING, &cert->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, cert_name,
        sizeof(cert_name))) {
        *out = false;
        return E_OK;
    }

    CertFreeCertificateContext(cert);

    *out = true;
    return E_OK;
}

_Error _MscapiVerifyCadesBesAttached(_Blob signature, bool* out) {
    std::vector<BYTE> message;
    CRYPT_VERIFY_MESSAGE_PARA verify_param;
    memset(&verify_param, 0, sizeof(verify_param));
    verify_param.cbSize = sizeof(verify_param);
    verify_param.dwMsgAndCertEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

    DWORD message_size = 0;
    if (!CryptVerifyMessageSignature(&verify_param, 0, signature.data, static_cast<DWORD>(signature.size), NULL, &message_size,
        NULL)) {
        *out = false;
        return E_OK;
    }

    PCCERT_CONTEXT cert = NULL;
    message.resize(message_size);
    if (!CryptVerifyMessageSignature(&verify_param, 0, signature.data, static_cast<DWORD>(signature.size), &message[0],
        &message_size, &cert)) {
        *out = false;
        return E_OK;
    }

    char cert_name[512] = { 0 };
    if (!CertNameToStr(X509_ASN_ENCODING, &cert->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, cert_name,
        sizeof(cert_name))) {
        *out = false;
        return E_OK;
    }

    CertFreeCertificateContext(cert);

    *out = true;
    return E_OK;
}


_Error _CryptoProSignCadesXl(_MscapiCertificate* cert, _Blob data, bool detached, const wchar_t* tsp_service_url, _Blob* out) {
    PCCERT_CONTEXT mscapi_cert = (PCCERT_CONTEXT)cert;


    CRYPT_SIGN_MESSAGE_PARA sign_param = { sizeof(sign_param) };
    sign_param.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    sign_param.pSigningCert = mscapi_cert;
    sign_param.HashAlgorithm.pszObjId = (LPSTR)_MscapiGetHashOid(cert);

    CADES_SERVICE_CONNECTION_PARA tsp_connection_para = { sizeof(tsp_connection_para) };
    tsp_connection_para.wszUri = tsp_service_url;

    CADES_SIGN_PARA cades_sign_para = { sizeof(cades_sign_para) };
    cades_sign_para.dwCadesType = CADES_X_LONG_TYPE_1;
    cades_sign_para.pTspConnectionPara = &tsp_connection_para;

    CADES_SIGN_MESSAGE_PARA para = { sizeof(para) };
    para.pSignMessagePara = &sign_param;
    para.pCadesSignPara = &cades_sign_para;

    const uint8_t* pb_to_be_signed[] = { data.data };
    DWORD cb_to_be_signed[] = { (DWORD)data.size };
    PCRYPT_DATA_BLOB p_signed_message = 0;


    if (!CadesSignMessage(&para, detached, 1, pb_to_be_signed, cb_to_be_signed, &p_signed_message)) {
        return E_UNKNOWN;
    }

    out->size = static_cast<size_t>(p_signed_message->cbData);
    out->data = new uint8_t[out->size];
    std::memcpy(out->data, p_signed_message->pbData, out->size);

    if (!CadesFreeBlob(p_signed_message)) {
        return E_UNKNOWN;
    }

    return E_OK;
}

_Error _CryptoProVerifyCadesXlAttached(_Blob signature, bool* out) {
    CRYPT_VERIFY_MESSAGE_PARA crypt_verify_params = { sizeof(crypt_verify_params) };
    crypt_verify_params.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFICATION_PARA cades_verify_params = { sizeof(cades_verify_params) };
    cades_verify_params.dwCadesType = CADES_X_LONG_TYPE_1;

    CADES_VERIFY_MESSAGE_PARA verify_params = { sizeof(verify_params) };
    verify_params.pVerifyMessagePara = &crypt_verify_params;
    verify_params.pCadesVerifyPara = &cades_verify_params;

    PCADES_VERIFICATION_INFO p_verify_info_attached = 0;
    PCRYPT_DATA_BLOB p_content = 0;
    if (!CadesVerifyMessage(&verify_params, 0, signature.data, signature.size, &p_content, &p_verify_info_attached)) {
        *out = false;
        return E_OK;
    }

    bool result = (p_verify_info_attached->dwStatus == CADES_VERIFY_SUCCESS);
    if (!CadesFreeVerificationInfo(p_verify_info_attached)) {
        return E_UNKNOWN;
    }
    if (!CadesFreeBlob(p_content)) {
        return E_UNKNOWN;
    }

    *out = result;
    return E_OK;
}

_Error _CryptoProVerifyCadesXlDetached(_Blob signature, _Blob message, bool* out) {
    CRYPT_VERIFY_MESSAGE_PARA crypt_verify_params = { sizeof(crypt_verify_params) };
    crypt_verify_params.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

    CADES_VERIFICATION_PARA cades_verify_params = { sizeof(cades_verify_params) };
    cades_verify_params.dwCadesType = CADES_X_LONG_TYPE_1;

    CADES_VERIFY_MESSAGE_PARA verify_params = { sizeof(verify_params) };
    verify_params.pVerifyMessagePara = &crypt_verify_params;
    verify_params.pCadesVerifyPara = &cades_verify_params;

    const BYTE* message_ptr = message.data;
    DWORD message_size = (DWORD)message.size;

    PCADES_VERIFICATION_INFO p_verify_info_detached = 0;
    PCRYPT_DATA_BLOB p_content = 0;
    if (!CadesVerifyDetachedMessage(&verify_params, 0, signature.data, (unsigned long)signature.size, 1,
        &message_ptr, &message_size, &p_verify_info_detached)) {

        *out = false;
        return E_OK;
    }

    bool result = (p_verify_info_detached->dwStatus == CADES_VERIFY_SUCCESS);
    if (!CadesFreeVerificationInfo(p_verify_info_detached)) {
        return E_UNKNOWN;
    }

    *out = result;
    return E_OK;
}