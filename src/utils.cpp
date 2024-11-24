#include <memory>

#include <cryptofw/utils.hpp>
#include <cryptofw/CryptoProCsp.hpp>
#include <cryptofw/VipNetCsp.hpp>
#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <iostream>


std::ostream& operator<<(std::ostream& out, const Blob& blob) {
	for (auto byte : blob) {
		out << std::hex << static_cast<int>(byte);
	}
	return out;
}

std::shared_ptr<ICsp> GetSomeCSP() {
	srand(time(nullptr));
	if (rand() % 2 == 0) return std::make_shared<CryptoProCsp>();
	else return std::make_shared<VipNetCsp>();
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