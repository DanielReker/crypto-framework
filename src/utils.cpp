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

// Проверка, связан ли сертификат с целевым провайдером
bool IsProviderCertificate(PCCERT_CONTEXT pCertContext, const std::string& targetProvider) {
    DWORD dwProvNameSize = 0;
    if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwProvNameSize)) {
        return false; // Не удалось получить информацию
    }

    CRYPT_KEY_PROV_INFO* pProvInfo = (CRYPT_KEY_PROV_INFO*)malloc(dwProvNameSize);
    if (!pProvInfo) {
        return false; // Ошибка выделения памяти
    }

    if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pProvInfo, &dwProvNameSize)) {
        free(pProvInfo);
        return false; // Не удалось получить данные
    }

    std::string providerName;
    int len = WideCharToMultiByte(CP_UTF8, 0, pProvInfo->pwszProvName, -1, NULL, 0, NULL, NULL);
    if (len > 0) {
        providerName.resize(len - 1);
        WideCharToMultiByte(CP_UTF8, 0, pProvInfo->pwszProvName, -1, &providerName[0], len, NULL, NULL);
    }
    free(pProvInfo);

    // Проверяем, что провайдер соответствует целевому имени
    return providerName.find(targetProvider) != std::string::npos;
}

// Преобразует имя субъекта сертификата в строку
std::string GetCertificateSubject(PCCERT_CONTEXT pCertContext) {
    if (!pCertContext) {
        return "Ошибка: пустой контекст сертификата";
    }

    DWORD dwSize = CertGetNameStringA(
        pCertContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        NULL,
        0
    );

    if (dwSize <= 1) {
        return "Не удалось извлечь имя субъекта";
    }

    std::string subjectName(dwSize - 1, '\0');
    CertGetNameStringA(
        pCertContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        NULL,
        &subjectName[0],
        dwSize
    );

    return subjectName;
}

// Находит все сертификаты от указанного провайдера
std::vector<PCCERT_CONTEXT> FindProviderCertificates(const std::string& targetProvider) {
    std::vector<PCCERT_CONTEXT> certContexts;

    HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if (!hStore) {
        std::cerr << "Не удалось открыть хранилище сертификатов." << std::endl;
        return certContexts;
    }

    PCCERT_CONTEXT pCertContext = NULL;

    /*std::cout << "Поиск сертификатов от провайдера: " << targetProvider << "..." << std::endl;*/
    while (true) {
        pCertContext = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            NULL,
            pCertContext
        );

        if (pCertContext == NULL) {
            break; // Все сертификаты найдены
        }

        // Проверяем, что сертификат относится к нужному провайдеру
        if (IsProviderCertificate(pCertContext, targetProvider)) {
            //std::cout << "Найден сертификат:" << std::endl;
            //std::cout << "  Субъект: " << GetCertificateSubject(pCertContext) << std::endl;
            //std::cout << "------------------------------------------";

            // Создаем дубликат контекста сертификата и добавляем его в вектор
            PCCERT_CONTEXT pDupCertContext = CertDuplicateCertificateContext(pCertContext);
            if (pDupCertContext) {
                certContexts.push_back(pDupCertContext);
            }
            else {
                std::cerr << "Не удалось дублировать сертификат." << std::endl;
            }
        }
    }
    // nepizdec
    //for (auto cert : certContexts) {
    //    std::cout << "Субъект сертификата: " << GetCertificateSubject(cert) << std::endl;
    //}

    return certContexts;
}