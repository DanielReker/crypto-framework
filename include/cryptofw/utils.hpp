#pragma once

#include <memory>
#include <iostream>
#include <iomanip>
#include <fstream>

#include <windows.h>
#include <wincrypt.h>

#include "cryptofw/Blob.hpp"
#include "cryptofw/ICsp.hpp"

#define SERVICE_URL_2001 L"http://pki.tax.gov.ru/tsp/tsp.srf"
#define SERVICE_URL_2012 L"http://pki.tax.gov.ru/tsp/tsp.srf"



std::ostream& operator<<(std::ostream& out, const Blob& blob);

// Just for API demonstration
std::shared_ptr<ICsp> GetCryptoProCsp();
std::shared_ptr<ICsp> GetVipNetCsp();

bool IsProviderCertificate(PCCERT_CONTEXT p_cert_context, const std::string& target_provider);
std::string GetCertificateSubject(PCCERT_CONTEXT p_cert_context);
std::vector<PCCERT_CONTEXT> FindProviderCertificates(const std::string& target_provider);

const char* GetHashOid(PCCERT_CONTEXT p_cert);

void SaveDataToFile(const Blob& data, const std::string& file_path);

Blob EncryptData(PCCERT_CONTEXT cert, const Blob& sourceData);
Blob DecryptData(PCCERT_CONTEXT cert, const Blob& encryptedData);

std::shared_ptr<ICsp> GetAvailableCsp();
