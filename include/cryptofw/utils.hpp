#pragma once

#include <ostream>
#include <memory>
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include "cryptofw/Blob.hpp"
#include "cryptofw/ICsp.hpp"


std::ostream& operator<<(std::ostream& out, const Blob& blob);

// Just for API demonstration
std::shared_ptr<ICsp> GetSomeCSP();

bool IsProviderCertificate(PCCERT_CONTEXT p_cert_context, const std::string& target_provider);
std::string GetCertificateSubject(PCCERT_CONTEXT p_cert_context);
std::vector<PCCERT_CONTEXT> FindProviderCertificates(const std::string& target_provider);
