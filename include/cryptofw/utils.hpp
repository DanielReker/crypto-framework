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


std::string GetCertificateSubject(PCCERT_CONTEXT pCertContext);
std::vector<PCCERT_CONTEXT> FindProviderCertificates(const std::string& targetProvider);
