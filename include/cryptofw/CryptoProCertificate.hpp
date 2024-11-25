#pragma once

#include <windows.h>
#include <wincrypt.h>
#include "cryptofw/ICertificate.hpp"
#include <string>


class CryptoProCsp;

class CryptoProCertificate : public ICertificate {
private:
    const CryptoProCsp& crypto_pro_csp_;
    std::string subject_name_;
    PCCERT_CONTEXT context_;

public:
    CryptoProCertificate(const CryptoProCsp& crypto_pro_csp, const std::string& subject_name, PCCERT_CONTEXT context);
    
    PCCERT_CONTEXT GetCertContext() const;

    Blob Encrypt(const Blob& data) const override;
    Blob Decrypt(const Blob& encrypted_data) const override;
    Blob SignCades(const Blob& data, CadesType type, bool detached) const override;
    Blob SignXades(const Blob& data, XadesType type) const override;

    std::string GetSubjectName() const override;
};