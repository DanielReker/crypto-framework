#pragma once

#include "cryptofw/ICertificate.hpp"
#include <string>


class CryptoProCsp;

class CryptoProCertificate : public ICertificate {
private:
    const CryptoProCsp& crypto_pro_csp_;
    std::string subject_name_;

public:
    CryptoProCertificate(const CryptoProCsp& crypto_pro_csp, const std::string& subject_name);

    Blob Encrypt(const Blob& data) const override;

    Blob Decrypt(const Blob& encrypted_data) const override;

    Blob SignCades(const Blob& data, CadesType type) const override;
    bool VerifyCades(const Blob& signature, CadesType type) const override;

    Blob SignXades(const Blob& data, XadesType type) const override;
    bool VerifyXades(const Blob& signature, XadesType type) const override;

    std::string GetSubjectName() const override;
};