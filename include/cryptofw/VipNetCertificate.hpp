#pragma once
#include <windows.h>
#include <wincrypt.h>
#include "cryptofw/ICertificate.hpp"
#include <string>


class VipNetCsp;

class VipNetCertificate : public ICertificate {
private:
    const VipNetCsp& vip_net_csp_;
    std::string subject_name_;
    PCCERT_CONTEXT context_;
public:
    VipNetCertificate(const VipNetCsp& vip_net_csp, const std::string& subject_name, PCCERT_CONTEXT context);

    Blob Encrypt(const Blob& data) const override;

    Blob Decrypt(const Blob& encrypted_data) const override;

    Blob SignCades(const Blob& data, CadesType type) const override;
    bool VerifyCades(const Blob& signature, CadesType type) const override;

    Blob SignXades(const Blob& data, XadesType type) const override;
    bool VerifyXades(const Blob& signature, XadesType type) const override;

    std::string GetSubjectName() const override;
};