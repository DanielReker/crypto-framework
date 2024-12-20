#pragma once

#include "cryptofw/ICertificate.hpp"

#include "cryptofw-backend.h"

#include <string>


class MscapiCsp;

class MscapiCertificate : public ICertificate {
private:
    const MscapiCsp& mscapi_csp_;
    std::string subject_name_;
    _MscapiCertificate* context_;

public:
    MscapiCertificate(const MscapiCsp& mscapi_csp, const std::string& subject_name, _MscapiCertificate* context);
    _MscapiCertificate* GetCertContext() const;

    Blob Encrypt(const Blob& data) const override;
    Blob Decrypt(const Blob& encrypted_data) const override;
    Blob SignCades(const Blob& data, CadesType type, bool detached, const std::wstring& tsp_server_url = L"") const override;

    std::string GetSubjectName() const override;
};