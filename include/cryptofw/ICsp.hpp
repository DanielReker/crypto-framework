#pragma once

#include <vector>
#include <memory>

class ICertificate;

class ICsp {
public:
    virtual ~ICsp() = default;

    virtual std::vector<std::shared_ptr<ICertificate>> GetCertificates() = 0;
};