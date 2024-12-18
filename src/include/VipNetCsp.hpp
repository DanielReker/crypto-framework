#pragma once

#include <string>

#include "cryptofw/Blob.hpp"

#include "MscapiCsp.hpp"
#include "MscapiCertificate.hpp"


class VipNetCsp : public MscapiCsp {
private:
    static std::shared_ptr<ICsp> instance_;

    static const std::string mscapi_name_;


public:
    static std::shared_ptr<ICsp> GetInstance();

    VipNetCsp();
};