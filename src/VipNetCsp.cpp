#include "VipNetCsp.hpp"


std::shared_ptr<ICsp> VipNetCsp::instance_;

const std::string VipNetCsp::mscapi_name_ = "Infotecs";


std::shared_ptr<ICsp> VipNetCsp::GetInstance() {
    if (!VipNetCsp::instance_) {
        if (MscapiCsp::IsMscapiCspAvailable(VipNetCsp::mscapi_name_))
            VipNetCsp::instance_ = std::make_shared<VipNetCsp>();
        else
            VipNetCsp::instance_ = std::shared_ptr<VipNetCsp>();
    }

    return VipNetCsp::instance_;
}

VipNetCsp::VipNetCsp() : MscapiCsp(VipNetCsp::mscapi_name_) {}



