#pragma once

#include <ostream>
#include <memory>

#include "cryptofw/Blob.hpp"
#include "cryptofw/ICsp.hpp"

std::ostream& operator<<(std::ostream& out, const Blob& blob);

// Just for API demonstration
std::shared_ptr<ICsp> GetSomeCSP();

