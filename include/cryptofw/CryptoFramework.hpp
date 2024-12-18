#pragma once

#include <memory>
#include <map>


#include "cryptofw/CspType.hpp"
#include "cryptofw/ICsp.hpp"

/**
 * @brief An "entry point" in CryptoFramework.
 *
 * This static class is used to start working with CryptoFramework.
 * It checks CSPs availability and provides their instances.
 */
class CryptoFramework {
public:
	/**
	 * @brief Is CSP available?
	 *
	 * Checks if given CSP type is available.
	 * 
	 * @param csp CSP type to check.
	 */
	static bool IsCspAvailable(CspType csp);

	/**
	 * @brief Get CSP instance.
	 *
	 * Returns CSP instance with `ICsp` interface if available.
	 *
	 * @param csp CSP type to get instance of.
	 * 
	 * @throws std::runtime_error If prompted CSP is not available.
	 */
	static std::shared_ptr<ICsp> GetCspInstance(CspType csp);
};