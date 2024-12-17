#pragma once

#include <vector>
#include <memory>

#include "cryptofw/Blob.hpp"
#include "cryptofw/CadesType.hpp"

class ICertificate;

/**
 * @class ICsp
 * @brief Interface for cryptographic service providers (CSPs).
 * 
 * The `ICsp` interface defines the methods required for managing certificates and verifying digital signatures.
 * Derived classes should implement these methods based on specific cryptographic service providers.
 */
class ICsp {
public:
    /**
     * @brief Virtual destructor for the `ICsp` interface.
     * 
     * Ensures proper cleanup of derived class objects through the interface.
     */
    virtual ~ICsp() = default;

    /**
     * @brief Retrieves a list of available certificates.
     * 
     * Provides access to the certificates managed by the cryptographic service provider.
     * 
     * @return A vector of shared pointers to all certificates that find by current CSP.
     */
    virtual std::vector<std::shared_ptr<ICertificate>> GetCertificates() = 0;

    /**
     * @brief Verifies an attached CAdES (CMS Advanced Electronic Signatures) signature.
     * 
     * Validates the authenticity of the provided signature against its embedded data.
     * 
     * @param signature The `Blob` containing the attached signature data.
     * @param type The type of CAdES signature (e.g., `CadesType::kBes`).
     * @return Returns `true` if the signature is valid, otherwise `false`.
     */
    virtual bool VerifyCadesAttached(const Blob& signature, CadesType type) const = 0;

    /**
     * @brief Verifies a detached CAdES (CMS Advanced Electronic Signatures) signature.
     * 
     * Validates the authenticity of the provided signature against external source data.
     * 
     * @param signature The `Blob` containing the detached signature data.
     * @param source The `Blob` containing the original source data.
     * @param type The type of CAdES signature (e.g., `CadesType::kBes`).
     * @return `true` if the signature is valid, otherwise `false`.
     */
    virtual bool VerifyCadesDetached(const Blob& signature, const Blob& source, CadesType type) const = 0;
};