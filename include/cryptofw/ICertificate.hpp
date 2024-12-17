#pragma once

#include <string>
#include "cryptofw/Blob.hpp"
#include "cryptofw/CadesType.hpp"

/**
 * @class ICertificate
 * @brief Interface representing a digital certificate.
 * 
 * The `ICertificate` interface defines methods for encryption, decryption, 
 * signing data using CAdES (CMS Advanced Electronic Signatures), and retrieving certificate information.
 */
class ICertificate {
public:
    /**
     * @brief Virtual destructor for the `ICertificate` interface.
     * 
     * Ensures proper cleanup of derived class objects through the interface.
     */
    virtual ~ICertificate() = default;

    /**
     * @brief Encrypts the provided data.
     * 
     * Encrypts the input `Blob` data using the certificate's public key.
     * 
     * @param data The `Blob` containing the data to be encrypted.
     * @return The encrypted data as a `Blob`.
     */
    virtual Blob Encrypt(const Blob& data) const = 0;

    /**
     * @brief Decrypts the provided encrypted data.
     * 
     * Decrypts the input `Blob` data using the certificate's private key.
     * 
     * @param encrypted_data The `Blob` containing the data to be decrypted.
     * @return The decrypted data as a `Blob`.
     */
    virtual Blob Decrypt(const Blob& encrypted_data) const = 0;

    /**
     * @brief Signs the provided data using the CAdES format.
     * 
     * Generates a CAdES signature for the input data, with the option to create 
     * an attached or detached signature. Additionally, a Time-Stamp Protocol (TSP)
     * server URL can be provided for timestamping the signature.
     * 
     * @param data The `Blob` containing the data to be signed.
     * @param type The type of CAdES signature (e.g., `CadesType::kBes`).
     * @param detached A boolean indicating whether the signature is detached (true) or attached (false).
     * @param tsp_server_url An optional URL of the TSP server to include a trusted timestamp in the signature.
     *                       If not provided, timestamping will not be performed.
     * @return The generated signature as a `Blob`.
     */
    virtual Blob SignCades(const Blob& data, CadesType type, bool detached, const std::wstring& tsp_server_url = L"") const = 0;

    /**
     * @brief Retrieves the subject name of the certificate.
     * 
     * Returns the subject name (distinguished name) associated with the certificate.
     * 
     * @return The subject name of the certificate.
     */
    virtual std::string GetSubjectName() const = 0;
};