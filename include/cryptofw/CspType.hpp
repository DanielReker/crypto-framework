#pragma once

/**
 * @enum CspType
 * @brief Types of CSPs (cryptographic service providers).
 *
 * Lists all CSPs (cryptographic service providers) supported by CryptoFramework.
 */
enum class CspType {
    /**
     * @brief CryptoPro CSP.
     *
     * CryptoPro CSP supports all available functionality (including CMS encryption/decryption,
     * CAdES-BES and CAdES-X Long Type 1 signatures).
     */
    kCryptoProCsp,

    /**
     * @brief ViPNet CSP.
     *
     * CryptoPro CSP supports CMS encryption/decryption and CAdES-BES signatures,
     * but does not support CAdES-X Long Type 1 signatures).
     */
    kVipNetCsp
};