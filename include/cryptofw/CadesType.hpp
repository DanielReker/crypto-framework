#pragma once

/**
 * @enum CadesType
 * @brief Enum representing different types of CAdES (CMS Advanced Electronic Signatures).
 * 
 * The `CadesType` enumeration defines the signature types used in the CAdES standard.
 */
enum class CadesType {
	/**
     * @brief Basic Electronic Signature (BES).
     * 
     * A CAdES signature type that provides a basic level of electronic signature compliance.
     */
	kBes,

	/**
     * @brief Extended Long-Term Type 1 (XLongType1).
     * 
     * A CAdES signature type that provides extended long-term validation capabilities.
     */
	kXLongType1
};