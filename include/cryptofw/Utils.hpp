#pragma once

#include <memory>
#include <string>

#include "cryptofw/ICsp.hpp"

/**
 * @brief Utility class for cryptographic services and data management.
 * 
 * The `Utils` class provides static methods to retrieve cryptographic service providers (CSPs)
 * and save data to a file.
 */
class Utils {
public:
	// TODO: Move to Blob implementation
    /**
     * @brief Saves data to a file.
     * 
     * Writes the contents of a `Blob` object to the specified file path.
     * 
     * @param data The data to be saved, provided as a `Blob` object.
     * @param file_path The file path where the data will be written.
     * 
     * @note If the file already exists, it will be overwritten.
     */
	static void SaveDataToFile(const Blob& data, const std::string& file_path);
};

// TODO: Move to Blob implementation
std::ostream& operator<<(std::ostream& out, const Blob& blob);
