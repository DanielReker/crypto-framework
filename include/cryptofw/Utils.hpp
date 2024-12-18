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
    /**
     * @brief Saves binary data to file.
     * 
     * Writes the contents of a `Blob` object to the specified file path.
     * 
     * @param data The data to be saved, provided as a `Blob`.
     * @param file_path The file path where the data will be written.
     * 
     * @note If the file already exists, it will be overwritten.
     */
	static void SaveDataToFile(const Blob& data, const std::string& file_path);

    /**
     * @brief Reads binary data from file.
     *
     * Reads file at specified path and returns its binary data as `Blob`.
     *
     * @param file_path File path to read data from.
     * 
     * @throws std::runtime_error File does not exist.
     */
    static Blob ReadDataFromFile(const std::string& file_path);
};

// TODO: Move to Blob implementation
std::ostream& operator<<(std::ostream& out, const Blob& blob);
