#pragma once

#include <vector>
#include <cstdint>

/**
 * @typedef Blob
 * @brief Represents a binary data container.
 * 
 * The `Blob` type is defined as a `std::vector` of 8-bit unsigned integers (`std::uint8_t`). 
 * It is used to store and manipulate raw binary data in cryptographic operations.
 */
typedef std::vector<std::uint8_t> Blob;