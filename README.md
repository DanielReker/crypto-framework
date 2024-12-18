# CryptoFramework

This framework simplifies working with various cryptographic providers by offering a unified API for digital signatures and encryption. It abstracts away the complexities of different provider APIs, allowing developers to easily integrate and switch between them without modifying their application code.

## Introduction

This framework acts as a universal adapter, bridging the gap between your application and various cryptographic providers. Each provider typically offers its own unique API, which can lead to integration headaches and vendor lock-in. This framework solves this problem by presenting a consistent, streamlined API for all supported providers. It also provides an extensible architecture, making it easy for developers to add support for new providers as needed.  
**Note:** This framework's reliance on Windows-specific functionalities currently limits its cross-platform compatibility.

## Features

* **Unified API:**  Provides a single, consistent interface for working with multiple cryptographic providers.
* **Provider Abstraction:**  Hides the complexities of individual provider APIs, simplifying integration and reducing code dependencies.
* **Extensibility:** Easily add support for new cryptographic providers through a well-defined interface.
* **Digital Signature Support:**  Covers various digital signature algorithms and formats.
* **Encryption/Decryption:** Supports common encryption and decryption algorithms.

## Supported Crypto Providers

* CryptoPro CSP
* VipNet CSP

## Getting Started

### Dependencies

To work with CryptoFramework, you have to download and install CryptoPro SDK from official website: [https://www.cryptopro.ru/products/cades/sdk](https://www.cryptopro.ru/products/cades/sdk), including runtime libraries.

### Installation

Currently only CMake is supported as build system.

To use CryptoFramework in your CMake project:

1) Clone CryptoFramework repository somewhere in your project like:\
`git clone https://github.com/DanielReker/crypto-framework.git externals/crypto-framework`

2) Add it in your CMakeLists.txt as a subdirectory:\
`add_subdirectory(externals/crypto-framework)`\
It adds `cryptofw` target to your CMake project.

3) Link `cryptofw` to your target like:\
`target_link_libraries(your-target PRIVATE cryptofw)`

Now CryptoFramework is ready to use!


### Usage

Here's simple example of how you can use CryptoFramework in your app:

```c++
#include <iostream>
#include <cryptofw/ICsp.hpp>
#include <cryptofw/ICertificate.hpp>
#include <cryptofw/CryptoFramework.hpp>
#include <cryptofw/CspType.hpp>


int main() {
    auto csp = CryptoFramework::GetCspInstance(CspType::kCryptoProCsp);
    auto certs = csp->GetCertificates();
    if (certs.empty()) {
        std::cout << "No certificates found.\n";
        return 1;
    }
    auto cert = certs[0];
    Blob data = {0x00, 0x11, 0x22, 0x33}; // Example data

    auto signature = cert->SignCades(data, CadesType::kBes, true);  // Create a detached CAdES-BES signature
    if (csp->VerifyCadesDetached(signature, data, CadesType::kBes)) { // And verify it
        std::cout << "Signature verification successful.\n";
    } else {
        std::cout << "Signature verification failed.\n";
        return 1;
    }
    
    //Encryption Example
    auto encryptedData = cert->Encrypt(data);
    auto decryptedData = cert->Decrypt(encryptedData);
    if (data == decryptedData) {
        std::cout << "Encryption/Decryption successful.\n";
    } else {
        std::cout << "Encryption/Decryption failed.\n";
        return 1;
    }
    return 0;
}
```

You can find complete example in `apps/demo` folder.

## Language Bindings

This framework provides language bindings for Java, C#, and Python, generated using SWIG. These bindings are packaged as DLL files (shared libraries) located within the respective language directories. You can find the bindings and example code in the following locations:

- Python: langs/python

- Java: langs/java

- C#: langs/csharp

The DLL files for each language are located at `langs/<language>/swig_generated/<language>_cryptofw.dll` after build target for specific language.

# Documentation

The documentation for this framework is generated using Doxygen (complete API reference) and can be built using the docs CMake target. You can find it here: [https://danielreker.github.io/crypto-framework/index.html](https://danielreker.github.io/crypto-framework/index.html)