# Cryptographic Framework

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

### Installation
This project uses CMake. Follow these steps to install and build application:
```powershell
git clone https://github.com/DanielReker/crypto-framework.git
cd crypto-framework
cmake . -B build/
cd build
cmake --build . --config Release # or --config Debug
```

### Build demo app
```powershell
cmake --build . --target demo --config Release
apps/demo/Release/demo.exe # run a demo app to verify an installation
```

### Usage
```c++
#include <iostream>
#include <cryptofw/ICsp.hpp>
#include <cryptofw/ICertificate.hpp>
#include <cryptofw/Utils.hpp>

int main() {
    auto csp = Utils::GetCryptoProCsp(); // Or Utils::GetVipNetCsp()
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

## Language Bindings

This framework provides language bindings for Java, C#, and Python, generated using SWIG. These bindings are packaged as DLL files (shared libraries) located within the respective language directories. You can find the bindings and example code in the following locations:

- Python: langs/python

- Java: langs/java

- C#: langs/csharp

The DLL files for each language are located at `langs/<language>/swig_generated/<language>_cryptofw.dll` after build target for specific language.

### Python

The Python bindings are provided as a py_cryptofw.pyd built by SWIG from the `py_cryptofw` CMake target. 

<font size="6"> ***TODO: here is python example from test file, or without it*** </font>

### Java

The Java bindings are provided as a java_cryptofw.dll built by SWIG from the `java_cryptofw` CMake target. 

<font size="6"> ***TODO: here is python example from test file, or without it*** </font>

### C#

The C# bindings are provided as a csharp_cryptofw.pyd built by SWIG from the `csharp_cryptofw` CMake target. 

<font size="6"> ***TODO: here is python example from test file, or without it*** </font>

# Documentation

The documentation for this framework is generated using Doxygen and can be built using the docs CMake target. You'll need to have Doxygen installed on your system to build the documentation.