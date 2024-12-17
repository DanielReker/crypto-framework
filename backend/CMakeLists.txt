add_library(cryptofw-backend "cryptofw-backend.cpp" "include/cryptofw-backend.h")

target_include_directories(cryptofw-backend PUBLIC "./include")

target_link_libraries(cryptofw-backend PRIVATE CryptoPro::cades)

target_compile_features(cryptofw-backend PRIVATE cxx_std_14)

source_group(
	TREE "${PROJECT_SOURCE_DIR}/backend/include"
	PREFIX "Backend headers"
	FILES "include/cryptofw-backend.h"
)
