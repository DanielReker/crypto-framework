file(GLOB HEADER_LIST CONFIGURE_DEPENDS "${ModernCMakeExample_SOURCE_DIR}/include/modern/*.hpp")

add_library(cryptofw ${HEADER_LIST} "CryptoProCsp.cpp" "CryptoProCertificate.cpp" "utils.cpp" "VipNetCsp.cpp" "VipNetCertificate.cpp")

target_include_directories(cryptofw PUBLIC ../include)

target_link_libraries(cryptofw PRIVATE CryptoPro::cades CryptoPro::xades)

target_compile_features(cryptofw PUBLIC cxx_std_11)

source_group(
	TREE "${PROJECT_SOURCE_DIR}/include"
	PREFIX "Header Files"
	FILES ${HEADER_LIST}
)
