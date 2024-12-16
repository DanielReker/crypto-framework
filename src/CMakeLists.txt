file(GLOB PUBLIC_HEADER_LIST CONFIGURE_DEPENDS "${CryptoFramework_SOURCE_DIR}/include/cryptofw/*.hpp")
file(GLOB PRIVATE_HEADER_LIST CONFIGURE_DEPENDS "${CryptoFramework_SOURCE_DIR}/src/include/*.hpp")
file(GLOB SOURCE_LIST CONFIGURE_DEPENDS "${CryptoFramework_SOURCE_DIR}/src/*.cpp")

add_library(cryptofw ${PUBLIC_HEADER_LIST} ${PRIVATE_HEADER_LIST} ${SOURCE_LIST} "Utils.cpp")

target_include_directories(cryptofw PUBLIC "../include")
target_include_directories(cryptofw PRIVATE "./include")

target_link_libraries(cryptofw PRIVATE CryptoPro::cades)

target_compile_features(cryptofw PUBLIC cxx_std_11)

source_group(
	TREE "${PROJECT_SOURCE_DIR}/include"
	PREFIX "Public headers"
	FILES ${PUBLIC_HEADER_LIST}
)

source_group(
	TREE "${PROJECT_SOURCE_DIR}/src/include"
	PREFIX "Private headers"
	FILES ${PRIVATE_HEADER_LIST}
)
