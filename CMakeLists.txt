cmake_minimum_required (VERSION 3.16)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
	cmake_policy(SET CMP0141 NEW)
	set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project (CryptoFramework)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(CryptoPro COMPONENTS cades)

add_subdirectory(src)
add_subdirectory(backend)

# If this is main project
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
	set(CMAKE_CXX_EXTENSIONS OFF)
	set_property(GLOBAL PROPERTY USE_FOLDERS ON)

	find_package(Doxygen)
	if(Doxygen_FOUND)
		add_subdirectory(docs)
	else()
		message(STATUS "Doxygen not found, not building docs")
	endif()


	add_subdirectory(apps/demo)
	add_subdirectory(apps/backend-demo)

	find_package(SWIG)
	if (SWIG_FOUND)
		include(${SWIG_USE_FILE})

		find_package(Python3)
		if (Python3_FOUND)
			add_subdirectory(langs/python)
		else()
			message(STATUS "Python3 not found, not building Python bindings")
		endif()

		find_package(JNI)
		if (JNI_FOUND)
			add_subdirectory(langs/java)
		else()
			message(STATUS "JNI not found, not building Java bindings")
		endif()

		add_subdirectory(langs/csharp)
	else()
		message(STATUS "SWIG not found, not building bindings")
	endif()
endif()
