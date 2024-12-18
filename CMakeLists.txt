cmake_minimum_required (VERSION 3.16)

option(BUILD_CRYPTOFW "Build CryptoFramework" ON)
option(BUILD_APPS "Build demo apps" ON)
option(BUILD_PYTHON "Build Python bindings" ON)
option(BUILD_JAVA "Build Java bindings" ON)
option(BUILD_CSHARP "Build C# bindings" ON)
option(BUILD_DOCS "Build docs" ON)



# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
	cmake_policy(SET CMP0141 NEW)
	set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project (CryptoFramework)

if (BUILD_CRYPTOFW OR BUILD_APPS)
	list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
	find_package(CryptoPro COMPONENTS cades)
	add_subdirectory(src)
	add_subdirectory(backend)
endif()


# If this is main project
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
	set(CMAKE_CXX_EXTENSIONS OFF)
	set_property(GLOBAL PROPERTY USE_FOLDERS ON)

	if (BUILD_DOCS)
		find_package(Doxygen)
		if(Doxygen_FOUND)
			add_subdirectory(docs)
		else()
			message(STATUS "Doxygen not found, not building docs")
		endif()
	endif()


	if (BUILD_APPS)
		add_subdirectory(apps/demo)
		add_subdirectory(apps/backend-demo)
	endif()

	if (BUILD_PYTHON OR BUILD_JAVA OR BUILD_CSHARP)
		find_package(SWIG)
		if (SWIG_FOUND)
			include(${SWIG_USE_FILE})

			if (BUILD_PYTHON)
				find_package(Python3)
				if (Python3_FOUND)
					add_subdirectory(langs/python)
				else()
					message(STATUS "Python3 not found, not building Python bindings")
				endif()
			endif()

			if (BUILD_JAVA)
				find_package(JNI)
				if (JNI_FOUND)
					add_subdirectory(langs/java)
				else()
					message(STATUS "JNI not found, not building Java bindings")
				endif()
			endif()

			if (BUILD_CSHARP)
				add_subdirectory(langs/csharp)
			endif()
		else()
			message(STATUS "SWIG not found, not building bindings")
		endif()
	endif()
endif()
