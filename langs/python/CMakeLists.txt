# python для вызова в execute_process
find_program(PYTHON_EXECUTABLE
    NAMES python3 python3.11 python3.10 python3.9 python
    HINTS ENV PATH
)

# нахождение Python_INCLUDE_DIRS и Python_LIBRARIES, если их нет
if (PYTHON_EXECUTABLE)
    message(STATUS "Found Python executable: ${PYTHON_EXECUTABLE}")

    # Получаем путь к include-директории
    if (NOT DEFINED Python_INCLUDE_DIRS OR Python_INCLUDE_DIRS STREQUAL "")
        execute_process(
            COMMAND ${PYTHON_EXECUTABLE} -c "from distutils.sysconfig import get_python_inc; print(get_python_inc())"
            OUTPUT_VARIABLE Python_INCLUDE_DIRS
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if (Python_INCLUDE_DIRS)
            message(STATUS "Python Include Dirs detected: ${Python_INCLUDE_DIRS}")
        else()
            message(FATAL_ERROR "Failed to retrieve Python include directories")
        endif()
    else()
        message(STATUS "Using existing Python_INCLUDE_DIRS: ${Python_INCLUDE_DIRS}")
    endif()

    if (NOT DEFINED Python_LIBRARIES OR Python_LIBRARIES STREQUAL "")
        execute_process(
            COMMAND ${PYTHON_EXECUTABLE} -c "import sysconfig, os; lib_name = f'python{sysconfig.get_config_var('VERSION').replace('.', '')}.lib'; lib_dir = sysconfig.get_config_var('LIBDIR') or os.path.join(sysconfig.get_paths()['stdlib'], '..', 'libs'); print(os.path.join(lib_dir, lib_name))"
            OUTPUT_VARIABLE Python_LIBRARIES
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        
        if (NOT EXISTS ${Python_LIBRARIES})
            message(FATAL_ERROR "Python library not found: ${Python_LIBRARIES}")
        else()
            message(STATUS "Python library detected: ${Python_LIBRARIES}")
            set(Python_LIBRARIES ${Python_LIBRARIES} PARENT_SCOPE)
        endif()
    else()
        message(STATUS "Using existing Python_LIBRARIES: ${Python_LIBRARIES}")
    endif()

else()
    message(FATAL_ERROR "Python executable not found! Please ensure Python is installed and available in PATH.")
endif()


set(SWIG_INPUT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../cryptofw.i")
set(SWIG_MODULE_NAME "py_cryptofw")

set(SWIG_GENERATED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/swig_generated")
file(MAKE_DIRECTORY ${SWIG_GENERATED_DIR})

# Создаём модуль SWIG

# Надо установить PATH переменные
# SWIG_DIR = D:\SWIG
# SWIG_EXECUTABLE = D:\SWIG\swig.exe

set_source_files_properties(${SWIG_INPUT_FILE} PROPERTIES CPLUSPLUS ON)
set(CMAKE_SWIG_OUTDIR ${SWIG_GENERATED_DIR})

swig_add_library(${SWIG_MODULE_NAME}
    TYPE MODULE
    LANGUAGE python
    SOURCES ${SWIG_INPUT_FILE}
)

set_target_properties(${SWIG_MODULE_NAME} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${SWIG_GENERATED_DIR}
    LIBRARY_OUTPUT_DIRECTORY ${SWIG_GENERATED_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${SWIG_GENERATED_DIR}
    SWIG_GENERATED_FILE_DIR ${SWIG_GENERATED_DIR}
)

target_link_libraries(${SWIG_MODULE_NAME} PRIVATE cryptofw ${Python_LIBRARIES})

target_include_directories(${SWIG_MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${Python_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}
)
