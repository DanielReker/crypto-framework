find_package(SWIG REQUIRED)
include(${SWIG_USE_FILE})

# TODO: надо чтобы само находило, но пока пусть будет так
set(Python_INCLUDE_DIRS C:/ProgramData/anaconda3/include)
set(Python_LIBRARIES C:/ProgramData/anaconda3/libs/python312.lib)

find_package(Python3 REQUIRED)

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
