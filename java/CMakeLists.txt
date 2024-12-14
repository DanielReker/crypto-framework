# find_package(SWIG REQUIRED)
# include(${SWIG_USE_FILE})

# # TODO: надо чтобы само находило, но пока пусть будет так
# set(Python_INCLUDE_DIRS C:/ProgramData/anaconda3/include)
# set(Python_LIBRARIES C:/ProgramData/anaconda3/libs/python312.lib)

# find_package(Python3 REQUIRED)

# set(SWIG_INPUT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cryptofw.i")
# set(SWIG_MODULE_NAME "py_cryptofw")

# set(SWIG_GENERATED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/swig_generated")
# file(MAKE_DIRECTORY ${SWIG_GENERATED_DIR})

# # Создаём модуль SWIG

# # Надо установить PATH переменные
# # SWIG_DIR = D:\SWIG
# # SWIG_EXECUTABLE = D:\SWIG\swig.exe

# set_source_files_properties(${SWIG_INPUT_FILE} PROPERTIES CPLUSPLUS ON)
# set(CMAKE_SWIG_OUTDIR ${SWIG_GENERATED_DIR})

# swig_add_library(${SWIG_MODULE_NAME}
#     TYPE MODULE
#     LANGUAGE python
#     SOURCES ${SWIG_INPUT_FILE}
# )

# set_target_properties(${SWIG_MODULE_NAME} PROPERTIES
#     ARCHIVE_OUTPUT_DIRECTORY ${SWIG_GENERATED_DIR}
#     LIBRARY_OUTPUT_DIRECTORY ${SWIG_GENERATED_DIR}
#     RUNTIME_OUTPUT_DIRECTORY ${SWIG_GENERATED_DIR}
#     SWIG_GENERATED_FILE_DIR ${SWIG_GENERATED_DIR}
# )

# target_link_libraries(${SWIG_MODULE_NAME} PRIVATE cryptofw ${Python_LIBRARIES})

# target_include_directories(${SWIG_MODULE_NAME} PRIVATE
#     ${CMAKE_CURRENT_SOURCE_DIR}
#     ${Python_INCLUDE_DIRS}
#     ${CMAKE_SOURCE_DIR}
# )




find_package(SWIG REQUIRED)
include(${SWIG_USE_FILE})

set(JAVA_HOME "C:/Program Files/Java/jdk-21")
include_directories(${JAVA_HOME}/include)
include_directories(${JAVA_HOME}/include/win32)

find_package(Java REQUIRED)

set(SWIG_INPUT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cryptofw.i")
set(SWIG_MODULE_NAME "java_cryptofw")

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
    LANGUAGE java
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
    ${JAVA_HOME}/include
    ${CMAKE_SOURCE_DIR}
)





# find_package(SWIG REQUIRED)
# include(${SWIG_USE_FILE})

# # Укажите путь к Java Development Kit (JDK), если не установлен по умолчанию
# set(JAVA_HOME "C:/Program Files/Java/jdk-21")
# include_directories(${JAVA_HOME}/include)
# include_directories(${JAVA_HOME}/include/win32)

# find_package(Java REQUIRED)

# set(SWIG_INPUT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cryptofw.i")
# set(SWIG_MODULE_NAME "java_cryptofw")

# set(SWIG_GENERATED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/swig_generated")
# file(MAKE_DIRECTORY ${SWIG_GENERATED_DIR})

# # Указываем директорию для Java-обёрток
# set(CMAKE_SWIG_OUTDIR ${SWIG_GENERATED_DIR})

# # Создаем SWIG библиотеку
# set_source_files_properties(${SWIG_INPUT_FILE} PROPERTIES CPLUSPLUS ON)

# # Генерируем код для Java
# swig_add_library(${SWIG_MODULE_NAME}
#     TYPE SHARED
#     LANGUAGE java
#     SOURCES ${SWIG_INPUT_FILE}
# )

# # Связываем созданную библиотеку с cryptofw и Java
# set_target_properties(${SWIG_MODULE_NAME} PROPERTIES
#     LIBRARY_OUTPUT_DIRECTORY ${SWIG_GENERATED_DIR}
#     SWIG_GENERATED_FILE_DIR ${SWIG_GENERATED_DIR}
# )

# # Включаем директорию, где находится cryptofw (при необходимости)
# target_include_directories(${SWIG_MODULE_NAME} PRIVATE
#     ${CMAKE_CURRENT_SOURCE_DIR}
#     ${CMAKE_SOURCE_DIR}
# )

# # Компилируем библиотеку cryptofw для связывания с Java
# target_link_libraries(${SWIG_MODULE_NAME} PRIVATE cryptofw)

# # Если используется Java, указываем путь к JDK
# if(JAVA_FOUND)
#     target_include_directories(${SWIG_MODULE_NAME} PRIVATE ${JAVA_INCLUDE_PATH} ${JAVA_INCLUDE_PATH2})
#     target_link_libraries(${SWIG_MODULE_NAME} PRIVATE ${JAVA_JVM_LIBRARY})
# endif()