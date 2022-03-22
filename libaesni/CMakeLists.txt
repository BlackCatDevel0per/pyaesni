cmake_minimum_required(VERSION 3.14.7 FATAL_ERROR)
list(APPEND CMAKE_ASM_NASM_SOURCE_FILE_EXTENSIONS s)
project(libaesni LANGUAGES C ASM_NASM)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(BUILD_SHARED_LIBS "Whether to build a dynamic library" OFF)

include(cmake/PreventInSourceBuild.cmake)
prevent_in_source_build()

if (NOT "${CMAKE_ASM_NASM_COMPILER_ID}" MATCHES "YASM")
    message(FATAL_ERROR "-DCMAKE_ASM_NASM_ASM variable must point to a yasm assembler, currently points to: ${CMAKE_ASM_NASM_COMPILER_ID}")
endif ()

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_library(${PROJECT_NAME}_asm OBJECT asm/x64/iaesx64.s asm/x64/do_rdtsc.s)
elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
    add_library(${PROJECT_NAME}_asm OBJECT asm/x86/iaesx86.s asm/x86/do_rdtsc.s)
else ()
    message(FATAL_ERROR "Only x86 and x64 targets are currently supported")
endif ()


if (UNIX)
    target_compile_options(${PROJECT_NAME}_asm PRIVATE -D__linux__)
endif ()

add_library(${PROJECT_NAME} src/iaesni.c $<TARGET_OBJECTS:${PROJECT_NAME}_asm>)
add_library(IAESNI::aes ALIAS ${PROJECT_NAME})

include(GenerateExportHeader)
generate_export_header(${PROJECT_NAME})

include(GNUInstallDirs)
target_include_directories(${PROJECT_NAME}
        PUBLIC
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        )

set_property(TARGET ${PROJECT_NAME}
        PROPERTY PUBLIC_HEADER
        include/iaesni.h
        "${CMAKE_CURRENT_BINARY_DIR}/libaesni_export.h")

set_target_properties(${PROJECT_NAME} PROPERTIES
        EXPORT_NAME aes
        PREFIX ""
        )

install(TARGETS
        ${PROJECT_NAME}
        EXPORT IAESNIConfig)

export(TARGETS
        ${PROJECT_NAME}
        NAMESPACE IAESNI::
        FILE "${CMAKE_CURRENT_BINARY_DIR}/IAESNIConfig.cmake"
        )

install(EXPORT
        IAESNIConfig
        DESTINATION "${CMAKE_INSTALL_DATADIR}/cmake"
        NAMESPACE IAESNI::
        )


if (LIBAESNI_ENABLE_TESTS)
    add_executable(test EXCLUDE_FROM_ALL test/test_libaesni.c)
    target_link_libraries(test PRIVATE ${PROJECT_NAME})
endif ()
