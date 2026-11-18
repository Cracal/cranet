
cmake_minimum_required(VERSION 3.22.0)
project(cranet VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD_REQUIRED ON)
message(STATUS "c standard: ${CMAKE_C_STANDARD}")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Configuration types: ${CMAKE_CONFIGURATION_TYPES}")


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

foreach(cfg DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${cfg} ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${cfg} ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${cfg} ${CMAKE_BINARY_DIR}/lib)
endforeach()


include(cmake/cranetOptions.cmake)
include(cmake/cranetDependencies.cmake)

option(CRANET_BUILD_TESTS "Build tests" ON)
if(CRANET_BUILD_TESTS)
    include(CTest)
    enable_testing()
    add_subdirectory(tests)
endif()


find_package(crabase REQUIRED)

file(GLOB_RECURSE CRANET_SRC CONFIGURE_DEPENDS src/*.c)
file(GLOB_RECURSE CRANET_INC CONFIGURE_DEPENDS inc/*.h)

option(CRANET_BUILD_SHARED_LIBS "Build shared library" ON)
if(CRANET_BUILD_SHARED_LIBS)
    add_library(cranet SHARED ${CRANET_SRC} ${CRANET_INC})
    target_compile_definitions(cranet PRIVATE CRANET_EXPORT)
else()
    add_library(cranet STATIC ${CRANET_SRC} ${CRANET_INC})
    target_compile_definitions(cranet PUBLIC CRANET_STATIC)
endif()

add_library(cranet::cranet ALIAS cranet)

target_link_libraries(cranet PRIVATE cranet_options crabase::crabase)


target_include_directories(cranet
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
        $<INSTALL_INTERFACE:inc>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cranetConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/cranetConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cranet
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/cranetConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(TARGETS cranet cranet_options
    EXPORT cranetTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/inc/
    DESTINATION inc
    FILES_MATCHING PATTERN "*.h"
)

install(EXPORT cranetTargets
    FILE cranetTargets.cmake
    NAMESPACE cranet::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cranet
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/cranetConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/cranetConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cranet
)
