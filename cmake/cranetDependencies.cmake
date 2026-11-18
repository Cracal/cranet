include(ExternalProject)

set(CRANET_EXTERNAL_SOURCE_DIR "${PROJECT_SOURCE_DIR}/external")
set(CRANET_EXTERNAL_BUILD_DIR "${CMAKE_BINARY_DIR}/external")
set(CRANET_EXTERNAL_INSTALL_DIR "${CMAKE_BINARY_DIR}/external/install")

list(APPEND CMAKE_PREFIX_PATH "${CRANET_EXTERNAL_INSTALL_DIR}")

message(STATUS "external source dir  = [${CRANET_EXTERNAL_SOURCE_DIR}]")
message(STATUS "external build dir   = [${CRANET_EXTERNAL_BUILD_DIR}]")
message(STATUS "external install dir = [${CRANET_EXTERNAL_INSTALL_DIR}]")

function(cranet_install_lib lib_name)
    set(SOURCE_DIR "${CRANET_EXTERNAL_SOURCE_DIR}/${lib_name}")
    set(BUILD_DIR "${CRANET_EXTERNAL_BUILD_DIR}/${lib_name}")
    set(INSTALL_DIR "${CRANET_EXTERNAL_INSTALL_DIR}/${lib_name}")
    set(CONFIG_FILE "${INSTALL_DIR}/lib/cmake/${lib_name}/${lib_name}Config.cmake")

    if (NOT EXISTS "${CONFIG_FILE}")
        message(STATUS "${lib_name}: building and installing...")

        execute_process(
            COMMAND ${CMAKE_COMMAND}
                -S "${SOURCE_DIR}"
                -B "${BUILD_DIR}"
                "-DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}"
                "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
                ${ARGN}
            RESULT_VARIABLE cfg_result
            OUTPUT_VARIABLE cfg_output
            ERROR_VARIABLE  cfg_error
        )
        if (NOT cfg_result EQUAL 0)
            message(FATAL_ERROR "${lib_name}: configure failed: ${cfg_output} ${cfg_error}")
        endif()

        execute_process(
            COMMAND ${CMAKE_COMMAND} --build "${BUILD_DIR}" --target install --parallel
            RESULT_VARIABLE build_result
            OUTPUT_VARIABLE build_output
            ERROR_VARIABLE  build_error
        )
        if (NOT build_result EQUAL 0)
            message(FATAL_ERROR "${lib_name}: build/install failed: ${build_output} ${build_error}")
        endif()

        if (NOT EXISTS "${CONFIG_FILE}")
            message(FATAL_ERROR "${lib_name}: install failed. ${CONFIG_FILE} not found.")
        endif()
    endif()
endfunction()


# Install crabase
cranet_install_lib(crabase
    "-DCRABASE_BUILD_SHARED_LIBS=OFF"
    "-DCRABASE_BUILD_TESTS=OFF"
)
