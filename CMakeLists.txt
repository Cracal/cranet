cmake_minimum_required(VERSION 3.22.0)
project(cranet VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED true)

if(MSVC)
    add_compile_options(/utf-8)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(
        -Wall -Wextra
        -pedantic
        -Werror

        -Wno-cast-function-type
    )
    add_compile_options(-fvisibility=hidden)
    if (MINGW)
        add_compile_options(-fexec-charset=UTF-8 -finput-charset=UTF-8)
    endif()
endif()

add_library(mem_detect_config INTERFACE)
target_compile_definitions(mem_detect_config INTERFACE
    $<$<CONFIG:Debug>:CRA_MEMORY_LEAK_DETECTOR>
)

add_definitions(-DCRA_LOG_FILE_LINE)
add_definitions(-DCRA_WITH_MY_ASSERT)

include_directories(inc)
include_directories(../crabase/inc)

set(SRC
    src/cra_common.c
    src/cra_socket.c
    src/cra_loop.c
    src/cra_poller_poll.c
    src/cra_poller_epoll.c
    src/cra_trans_default.c
    src/cra_conntimer.c
    src/cra_conn.c
    src/cra_server.c
    src/cra_client.c
)

find_library(LIBCRABASE crabase lib)
set(LIBS ${LIBCRABASE} mem_detect_config)
if(WIN32)
    set(LIBS ${LIBS} ws2_32)
    # option(CRA_WITH_TIME_PERIOD "WIN: with time[Begin|End]Period()" ON)
    # if (CRA_WITH_TIME_PERIOD)
    #     add_definitions(-DCRA_WITH_TIME_PERIOD)
    #     set(LIBS ${LIBS} winmm) # for time[Begin&end]Period()
    # endif()
endif()

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/tests)

add_library(${PROJECT_NAME} SHARED ${SRC})
target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBS})
target_compile_definitions(${PROJECT_NAME} PRIVATE CRA_NET_BUILD_DLL)

include(CTest)
enable_testing()

add_subdirectory(tests)
