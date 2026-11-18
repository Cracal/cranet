add_library(cranet_options INTERFACE)

if(CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    set(CRANET_MSVC_OPTIONS /W4 /WX /utf-8 /std:c11)
else()
    set(CRANET_GNU_OPTIONS -Wall -Werror -Wextra -pedantic -fvisibility=hidden)
endif()
target_compile_options(cranet_options INTERFACE
    ${CRANET_MSVC_OPTIONS}
    ${CRANET_GNU_OPTIONS}
)

target_compile_definitions(cranet_options INTERFACE
    $<$<AND:$<PLATFORM_ID:Linux>,$<OR:$<C_COMPILER_ID:GNU>,$<C_COMPILER_ID:Clang>>>:
        _POSIX_C_SOURCE=200809L
        _GNU_SOURCE
    >
)
