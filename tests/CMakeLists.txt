cmake_minimum_required(VERSION 3.22.0)

# set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR})

set(LIBS ${LIBS} ${PROJECT_NAME})

add_executable(test_server test_server.c)
target_link_libraries(test_server ${LIBS})
add_executable(test_client test_client.c)
target_link_libraries(test_client ${LIBS})

add_executable(example_echo_server example_echo_server.c)
target_link_libraries(example_echo_server ${LIBS})
add_executable(example_client example_client.c)
target_link_libraries(example_client ${LIBS})
add_executable(example_chat_server example_chat_server.c)
target_link_libraries(example_chat_server ${LIBS})

set(KCP_SRC test_kcp/kcp/ikcp.c test_kcp/kcp_transport.c)
add_executable(test_kcp_server test_kcp/server.c ${KCP_SRC})
target_link_libraries(test_kcp_server ${LIBS})
add_executable(test_kcp_client test_kcp/client.c ${KCP_SRC})
target_link_libraries(test_kcp_client ${LIBS})

find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    set(TLS_SRC test_tls/tls_transport.c)
    add_executable(test_tls_server test_tls/server.c ${TLS_SRC})
    target_link_libraries(test_tls_server ${LIBS} OpenSSL::SSL OpenSSL::Crypto)
    add_executable(test_tls_client test_tls/client.c ${TLS_SRC})
    target_link_libraries(test_tls_client ${LIBS} OpenSSL::SSL OpenSSL::Crypto)
else()
    message(STATUS "OpenSSL Not Found, skip test_tls.")
endif()
