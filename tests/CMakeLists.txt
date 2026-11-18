find_package(crabase REQUIRED)

set(LIBS cranet crabase::crabase)

add_executable(test_socket test_socket.c)
target_link_libraries(test_socket PRIVATE ${LIBS})
