add_subdirectory(encryption)
add_subdirectory(sockets)
add_subdirectory(tls)

add_executable(shadetest main.cpp)
target_link_libraries(shadetest PUBLIC sockets tls encryption fmt)
