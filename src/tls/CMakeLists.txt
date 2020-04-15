add_library(tls STATIC
    include/tls/tls.h
    include/tls/names.h
    include/tls/connection.h
    include/tls/buffer.h

    include/tls/data/alert.h
    include/tls/data/plaintext.h
    include/tls/data/handshake.h
    include/tls/data/asn1.h
    include/tls/data/handshakes/certificate.h
    include/tls/data/handshakes/client_hello.h
    include/tls/data/handshakes/server_hello.h
    include/tls/data/handshakes/client_key_exchange_rsa.h

    src/tls.cpp
    src/names.cpp
    src/connection.cpp
    src/buffer.cpp

    src/data/alert.cpp
    src/data/plaintext.cpp
    src/data/handshake.cpp
    src/data/asn1.cpp
    src/data/handshakes/certificate.cpp
    src/data/handshakes/client_hello.cpp
    src/data/handshakes/server_hello.cpp
    src/data/handshakes/client_key_exchange_rsa.cpp

    src/handle/initialize.cpp
    src/handle/client_hello.cpp
    src/handle/server_hello.cpp
    src/handle/certificate.cpp
    src/handle/server_hello_done.cpp)

target_include_directories(tls PUBLIC include)
target_link_libraries(tls PRIVATE encryption fmt)
