add_library(encryption STATIC
    include/encryption/int.h
    include/encryption/sha.h
    include/encryption/rsa.h

    src/sha.cpp
    src/rsa.cpp)

target_include_directories(encryption PUBLIC include)
