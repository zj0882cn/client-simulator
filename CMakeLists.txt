cmake_minimum_required(VERSION 3.16)
project(wow_client_simulator LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

# Platform-specific settings
if(WIN32)
    # Windows: link ws2_32 for sockets, no dl needed
    set(PLATFORM_LIBS ws2_32)
    add_definitions(-D_WIN32_WINNT=0x0601)
else()
    # Linux/Mac: link dl and pthread
    find_package(Threads REQUIRED)
    set(PLATFORM_LIBS Threads::Threads dl)
endif()

add_executable(wow_client
    main.cpp
    wow_auth.cpp
    wow_world.cpp
)

target_include_directories(wow_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(wow_client
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
        ${PLATFORM_LIBS}
)

# Compiler options
if(MSVC)
    target_compile_options(wow_client PRIVATE
        /W4
        /wd4100   # unreferenced formal parameter
        /wd4101   # unreferenced local variable
        /wd4267   # conversion, possible loss of data
        /wd4244   # conversion
        /wd4996   # deprecated functions
    )
else()
    target_compile_options(wow_client PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wno-unused-parameter
        -Wno-unused-variable
        -Wno-sign-compare
        -Wno-unused-function
    )
endif()

install(TARGETS wow_client RUNTIME DESTINATION bin)
