cmake_minimum_required(VERSION 3.28)
project(server_client_encryption C)

# Set the C standard
set(CMAKE_C_STANDARD 11)

# Include the current directory for header files
include_directories(${CMAKE_SOURCE_DIR})

# Add the socketAttribute.c file to a static library
add_library(SocketUtil STATIC socketAttribute.c)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Check if OpenSSL was found
if (OpenSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
else ()
    message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL and try again.")
endif ()

# Create the server executable and link with SocketUtil and OpenSSL
add_executable(server server.c)
target_link_libraries(server PRIVATE SocketUtil OpenSSL::SSL OpenSSL::Crypto)

# Create the client executable and link with SocketUtil and OpenSSL
add_executable(client client.c)
target_link_libraries(client PRIVATE SocketUtil OpenSSL::SSL OpenSSL::Crypto)

# Optionally, specify include directories for targets (more modern approach)
# target_include_directories(server PRIVATE ${OPENSSL_INCLUDE_DIR})
# target_include_directories(client PRIVATE ${OPENSSL_INCLUDE_DIR})
