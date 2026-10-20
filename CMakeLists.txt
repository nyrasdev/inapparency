cmake_minimum_required(VERSION 3.20)

project(inapparency VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(INAPPARENCY_BUILD_TESTS "Build the host test suite" ${PROJECT_IS_TOP_LEVEL})
option(INAPPARENCY_WERROR "Treat warnings as errors" OFF)
option(INAPPARENCY_SANITIZE "Build with AddressSanitizer and UBSan" OFF)

add_library(inapparency_warnings INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(inapparency_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
        -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
        $<$<BOOL:${INAPPARENCY_WERROR}>:-Werror>)
endif()

if(INAPPARENCY_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    add_link_options(-fsanitize=address,undefined)
endif()

add_subdirectory(core)

if(INAPPARENCY_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
