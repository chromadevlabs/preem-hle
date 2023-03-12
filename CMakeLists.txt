cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 20)

set(UNICORN_ARCH                  "arm" CACHE STRING   "" FORCE) 
set(UNICORN_INSTALL               FALSE CACHE BOOL     "" FORCE)
set(UNICORN_BUILD_TESTS           FALSE CACHE BOOL     "" FORCE)
set(BUILD_SHARED_LIBS             FALSE CACHE BOOL     "" FORCE)
add_subdirectory(dependencies/unicorn)

set(BUILD_SHARED_LIBS             FALSE CACHE BOOL     "" FORCE)
set(CAPSTONE_BUILD_TESTS          FALSE CACHE BOOL     "" FORCE)
set(CAPSTONE_BUILD_CSTOOL         FALSE CACHE BOOL     "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF   CACHE BOOL     "" FORCE)
set(CAPSTONE_DEBUG                FALSE CACHE BOOL     "" FORCE)
set(CAPSTONE_INSTALL              FALSE CACHE BOOL     "" FORCE)
set(SUPPORTED_ARCHITECTURES       ""    CACHE STRING "" FORCE)
set(SUPPORTED_ARCHITECTURE_LABELS ""    CACHE STRING "" FORCE)
add_subdirectory(dependencies/capstone)

project(preem)
add_executable(${PROJECT_NAME} main.cc "pe.h" "utils.h")

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        unicorn
        capstone
)
