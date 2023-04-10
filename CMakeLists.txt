cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 20)

set(UNICORN_ARCH                  "arm" CACHE STRING   "" FORCE)
set(UNICORN_INSTALL               FALSE CACHE BOOL     "" FORCE)
set(UNICORN_BUILD_TESTS           FALSE CACHE BOOL     "" FORCE)
set(BUILD_SHARED_LIBS             FALSE CACHE BOOL     "" FORCE)
add_subdirectory(dependencies/unicorn)

set(CAPSTONE_BUILD_CSTOOL         FALSE CACHE BOOL     "" FORCE)
set(CAPSTONE_BUILD_TESTS          FALSE CACHE BOOL     "" FORCE)
set(CAPSTONE_BUILD_SHARED         FALSE CACHE BOOL     "" FORCE)
add_subdirectory(dependencies/capstone)

project(preem-hle)
add_executable(${PROJECT_NAME}
    main.cc
    utils.cc
    disassembler.cc
    process.cc
    modules/modules.cc
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        -DPREEM_HLE_ROM_PATH="${PROJECT_SOURCE_DIR}/roms"
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        "dependencies/unicorn/include"
        "dependencies/capstone/include"
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        unicorn
        capstone-static
)
