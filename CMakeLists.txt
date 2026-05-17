cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD            20)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
set(CMAKE_COLOR_DIAGNOSTICS       ON)

set(UNICORN_ARCH                  "arm" CACHE STRING   "" FORCE)
set(UNICORN_INSTALL               FALSE CACHE BOOL     "" FORCE)
set(UNICORN_BUILD_TESTS           FALSE CACHE BOOL     "" FORCE)
set(BUILD_SHARED_LIBS             FALSE CACHE BOOL     "" FORCE)
add_subdirectory(dependencies/unicorn)

set(CAPSTONE_BUILD_CSTOOL         FALSE CACHE BOOL     "" FORCE)
set(CAPSTONE_BUILD_TESTS          FALSE CACHE BOOL     "" FORCE)
set(CAPSTONE_BUILD_SHARED         FALSE CACHE BOOL     "" FORCE)
add_subdirectory(dependencies/capstone)

add_subdirectory(dependencies/glfw)

project(preem-hle)
add_executable(${PROJECT_NAME}
    main.cc
    utils.cc
    disassembler.cc
    process.cc

    winapi_impl.cc
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        -DPREEM_HLE_ROM_PATH="${PROJECT_SOURCE_DIR}/roms"
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        "dependencies/unicorn/include"
        "dependencies/capstone/include"
        "dependencies/glad-4.1/include"
)

#target_compile_options(${PROJECT_NAME}
#    PRIVATE
#        "-fsanitize=address"
#)
#
#target_link_options(${PROJECT_NAME}
#    PRIVATE
#        "-fsanitize=address"
#)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        unicorn
        capstone
        glfw
)
