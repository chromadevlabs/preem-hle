cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 20)

add_subdirectory(dependencies/unicorn)
add_subdirectory(dependencies/capstone)

project(preem)
add_executable(${PROJECT_NAME} main.cc)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        unicorn
        capstone
)
