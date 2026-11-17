cmake_minimum_required(VERSION 3.16)

project(lrs_demo_keygen LANGUAGES C CXX)

add_subdirectory(
    "${CMAKE_CURRENT_LIST_DIR}/../../cpp_backend"
    "${CMAKE_CURRENT_BINARY_DIR}/cpp_backend"
)

add_executable(lrs_keygen_cli keygen_cli.cpp)
target_link_libraries(lrs_keygen_cli PRIVATE lattice_lrs_backend)
target_compile_features(lrs_keygen_cli PRIVATE cxx_std_17)
