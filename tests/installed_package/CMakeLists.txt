cmake_minimum_required(VERSION 3.18)

project(purify_installed_consumer LANGUAGES CXX)

find_package(purify CONFIG REQUIRED)

add_executable(purify_installed_consumer main.cpp)
target_link_libraries(purify_installed_consumer PRIVATE purify::purify)
target_compile_features(purify_installed_consumer PRIVATE cxx_std_20)

enable_testing()
add_test(NAME purify.installed.consumer COMMAND purify_installed_consumer)
