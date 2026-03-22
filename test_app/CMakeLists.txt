cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/..")

set(TEST_COMPONENTS "presidio-hardened-esp32" CACHE STRING "Components to test")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(presidio_test_app)
