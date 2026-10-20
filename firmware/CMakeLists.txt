cmake_minimum_required(VERSION 3.16)

# The portable code lives outside this folder and is pulled in as components.
set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../core
    ${CMAKE_CURRENT_LIST_DIR}/../modules/serial
    ${CMAKE_CURRENT_LIST_DIR}/../modules/display
    ${CMAKE_CURRENT_LIST_DIR}/../modules/storage
    ${CMAKE_CURRENT_LIST_DIR}/../platform/espidf
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(inapparency)
