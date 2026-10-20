# Formats events and status lines as text or JSON. No IO of its own, so the
# firmware, the replay tool and tests all share it.

if(ESP_PLATFORM)
    idf_component_register(SRCS src/format.cpp INCLUDE_DIRS include REQUIRES core)
    return()
endif()

add_library(inapparency_serial STATIC src/format.cpp)
add_library(inapparency::serial ALIAS inapparency_serial)
target_include_directories(inapparency_serial PUBLIC include)
target_link_libraries(inapparency_serial PUBLIC inapparency::core PRIVATE inapparency_warnings)
