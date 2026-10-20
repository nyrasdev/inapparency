# Rotating JSON-lines event log on top of a tiny file system interface.

if(ESP_PLATFORM)
    idf_component_register(SRCS src/event_log.cpp INCLUDE_DIRS include REQUIRES core serial vfs)
    return()
endif()

add_library(inapparency_storage STATIC src/event_log.cpp)
add_library(inapparency::storage ALIAS inapparency_storage)
target_include_directories(inapparency_storage PUBLIC include)
target_link_libraries(inapparency_storage PUBLIC inapparency::core inapparency::serial
    PRIVATE inapparency_warnings)
