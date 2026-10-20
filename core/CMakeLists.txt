set(INAPPARENCY_CORE_SOURCES
    src/frame.cpp
    src/parser.cpp
    src/detector.cpp
    src/rules/deauth_burst.cpp
    src/rules/malformed_frames.cpp
)

# Inside an ESP-IDF build the core is pulled in as a regular component.
if(ESP_PLATFORM)
    idf_component_register(SRCS ${INAPPARENCY_CORE_SOURCES} INCLUDE_DIRS include)
    return()
endif()

add_library(inapparency_core STATIC ${INAPPARENCY_CORE_SOURCES})
add_library(inapparency::core ALIAS inapparency_core)
target_include_directories(inapparency_core PUBLIC include)
target_compile_features(inapparency_core PUBLIC cxx_std_20)
target_link_libraries(inapparency_core PRIVATE inapparency_warnings)
