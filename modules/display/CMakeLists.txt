# Drawing and screen layouts for small monochrome displays. No hardware
# access in here: the platform adapter just copies the framebuffer out.

set(INAPPARENCY_DISPLAY_SOURCES src/font.cpp src/framebuffer.cpp src/screens.cpp)

if(ESP_PLATFORM)
    idf_component_register(SRCS ${INAPPARENCY_DISPLAY_SOURCES} INCLUDE_DIRS include REQUIRES core)
    return()
endif()

add_library(inapparency_display STATIC ${INAPPARENCY_DISPLAY_SOURCES})
add_library(inapparency::display ALIAS inapparency_display)
target_include_directories(inapparency_display PUBLIC include)
target_link_libraries(inapparency_display PUBLIC inapparency::core PRIVATE inapparency_warnings)
