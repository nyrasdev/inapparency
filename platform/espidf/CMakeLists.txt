# ESP-IDF radio adapter. Same code for every supported chip; differences
# get handled here with target checks when they show up on real hardware.
idf_component_register(
    SRCS src/capture.cpp
    INCLUDE_DIRS include
    REQUIRES core
    PRIV_REQUIRES esp_wifi esp_timer esp_event
)
