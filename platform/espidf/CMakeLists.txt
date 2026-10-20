# ESP-IDF adapter. The radio capture is always built; the display and SD
# card drivers only when they're switched on in menuconfig.
#
# Component dependencies are resolved before menuconfig values are known, so
# they're always listed. Driver code that isn't compiled in never reaches the
# binary.
set(srcs src/capture.cpp)
if(CONFIG_INAPPARENCY_DISPLAY)
    list(APPEND srcs src/oled.cpp)
endif()
if(CONFIG_INAPPARENCY_STORAGE)
    list(APPEND srcs src/sdcard.cpp)
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS include
    REQUIRES core display
    PRIV_REQUIRES esp_wifi esp_timer esp_event esp_driver_i2c fatfs esp_driver_sdspi
                  esp_driver_spi sdmmc
)
