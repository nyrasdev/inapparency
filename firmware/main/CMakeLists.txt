idf_component_register(
    SRCS main.cpp
    REQUIRES core serial espidf
    PRIV_REQUIRES nvs_flash esp_timer
)
