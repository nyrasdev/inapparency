idf_component_register(
    SRCS main.cpp
    REQUIRES core serial display storage espidf
    PRIV_REQUIRES nvs_flash esp_timer
)
