set(srcs
    "src/presidio_security.c"
    "src/presidio_tls.c"
    "src/presidio_nvs.c"
    "src/presidio_boot.c"
    "src/presidio_anomaly.c"
    "src/presidio_input.c"
    "src/presidio_log.c"
)

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES log mbedtls
    PRIV_REQUIRES nvs_flash bootloader_support efuse esp_event app_update spi_flash esp_timer
)
