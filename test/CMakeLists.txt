idf_component_register(
    SRC_DIRS "."
    INCLUDE_DIRS "."
    REQUIRES unity presidio-hardened-esp32 nvs_flash
    WHOLE_ARCHIVE
)
