#ifndef PRESIDIO_BOOT_H
#define PRESIDIO_BOOT_H

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Boot security status flags. */
typedef struct {
    bool secure_boot_enabled;
    bool flash_encryption_enabled;
    bool jtag_disabled;
    bool uart_download_disabled;
} presidio_boot_status_t;

/**
 * Query the current boot security status from eFuse values.
 *
 * @param status  Receives the boot security flags.
 * @return ESP_OK on success.
 */
esp_err_t presidio_boot_get_status(presidio_boot_status_t *status);

/**
 * Verify boot security and log warnings for any disabled protections.
 * If PRESIDIO_BOOT_HALT_IF_INSECURE is set, aborts on failure.
 *
 * @return ESP_OK if all checks pass,
 *         ESP_ERR_INVALID_STATE if protections are missing.
 */
esp_err_t presidio_boot_verify(void);

/**
 * Return a human-readable string describing the boot security state.
 * The returned pointer is to a static buffer; do not free.
 */
const char *presidio_boot_status_str(void);

#ifdef __cplusplus
}
#endif

#endif /* PRESIDIO_BOOT_H */
