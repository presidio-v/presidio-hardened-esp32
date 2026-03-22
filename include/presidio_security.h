#ifndef PRESIDIO_SECURITY_H
#define PRESIDIO_SECURITY_H

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PRESIDIO_VERSION_MAJOR 0
#define PRESIDIO_VERSION_MINOR 1
#define PRESIDIO_VERSION_PATCH 0
#define PRESIDIO_VERSION_STRING "0.1.0"

/**
 * Initialize all enabled Presidio security extensions.
 *
 * Applies hardened defaults based on Kconfig settings:
 *  - mbedTLS hardening (strict ciphers, minimum TLS version)
 *  - NVS secret redaction
 *  - Secure boot / flash encryption verification
 *  - Anomaly detection event handlers
 *  - Security event logging subsystem
 *
 * Call once from app_main() before any network or storage operations.
 *
 * @return ESP_OK on success, or an error code if a critical subsystem fails.
 */
esp_err_t presidio_security_init(void);

/**
 * Return a human-readable summary of active security features.
 * The returned string is statically allocated and must not be freed.
 */
const char *presidio_security_status(void);

/**
 * Tear down Presidio security extensions and free resources.
 */
void presidio_security_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* PRESIDIO_SECURITY_H */
