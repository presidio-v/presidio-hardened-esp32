#ifndef PRESIDIO_TLS_H
#define PRESIDIO_TLS_H

#include "esp_err.h"
#include "mbedtls/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Apply Presidio-hardened settings to an mbedTLS SSL configuration.
 *
 * Enforces:
 *  - Minimum TLS 1.2 (or 1.3 if PRESIDIO_TLS_MIN_VERSION_13 is set)
 *  - Only AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)
 *  - Certificate verification required
 *  - No renegotiation
 *  - Strong signature algorithms only (SHA-256+)
 *
 * @param conf  Pointer to an already-initialized mbedtls_ssl_config.
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if conf is NULL.
 */
esp_err_t presidio_tls_apply_hardening(mbedtls_ssl_config *conf);

/**
 * Check whether a given cipher suite ID is allowed under Presidio policy.
 *
 * @param suite_id  mbedTLS cipher suite identifier.
 * @return true if the suite is permitted, false if it is blocked.
 */
bool presidio_tls_is_suite_allowed(int suite_id);

/**
 * Return a NULL-terminated list of Presidio-approved cipher suite IDs.
 * Suitable for passing to mbedtls_ssl_conf_ciphersuites().
 */
const int *presidio_tls_get_allowed_suites(void);

#ifdef __cplusplus
}
#endif

#endif /* PRESIDIO_TLS_H */
