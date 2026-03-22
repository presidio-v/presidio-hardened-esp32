#ifndef PRESIDIO_NVS_H
#define PRESIDIO_NVS_H

#include "esp_err.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque handle for a Presidio-managed NVS namespace. */
typedef struct presidio_nvs_handle *presidio_nvs_handle_t;

/**
 * Open an NVS namespace with Presidio security wrappers.
 *
 * All subsequent operations through this handle automatically redact
 * secret values in log output and validate inputs.
 *
 * @param namespace_name  NVS namespace (max 15 chars).
 * @param out_handle      Receives the opened handle.
 * @return ESP_OK on success.
 */
esp_err_t presidio_nvs_open(const char *namespace_name,
                            presidio_nvs_handle_t *out_handle);

/**
 * Store a string value. Secret keys are redacted in log output.
 */
esp_err_t presidio_nvs_set_str(presidio_nvs_handle_t handle,
                               const char *key, const char *value);

/**
 * Read a string value. Allocates buffer; caller must free with free().
 */
esp_err_t presidio_nvs_get_str(presidio_nvs_handle_t handle,
                               const char *key, char **out_value);

/**
 * Store a binary blob. Secret keys are redacted in log output.
 */
esp_err_t presidio_nvs_set_blob(presidio_nvs_handle_t handle,
                                const char *key,
                                const void *value, size_t length);

/**
 * Read a binary blob. Allocates buffer; caller must free with free().
 */
esp_err_t presidio_nvs_get_blob(presidio_nvs_handle_t handle,
                                const char *key,
                                void **out_value, size_t *out_length);

/**
 * Erase a key from the namespace.
 */
esp_err_t presidio_nvs_erase_key(presidio_nvs_handle_t handle,
                                 const char *key);

/**
 * Commit pending writes and close the handle.
 */
esp_err_t presidio_nvs_close(presidio_nvs_handle_t handle);

/**
 * Check whether a key name matches a secret pattern
 * (password, key, token, secret, credential, etc.).
 */
bool presidio_nvs_is_secret_key(const char *key);

#ifdef __cplusplus
}
#endif

#endif /* PRESIDIO_NVS_H */
