#ifndef PRESIDIO_INPUT_H
#define PRESIDIO_INPUT_H

#include "esp_err.h"
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Result of an input sanitization check. */
typedef enum {
    PRESIDIO_INPUT_OK = 0,
    PRESIDIO_INPUT_NULL_PTR,
    PRESIDIO_INPUT_TOO_LONG,
    PRESIDIO_INPUT_TOO_SHORT,
    PRESIDIO_INPUT_INVALID_CHARS,
    PRESIDIO_INPUT_INJECTION_DETECTED,
} presidio_input_result_t;

/**
 * Validate and sanitize a Wi-Fi SSID.
 * Checks length (1..32), rejects null bytes and non-printable control chars.
 *
 * @param ssid  Null-terminated SSID string.
 * @return PRESIDIO_INPUT_OK if valid.
 */
presidio_input_result_t presidio_input_sanitize_ssid(const char *ssid);

/**
 * Validate and sanitize a Wi-Fi password.
 * Checks length (8..64), rejects null bytes and control characters.
 *
 * @param password  Null-terminated password string.
 * @return PRESIDIO_INPUT_OK if valid.
 */
presidio_input_result_t presidio_input_sanitize_wifi_password(const char *password);

/**
 * Validate and sanitize an MQTT topic string.
 * Rejects null bytes, control characters, and topic-level injection
 * (stacked wildcards, $SYS traversal without explicit permission).
 *
 * @param topic  Null-terminated topic string.
 * @return PRESIDIO_INPUT_OK if valid.
 */
presidio_input_result_t presidio_input_sanitize_mqtt_topic(const char *topic);

/**
 * Validate and sanitize an HTTP request body.
 * Checks for null bytes, excessive length, and basic script injection patterns.
 *
 * @param body    Pointer to body data.
 * @param length  Length in bytes.
 * @return PRESIDIO_INPUT_OK if valid.
 */
presidio_input_result_t presidio_input_sanitize_http_body(const char *body,
                                                          size_t length);

/**
 * Return a human-readable description of a sanitization result.
 */
const char *presidio_input_result_to_str(presidio_input_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* PRESIDIO_INPUT_H */
