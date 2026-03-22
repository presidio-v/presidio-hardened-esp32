#ifndef PRESIDIO_LOG_H
#define PRESIDIO_LOG_H

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Severity levels for security events. */
typedef enum {
    PRESIDIO_SEV_INFO = 0,
    PRESIDIO_SEV_WARNING,
    PRESIDIO_SEV_ALERT,
    PRESIDIO_SEV_CRITICAL,
} presidio_severity_t;

/** Structured security event record. */
typedef struct {
    uint32_t            timestamp_ms;
    presidio_severity_t severity;
    const char         *module;
    const char         *message;
} presidio_security_event_t;

/**
 * Callback for security event notifications.
 */
typedef void (*presidio_log_handler_t)(const presidio_security_event_t *event,
                                       void *ctx);

/**
 * Initialize the security event logging subsystem.
 * Allocates the ring buffer for recent events.
 *
 * @return ESP_OK on success.
 */
esp_err_t presidio_log_init(void);

/**
 * Log a security event. The event is stored in the ring buffer
 * and forwarded to any registered handler.
 *
 * @param severity  Event severity.
 * @param module    Module name (e.g. "TLS", "NVS", "BOOT").
 * @param message   Human-readable description.
 * @return ESP_OK on success.
 */
esp_err_t presidio_log_event(presidio_severity_t severity,
                             const char *module,
                             const char *message);

/**
 * Register a callback for real-time security event notifications.
 *
 * @param handler  Callback function.
 * @param ctx      Opaque context forwarded to the handler.
 * @return ESP_OK on success.
 */
esp_err_t presidio_log_register_handler(presidio_log_handler_t handler,
                                        void *ctx);

/**
 * Retrieve the most recent N events from the ring buffer.
 *
 * @param out_events  Caller-allocated array.
 * @param max_events  Array capacity.
 * @return Number of events copied (may be less than max_events).
 */
int presidio_log_get_recent(presidio_security_event_t *out_events,
                            int max_events);

/**
 * Get the total number of security events logged since init.
 */
uint32_t presidio_log_get_total_count(void);

/**
 * Tear down the logging subsystem and free the ring buffer.
 */
void presidio_log_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* PRESIDIO_LOG_H */
