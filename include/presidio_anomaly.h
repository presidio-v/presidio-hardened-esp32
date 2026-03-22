#ifndef PRESIDIO_ANOMALY_H
#define PRESIDIO_ANOMALY_H

#include "esp_err.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Anomaly event types detected by the runtime monitor. */
typedef enum {
    PRESIDIO_ANOMALY_AUTH_FAILURE = 0,
    PRESIDIO_ANOMALY_REPEATED_DISCONNECT,
    PRESIDIO_ANOMALY_OTA_TAMPER,
    PRESIDIO_ANOMALY_UNEXPECTED_REBOOT,
    PRESIDIO_ANOMALY_STACK_OVERFLOW,
    PRESIDIO_ANOMALY_HEAP_CORRUPTION,
    PRESIDIO_ANOMALY_TYPE_MAX
} presidio_anomaly_type_t;

/**
 * Callback invoked when an anomaly is detected.
 *
 * @param type   The anomaly category.
 * @param count  How many times this anomaly has been seen since last reset.
 * @param ctx    User-supplied context pointer.
 */
typedef void (*presidio_anomaly_handler_t)(presidio_anomaly_type_t type,
                                           uint32_t count,
                                           void *ctx);

/**
 * Initialize the anomaly detection subsystem.
 * Registers ESP event handlers for Wi-Fi, IP, and OTA events.
 *
 * @return ESP_OK on success.
 */
esp_err_t presidio_anomaly_init(void);

/**
 * Register a user callback for a specific anomaly type.
 *
 * @param type     The anomaly type to monitor.
 * @param handler  Callback function.
 * @param ctx      Opaque context forwarded to the handler.
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if type is out of range.
 */
esp_err_t presidio_anomaly_register_handler(presidio_anomaly_type_t type,
                                            presidio_anomaly_handler_t handler,
                                            void *ctx);

/**
 * Manually report an anomaly (for application-level detections).
 */
esp_err_t presidio_anomaly_report(presidio_anomaly_type_t type);

/**
 * Reset anomaly counters.
 */
void presidio_anomaly_reset_counters(void);

/**
 * Get the current count for a specific anomaly type.
 */
uint32_t presidio_anomaly_get_count(presidio_anomaly_type_t type);

/**
 * Tear down anomaly detection and unregister event handlers.
 */
void presidio_anomaly_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* PRESIDIO_ANOMALY_H */
