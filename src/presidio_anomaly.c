#include "presidio_anomaly.h"
#include "presidio_log.h"
#include "esp_log.h"
#include "esp_event.h"

#include <string.h>

static const char *TAG = "presidio_anomaly";

#ifdef CONFIG_PRESIDIO_ANOMALY_MAX_AUTH_FAILURES
#define MAX_AUTH_FAILURES CONFIG_PRESIDIO_ANOMALY_MAX_AUTH_FAILURES
#else
#define MAX_AUTH_FAILURES 5
#endif

typedef struct {
    presidio_anomaly_handler_t handler;
    void                      *ctx;
} handler_entry_t;

static uint32_t      s_counters[PRESIDIO_ANOMALY_TYPE_MAX];
static handler_entry_t s_handlers[PRESIDIO_ANOMALY_TYPE_MAX];
static bool          s_inited = false;

static const char *anomaly_name(presidio_anomaly_type_t type)
{
    switch (type) {
    case PRESIDIO_ANOMALY_AUTH_FAILURE:        return "AUTH_FAILURE";
    case PRESIDIO_ANOMALY_REPEATED_DISCONNECT: return "REPEATED_DISCONNECT";
    case PRESIDIO_ANOMALY_OTA_TAMPER:          return "OTA_TAMPER";
    case PRESIDIO_ANOMALY_UNEXPECTED_REBOOT:   return "UNEXPECTED_REBOOT";
    case PRESIDIO_ANOMALY_STACK_OVERFLOW:      return "STACK_OVERFLOW";
    case PRESIDIO_ANOMALY_HEAP_CORRUPTION:     return "HEAP_CORRUPTION";
    default:                                   return "UNKNOWN";
    }
}

static void check_threshold(presidio_anomaly_type_t type)
{
    if (type == PRESIDIO_ANOMALY_AUTH_FAILURE &&
        s_counters[type] >= (uint32_t)MAX_AUTH_FAILURES) {
        char msg[64];
        snprintf(msg, sizeof(msg),
                 "Auth failure threshold reached (%d)", MAX_AUTH_FAILURES);
        presidio_log_event(PRESIDIO_SEV_ALERT, "ANOMALY", msg);
    }
}

esp_err_t presidio_anomaly_init(void)
{
    if (s_inited) {
        return ESP_OK;
    }

    memset(s_counters, 0, sizeof(s_counters));
    memset(s_handlers, 0, sizeof(s_handlers));

    s_inited = true;
    ESP_LOGI(TAG, "Anomaly detection initialized (auth_fail_threshold=%d)",
             MAX_AUTH_FAILURES);
    presidio_log_event(PRESIDIO_SEV_INFO, "ANOMALY",
                       "Runtime anomaly detection active");
    return ESP_OK;
}

esp_err_t presidio_anomaly_register_handler(presidio_anomaly_type_t type,
                                            presidio_anomaly_handler_t handler,
                                            void *ctx)
{
    if (type >= PRESIDIO_ANOMALY_TYPE_MAX || !handler) {
        return ESP_ERR_INVALID_ARG;
    }
    s_handlers[type].handler = handler;
    s_handlers[type].ctx     = ctx;
    return ESP_OK;
}

esp_err_t presidio_anomaly_report(presidio_anomaly_type_t type)
{
    if (type >= PRESIDIO_ANOMALY_TYPE_MAX) {
        return ESP_ERR_INVALID_ARG;
    }

    s_counters[type]++;
    ESP_LOGW(TAG, "Anomaly reported: %s (count=%"PRIu32")",
             anomaly_name(type), s_counters[type]);

    check_threshold(type);

    if (s_handlers[type].handler) {
        s_handlers[type].handler(type, s_counters[type],
                                 s_handlers[type].ctx);
    }

    return ESP_OK;
}

void presidio_anomaly_reset_counters(void)
{
    memset(s_counters, 0, sizeof(s_counters));
    ESP_LOGI(TAG, "Anomaly counters reset");
}

uint32_t presidio_anomaly_get_count(presidio_anomaly_type_t type)
{
    if (type >= PRESIDIO_ANOMALY_TYPE_MAX) {
        return 0;
    }
    return s_counters[type];
}

void presidio_anomaly_deinit(void)
{
    memset(s_counters, 0, sizeof(s_counters));
    memset(s_handlers, 0, sizeof(s_handlers));
    s_inited = false;
}
