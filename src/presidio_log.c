#include "presidio_log.h"
#include "esp_log.h"
#include "esp_timer.h"

#include <stdlib.h>
#include <string.h>

static const char *TAG = "presidio_log";

#ifdef CONFIG_PRESIDIO_LOG_MAX_EVENTS
#define RING_SIZE CONFIG_PRESIDIO_LOG_MAX_EVENTS
#else
#define RING_SIZE 64
#endif

typedef struct {
    uint32_t            timestamp_ms;
    presidio_severity_t severity;
    char                module[16];
    char                message[128];
} stored_event_t;

static stored_event_t *s_ring     = NULL;
static int             s_head     = 0;
static int             s_count    = 0;
static uint32_t        s_total    = 0;
static bool            s_inited   = false;

static presidio_log_handler_t s_handler     = NULL;
static void                  *s_handler_ctx = NULL;

static const char *severity_str(presidio_severity_t sev)
{
    switch (sev) {
    case PRESIDIO_SEV_INFO:     return "INFO";
    case PRESIDIO_SEV_WARNING:  return "WARN";
    case PRESIDIO_SEV_ALERT:    return "ALERT";
    case PRESIDIO_SEV_CRITICAL: return "CRIT";
    default:                    return "UNKNOWN";
    }
}

esp_err_t presidio_log_init(void)
{
    if (s_inited) {
        return ESP_OK;
    }
    s_ring = calloc(RING_SIZE, sizeof(stored_event_t));
    if (!s_ring) {
        ESP_LOGE(TAG, "Failed to allocate event ring buffer");
        return ESP_ERR_NO_MEM;
    }
    s_head   = 0;
    s_count  = 0;
    s_total  = 0;
    s_inited = true;
    ESP_LOGI(TAG, "Security event logging initialized (buffer=%d)", RING_SIZE);
    return ESP_OK;
}

esp_err_t presidio_log_event(presidio_severity_t severity,
                             const char *module,
                             const char *message)
{
    if (!module || !message) {
        return ESP_ERR_INVALID_ARG;
    }
    uint32_t ts = (uint32_t)(esp_timer_get_time() / 1000);

    switch (severity) {
    case PRESIDIO_SEV_CRITICAL:
        ESP_LOGE(TAG, "[%s] %s: %s", severity_str(severity), module, message);
        break;
    case PRESIDIO_SEV_ALERT:
        ESP_LOGW(TAG, "[%s] %s: %s", severity_str(severity), module, message);
        break;
    case PRESIDIO_SEV_WARNING:
        ESP_LOGW(TAG, "[%s] %s: %s", severity_str(severity), module, message);
        break;
    default:
        ESP_LOGI(TAG, "[%s] %s: %s", severity_str(severity), module, message);
        break;
    }

    if (s_inited && s_ring) {
        stored_event_t *e = &s_ring[s_head];
        e->timestamp_ms = ts;
        e->severity     = severity;
        strncpy(e->module, module, sizeof(e->module) - 1);
        e->module[sizeof(e->module) - 1] = '\0';
        strncpy(e->message, message, sizeof(e->message) - 1);
        e->message[sizeof(e->message) - 1] = '\0';

        s_head = (s_head + 1) % RING_SIZE;
        if (s_count < RING_SIZE) {
            s_count++;
        }
        s_total++;
    }

    if (s_handler) {
        presidio_security_event_t ev = {
            .timestamp_ms = ts,
            .severity     = severity,
            .module       = module,
            .message      = message,
        };
        s_handler(&ev, s_handler_ctx);
    }

    return ESP_OK;
}

esp_err_t presidio_log_register_handler(presidio_log_handler_t handler,
                                        void *ctx)
{
    if (!handler) {
        return ESP_ERR_INVALID_ARG;
    }
    s_handler     = handler;
    s_handler_ctx = ctx;
    return ESP_OK;
}

int presidio_log_get_recent(presidio_security_event_t *out_events,
                            int max_events)
{
    if (!out_events || max_events <= 0 || !s_inited) {
        return 0;
    }

    int to_copy = (max_events < s_count) ? max_events : s_count;
    int start   = (s_head - s_count + RING_SIZE) % RING_SIZE;

    int offset = s_count - to_copy;
    start = (start + offset) % RING_SIZE;

    for (int i = 0; i < to_copy; i++) {
        int idx = (start + i) % RING_SIZE;
        out_events[i].timestamp_ms = s_ring[idx].timestamp_ms;
        out_events[i].severity     = s_ring[idx].severity;
        out_events[i].module       = s_ring[idx].module;
        out_events[i].message      = s_ring[idx].message;
    }
    return to_copy;
}

uint32_t presidio_log_get_total_count(void)
{
    return s_total;
}

void presidio_log_deinit(void)
{
    if (s_ring) {
        free(s_ring);
        s_ring = NULL;
    }
    s_head       = 0;
    s_count      = 0;
    s_total      = 0;
    s_inited     = false;
    s_handler    = NULL;
    s_handler_ctx = NULL;
}
