#include "presidio_security.h"
#include "presidio_tls.h"
#include "presidio_nvs.h"
#include "presidio_boot.h"
#include "presidio_anomaly.h"
#include "presidio_input.h"
#include "presidio_log.h"
#include "esp_log.h"

#include <stdio.h>
#include <string.h>

static const char *TAG = "presidio";
static char s_status_buf[512];
static bool s_initialized = false;

esp_err_t presidio_security_init(void)
{
    if (s_initialized) {
        ESP_LOGW(TAG, "Already initialized");
        return ESP_OK;
    }

    ESP_LOGI(TAG, "Presidio Hardened ESP32 v%s initializing...",
             PRESIDIO_VERSION_STRING);

    esp_err_t ret;

    /* 1. Security event logging (must be first so other modules can log) */
#ifdef CONFIG_PRESIDIO_SECURITY_LOG
    ret = presidio_log_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Log subsystem init failed: %s", esp_err_to_name(ret));
        return ret;
    }
#endif

    presidio_log_event(PRESIDIO_SEV_INFO, "INIT",
                       "Presidio hardening applied to ESP32 session");

    /* 2. Boot security verification */
#ifdef CONFIG_PRESIDIO_BOOT_ENFORCEMENT
    ret = presidio_boot_verify();
    if (ret != ESP_OK) {
#ifdef CONFIG_PRESIDIO_BOOT_HALT_IF_INSECURE
        ESP_LOGE(TAG, "Boot security check failed – halting");
        return ret;
#else
        ESP_LOGW(TAG, "Boot security check found issues (non-fatal)");
#endif
    }
#endif

    /* 3. Anomaly detection */
#ifdef CONFIG_PRESIDIO_ANOMALY_DETECTION
    ret = presidio_anomaly_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Anomaly detection init failed: %s",
                 esp_err_to_name(ret));
        return ret;
    }
#endif

    s_initialized = true;
    ESP_LOGI(TAG, "Presidio security hardening active");
    presidio_log_event(PRESIDIO_SEV_INFO, "INIT",
                       "All security subsystems initialized");
    return ESP_OK;
}

const char *presidio_security_status(void)
{
    int pos = 0;
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "Presidio v%s | ", PRESIDIO_VERSION_STRING);

#ifdef CONFIG_PRESIDIO_TLS_HARDENING
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "TLS:hardened ");
#else
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "TLS:off ");
#endif

#ifdef CONFIG_PRESIDIO_NVS_REDACTION
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "NVS:redact ");
#else
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "NVS:plain ");
#endif

#ifdef CONFIG_PRESIDIO_BOOT_ENFORCEMENT
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "BOOT:enforced ");
#else
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "BOOT:off ");
#endif

#ifdef CONFIG_PRESIDIO_ANOMALY_DETECTION
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "ANOMALY:on ");
#else
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "ANOMALY:off ");
#endif

#ifdef CONFIG_PRESIDIO_INPUT_SANITIZATION
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "INPUT:sanitize ");
#else
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "INPUT:off ");
#endif

#ifdef CONFIG_PRESIDIO_SECURITY_LOG
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "LOG:on");
#else
    (void)pos;
    pos += snprintf(s_status_buf + pos, sizeof(s_status_buf) - pos,
                    "LOG:off");
#endif

    return s_status_buf;
}

void presidio_security_deinit(void)
{
    if (!s_initialized) {
        return;
    }

#ifdef CONFIG_PRESIDIO_ANOMALY_DETECTION
    presidio_anomaly_deinit();
#endif

#ifdef CONFIG_PRESIDIO_SECURITY_LOG
    presidio_log_deinit();
#endif

    s_initialized = false;
    ESP_LOGI(TAG, "Presidio security extensions torn down");
}
