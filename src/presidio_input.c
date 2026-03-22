#include "presidio_input.h"
#include "presidio_log.h"
#include "esp_log.h"

#include <string.h>
#include <ctype.h>

static const char *TAG = "presidio_input";

#ifdef CONFIG_PRESIDIO_INPUT_MAX_WIFI_SSID_LEN
#define MAX_SSID_LEN CONFIG_PRESIDIO_INPUT_MAX_WIFI_SSID_LEN
#else
#define MAX_SSID_LEN 32
#endif

#ifdef CONFIG_PRESIDIO_INPUT_MAX_WIFI_PASS_LEN
#define MAX_PASS_LEN CONFIG_PRESIDIO_INPUT_MAX_WIFI_PASS_LEN
#else
#define MAX_PASS_LEN 64
#endif

#ifdef CONFIG_PRESIDIO_INPUT_MAX_MQTT_TOPIC_LEN
#define MAX_TOPIC_LEN CONFIG_PRESIDIO_INPUT_MAX_MQTT_TOPIC_LEN
#else
#define MAX_TOPIC_LEN 256
#endif

#ifdef CONFIG_PRESIDIO_INPUT_MAX_HTTP_BODY_LEN
#define MAX_BODY_LEN CONFIG_PRESIDIO_INPUT_MAX_HTTP_BODY_LEN
#else
#define MAX_BODY_LEN 4096
#endif

static bool has_null_bytes(const char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\0') {
            return true;
        }
    }
    return false;
}

static bool has_control_chars(const char *str)
{
    for (size_t i = 0; str[i] != '\0'; i++) {
        unsigned char c = (unsigned char)str[i];
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
            return true;
        }
    }
    return false;
}

presidio_input_result_t presidio_input_sanitize_ssid(const char *ssid)
{
    if (!ssid) {
        return PRESIDIO_INPUT_NULL_PTR;
    }
    size_t len = strlen(ssid);
    if (len == 0) {
        return PRESIDIO_INPUT_TOO_SHORT;
    }
    if (len > MAX_SSID_LEN) {
        ESP_LOGW(TAG, "SSID too long (%zu > %d)", len, MAX_SSID_LEN);
        return PRESIDIO_INPUT_TOO_LONG;
    }
    if (has_control_chars(ssid)) {
        presidio_log_event(PRESIDIO_SEV_WARNING, "INPUT",
                           "SSID contains control characters");
        return PRESIDIO_INPUT_INVALID_CHARS;
    }
    return PRESIDIO_INPUT_OK;
}

presidio_input_result_t presidio_input_sanitize_wifi_password(const char *password)
{
    if (!password) {
        return PRESIDIO_INPUT_NULL_PTR;
    }
    size_t len = strlen(password);
    if (len < 8) {
        return PRESIDIO_INPUT_TOO_SHORT;
    }
    if (len > MAX_PASS_LEN) {
        ESP_LOGW(TAG, "Wi-Fi password too long (%zu > %d)", len, MAX_PASS_LEN);
        return PRESIDIO_INPUT_TOO_LONG;
    }
    if (has_control_chars(password)) {
        presidio_log_event(PRESIDIO_SEV_WARNING, "INPUT",
                           "Wi-Fi password contains control characters");
        return PRESIDIO_INPUT_INVALID_CHARS;
    }
    return PRESIDIO_INPUT_OK;
}

presidio_input_result_t presidio_input_sanitize_mqtt_topic(const char *topic)
{
    if (!topic) {
        return PRESIDIO_INPUT_NULL_PTR;
    }
    size_t len = strlen(topic);
    if (len == 0) {
        return PRESIDIO_INPUT_TOO_SHORT;
    }
    if (len > MAX_TOPIC_LEN) {
        ESP_LOGW(TAG, "MQTT topic too long (%zu > %d)", len, MAX_TOPIC_LEN);
        return PRESIDIO_INPUT_TOO_LONG;
    }
    if (has_control_chars(topic)) {
        presidio_log_event(PRESIDIO_SEV_WARNING, "INPUT",
                           "MQTT topic contains control characters");
        return PRESIDIO_INPUT_INVALID_CHARS;
    }

    /* Reject stacked multi-level wildcards (e.g. "#/#" or "##") */
    if (strstr(topic, "#/#") || strstr(topic, "##")) {
        presidio_log_event(PRESIDIO_SEV_ALERT, "INPUT",
                           "MQTT topic injection: stacked wildcards");
        return PRESIDIO_INPUT_INJECTION_DETECTED;
    }

    /* # must be last character if present */
    const char *hash = strchr(topic, '#');
    if (hash && hash[1] != '\0') {
        presidio_log_event(PRESIDIO_SEV_ALERT, "INPUT",
                           "MQTT topic injection: # not at end");
        return PRESIDIO_INPUT_INJECTION_DETECTED;
    }

    /* Reject $SYS topic traversal unless topic starts with $SYS */
    if (strstr(topic, "$SYS") && strncmp(topic, "$SYS", 4) != 0) {
        presidio_log_event(PRESIDIO_SEV_ALERT, "INPUT",
                           "MQTT topic injection: $SYS traversal");
        return PRESIDIO_INPUT_INJECTION_DETECTED;
    }

    return PRESIDIO_INPUT_OK;
}

presidio_input_result_t presidio_input_sanitize_http_body(const char *body,
                                                          size_t length)
{
    if (!body) {
        return PRESIDIO_INPUT_NULL_PTR;
    }
    if (length > (size_t)MAX_BODY_LEN) {
        ESP_LOGW(TAG, "HTTP body too large (%zu > %d)", length, MAX_BODY_LEN);
        return PRESIDIO_INPUT_TOO_LONG;
    }
    if (has_null_bytes(body, length)) {
        presidio_log_event(PRESIDIO_SEV_WARNING, "INPUT",
                           "HTTP body contains null bytes");
        return PRESIDIO_INPUT_INVALID_CHARS;
    }

    /* Basic script injection detection */
    static const char *patterns[] = {
        "<script", "javascript:", "onerror=", "onload=",
        "eval(", "document.cookie", NULL
    };
    for (int i = 0; patterns[i]; i++) {
        /* Case-insensitive substring search */
        size_t plen = strlen(patterns[i]);
        for (size_t j = 0; j + plen <= length; j++) {
            bool match = true;
            for (size_t k = 0; k < plen; k++) {
                if (tolower((unsigned char)body[j + k]) !=
                    tolower((unsigned char)patterns[i][k])) {
                    match = false;
                    break;
                }
            }
            if (match) {
                presidio_log_event(PRESIDIO_SEV_ALERT, "INPUT",
                                   "HTTP body: script injection pattern");
                return PRESIDIO_INPUT_INJECTION_DETECTED;
            }
        }
    }

    return PRESIDIO_INPUT_OK;
}

const char *presidio_input_result_to_str(presidio_input_result_t result)
{
    switch (result) {
    case PRESIDIO_INPUT_OK:                 return "OK";
    case PRESIDIO_INPUT_NULL_PTR:           return "null pointer";
    case PRESIDIO_INPUT_TOO_LONG:           return "input too long";
    case PRESIDIO_INPUT_TOO_SHORT:          return "input too short";
    case PRESIDIO_INPUT_INVALID_CHARS:      return "invalid characters";
    case PRESIDIO_INPUT_INJECTION_DETECTED: return "injection detected";
    default:                                return "unknown";
    }
}
