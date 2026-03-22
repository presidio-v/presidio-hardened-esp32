#include "presidio_nvs.h"
#include "presidio_log.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const char *TAG = "presidio_nvs";

struct presidio_nvs_handle {
    nvs_handle_t nvs;
    char         namespace_name[16];
};

static const char *s_secret_patterns[] = {
    "password", "passwd", "pass", "secret", "token",
    "key", "credential", "cred", "auth", "private",
    "cert", "apikey", "api_key",
    NULL
};

static bool str_contains_ci(const char *haystack, const char *needle)
{
    if (!haystack || !needle) {
        return false;
    }
    size_t h_len = strlen(haystack);
    size_t n_len = strlen(needle);
    if (n_len > h_len) {
        return false;
    }
    for (size_t i = 0; i <= h_len - n_len; i++) {
        bool match = true;
        for (size_t j = 0; j < n_len; j++) {
            if (tolower((unsigned char)haystack[i + j]) !=
                tolower((unsigned char)needle[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

bool presidio_nvs_is_secret_key(const char *key)
{
    if (!key) {
        return false;
    }
    for (int i = 0; s_secret_patterns[i] != NULL; i++) {
        if (str_contains_ci(key, s_secret_patterns[i])) {
            return true;
        }
    }
    return false;
}

static void log_nvs_op(const char *op, const char *ns, const char *key,
                        const char *value)
{
#ifdef CONFIG_PRESIDIO_NVS_REDACTION
    if (presidio_nvs_is_secret_key(key)) {
        ESP_LOGI(TAG, "%s [%s] %s = ***REDACTED***", op, ns, key);
    } else {
        ESP_LOGI(TAG, "%s [%s] %s = %s", op, ns, key,
                 value ? value : "(blob)");
    }
#else
    ESP_LOGI(TAG, "%s [%s] %s", op, ns, key);
#endif
}

esp_err_t presidio_nvs_open(const char *namespace_name,
                            presidio_nvs_handle_t *out_handle)
{
    if (!namespace_name || !out_handle) {
        return ESP_ERR_INVALID_ARG;
    }

    struct presidio_nvs_handle *h = calloc(1, sizeof(*h));
    if (!h) {
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = nvs_open(namespace_name, NVS_READWRITE, &h->nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open(%s) failed: %s", namespace_name,
                 esp_err_to_name(err));
        free(h);
        return err;
    }

    strncpy(h->namespace_name, namespace_name, sizeof(h->namespace_name) - 1);
    h->namespace_name[sizeof(h->namespace_name) - 1] = '\0';
    *out_handle = h;

    presidio_log_event(PRESIDIO_SEV_INFO, "NVS", "Secure NVS namespace opened");
    return ESP_OK;
}

esp_err_t presidio_nvs_set_str(presidio_nvs_handle_t handle,
                               const char *key, const char *value)
{
    if (!handle || !key || !value) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = nvs_set_str(handle->nvs, key, value);
    if (err == ESP_OK) {
        err = nvs_commit(handle->nvs);
    }

    log_nvs_op("SET_STR", handle->namespace_name, key, value);
    return err;
}

esp_err_t presidio_nvs_get_str(presidio_nvs_handle_t handle,
                               const char *key, char **out_value)
{
    if (!handle || !key || !out_value) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t required = 0;
    esp_err_t err = nvs_get_str(handle->nvs, key, NULL, &required);
    if (err != ESP_OK) {
        return err;
    }

    char *buf = malloc(required);
    if (!buf) {
        return ESP_ERR_NO_MEM;
    }

    err = nvs_get_str(handle->nvs, key, buf, &required);
    if (err != ESP_OK) {
        free(buf);
        return err;
    }

    *out_value = buf;
    log_nvs_op("GET_STR", handle->namespace_name, key, buf);
    return ESP_OK;
}

esp_err_t presidio_nvs_set_blob(presidio_nvs_handle_t handle,
                                const char *key,
                                const void *value, size_t length)
{
    if (!handle || !key || !value || length == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = nvs_set_blob(handle->nvs, key, value, length);
    if (err == ESP_OK) {
        err = nvs_commit(handle->nvs);
    }

    log_nvs_op("SET_BLOB", handle->namespace_name, key, NULL);
    return err;
}

esp_err_t presidio_nvs_get_blob(presidio_nvs_handle_t handle,
                                const char *key,
                                void **out_value, size_t *out_length)
{
    if (!handle || !key || !out_value || !out_length) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t required = 0;
    esp_err_t err = nvs_get_blob(handle->nvs, key, NULL, &required);
    if (err != ESP_OK) {
        return err;
    }

    void *buf = malloc(required);
    if (!buf) {
        return ESP_ERR_NO_MEM;
    }

    err = nvs_get_blob(handle->nvs, key, buf, &required);
    if (err != ESP_OK) {
        free(buf);
        return err;
    }

    *out_value  = buf;
    *out_length = required;
    log_nvs_op("GET_BLOB", handle->namespace_name, key, NULL);
    return ESP_OK;
}

esp_err_t presidio_nvs_erase_key(presidio_nvs_handle_t handle,
                                 const char *key)
{
    if (!handle || !key) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = nvs_erase_key(handle->nvs, key);
    if (err == ESP_OK) {
        err = nvs_commit(handle->nvs);
    }

    log_nvs_op("ERASE", handle->namespace_name, key, NULL);
    return err;
}

esp_err_t presidio_nvs_close(presidio_nvs_handle_t handle)
{
    if (!handle) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_commit(handle->nvs);
    nvs_close(handle->nvs);
    ESP_LOGI(TAG, "NVS namespace [%s] closed", handle->namespace_name);
    free(handle);
    return ESP_OK;
}
