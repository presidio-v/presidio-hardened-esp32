/*
 * Definitions for the stubbed ESP-IDF symbols. Anything that would touch
 * hardware (NVS flash) aborts: reaching it from a host test is a test bug,
 * not something to paper over with a fake success.
 */

#include "esp_err.h"
#include "esp_timer.h"
#include "host_fakes.h"
#include "nvs.h"

#include <stdio.h>
#include <stdlib.h>

static int64_t s_fake_time_us = 0;

void host_fake_timer_set_us(int64_t us)
{
    s_fake_time_us = us;
}

int64_t esp_timer_get_time(void)
{
    return s_fake_time_us;
}

const char *esp_err_to_name(esp_err_t code)
{
    switch (code) {
    case ESP_OK:                return "ESP_OK";
    case ESP_FAIL:              return "ESP_FAIL";
    case ESP_ERR_NO_MEM:        return "ESP_ERR_NO_MEM";
    case ESP_ERR_INVALID_ARG:   return "ESP_ERR_INVALID_ARG";
    case ESP_ERR_INVALID_STATE: return "ESP_ERR_INVALID_STATE";
    case ESP_ERR_NOT_SUPPORTED: return "ESP_ERR_NOT_SUPPORTED";
    default:                    return "ESP_ERR_UNKNOWN";
    }
}

static _Noreturn void hardware_path(const char *fn)
{
    fprintf(stderr, "host build: %s() needs real NVS flash; not available on host\n", fn);
    abort();
}

esp_err_t nvs_open(const char *namespace_name, nvs_open_mode_t open_mode, nvs_handle_t *out_handle)
{
    (void)namespace_name;
    (void)open_mode;
    (void)out_handle;
    hardware_path(__func__);
}

esp_err_t nvs_set_str(nvs_handle_t handle, const char *key, const char *value)
{
    (void)handle;
    (void)key;
    (void)value;
    hardware_path(__func__);
}

esp_err_t nvs_get_str(nvs_handle_t handle, const char *key, char *out_value, size_t *length)
{
    (void)handle;
    (void)key;
    (void)out_value;
    (void)length;
    hardware_path(__func__);
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char *key, const void *value, size_t length)
{
    (void)handle;
    (void)key;
    (void)value;
    (void)length;
    hardware_path(__func__);
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char *key, void *out_value, size_t *length)
{
    (void)handle;
    (void)key;
    (void)out_value;
    (void)length;
    hardware_path(__func__);
}

esp_err_t nvs_erase_key(nvs_handle_t handle, const char *key)
{
    (void)handle;
    (void)key;
    hardware_path(__func__);
}

esp_err_t nvs_commit(nvs_handle_t handle)
{
    (void)handle;
    hardware_path(__func__);
}

void nvs_close(nvs_handle_t handle)
{
    (void)handle;
    hardware_path(__func__);
}
