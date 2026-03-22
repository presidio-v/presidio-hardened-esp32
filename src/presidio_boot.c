#include "presidio_boot.h"
#include "presidio_log.h"
#include "esp_log.h"
#include "esp_flash_encrypt.h"
#include "esp_secure_boot.h"

#include <stdio.h>
#include <string.h>

static const char *TAG = "presidio_boot";

static char s_status_buf[256];

esp_err_t presidio_boot_get_status(presidio_boot_status_t *status)
{
    if (!status) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(status, 0, sizeof(*status));

    status->secure_boot_enabled = esp_secure_boot_enabled();
    status->flash_encryption_enabled = esp_flash_encryption_enabled();

    /*
     * JTAG and UART download status depend on eFuse reads that vary
     * by chip revision.  Default to false (unknown = not confirmed disabled).
     */
    status->jtag_disabled          = false;
    status->uart_download_disabled = false;

    return ESP_OK;
}

esp_err_t presidio_boot_verify(void)
{
#ifndef CONFIG_PRESIDIO_BOOT_ENFORCEMENT
    ESP_LOGW(TAG, "Boot enforcement disabled via Kconfig");
    return ESP_OK;
#else

    presidio_boot_status_t st;
    esp_err_t err = presidio_boot_get_status(&st);
    if (err != ESP_OK) {
        return err;
    }

    bool all_ok = true;

    if (!st.secure_boot_enabled) {
        presidio_log_event(PRESIDIO_SEV_WARNING, "BOOT",
                           "Secure boot is NOT enabled");
        ESP_LOGW(TAG, "Secure boot is NOT enabled");
        all_ok = false;
    } else {
        presidio_log_event(PRESIDIO_SEV_INFO, "BOOT",
                           "Secure boot verified");
    }

    if (!st.flash_encryption_enabled) {
        presidio_log_event(PRESIDIO_SEV_WARNING, "BOOT",
                           "Flash encryption is NOT enabled");
        ESP_LOGW(TAG, "Flash encryption is NOT enabled");
        all_ok = false;
    } else {
        presidio_log_event(PRESIDIO_SEV_INFO, "BOOT",
                           "Flash encryption verified");
    }

#ifdef CONFIG_PRESIDIO_BOOT_HALT_IF_INSECURE
    if (!all_ok) {
        presidio_log_event(PRESIDIO_SEV_CRITICAL, "BOOT",
                           "Halting: boot security requirements not met");
        ESP_LOGE(TAG, "HALTING: security requirements not met");
        return ESP_ERR_INVALID_STATE;
    }
#endif

    return all_ok ? ESP_OK : ESP_ERR_INVALID_STATE;
#endif /* CONFIG_PRESIDIO_BOOT_ENFORCEMENT */
}

const char *presidio_boot_status_str(void)
{
    presidio_boot_status_t st;
    if (presidio_boot_get_status(&st) != ESP_OK) {
        return "boot status: unknown";
    }

    snprintf(s_status_buf, sizeof(s_status_buf),
             "secure_boot=%s flash_enc=%s jtag=%s uart_dl=%s",
             st.secure_boot_enabled       ? "ON" : "OFF",
             st.flash_encryption_enabled  ? "ON" : "OFF",
             st.jtag_disabled             ? "disabled" : "enabled",
             st.uart_download_disabled    ? "disabled" : "enabled");

    return s_status_buf;
}
