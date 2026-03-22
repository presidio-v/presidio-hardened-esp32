#include "presidio_tls.h"
#include "presidio_log.h"
#include "esp_log.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ciphersuites.h"

#include <string.h>

static const char *TAG = "presidio_tls";

/*
 * Approved AEAD-only cipher suites.  Order matters: prefer
 * forward-secret ECDHE suites, then AES-256 over AES-128.
 */
static const int s_approved_suites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
#if defined(MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
#endif
    0  /* sentinel */
};

esp_err_t presidio_tls_apply_hardening(mbedtls_ssl_config *conf)
{
    if (!conf) {
        return ESP_ERR_INVALID_ARG;
    }

#ifdef CONFIG_PRESIDIO_TLS_HARDENING

#ifdef CONFIG_PRESIDIO_TLS_MIN_VERSION_13
    mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_3);
    ESP_LOGI(TAG, "TLS minimum version set to 1.3");
#else
    mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);
    ESP_LOGI(TAG, "TLS minimum version set to 1.2");
#endif

    mbedtls_ssl_conf_ciphersuites(conf, s_approved_suites);
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif

    presidio_log_event(PRESIDIO_SEV_INFO, "TLS",
                       "Presidio TLS hardening applied");

#else
    ESP_LOGW(TAG, "TLS hardening disabled via Kconfig");
#endif /* CONFIG_PRESIDIO_TLS_HARDENING */

    return ESP_OK;
}

bool presidio_tls_is_suite_allowed(int suite_id)
{
    for (int i = 0; s_approved_suites[i] != 0; i++) {
        if (s_approved_suites[i] == suite_id) {
            return true;
        }
    }
    return false;
}

const int *presidio_tls_get_allowed_suites(void)
{
    return s_approved_suites;
}
