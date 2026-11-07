#include "unity.h"
#include "presidio_security.h"
#include "presidio_tls.h"
#include "presidio_nvs.h"
#include "presidio_boot.h"

#include "mbedtls/ssl.h"
#include "nvs_flash.h"

#include <string.h>
#include <stdlib.h>

/*
 * Device-only test cases: they need real mbedTLS configuration calls,
 * NVS flash, eFuse reads or the full init sequence. Portable cases live in
 * test_tls_policy.c, test_nvs_policy.c, test_anomaly.c, test_input.c and
 * test_log.c and also run on the host (test/host).
 */

/* ------------------------------------------------------------------ */
/*  TLS hardening tests                                               */
/* ------------------------------------------------------------------ */

TEST_CASE("TLS: apply_hardening succeeds on valid config", "[presidio][tls]")
{
    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init(&conf);
    TEST_ASSERT_EQUAL(ESP_OK, presidio_tls_apply_hardening(&conf));
    mbedtls_ssl_config_free(&conf);
}

/* ------------------------------------------------------------------ */
/*  NVS secure storage tests                                          */
/* ------------------------------------------------------------------ */

TEST_CASE("NVS: set/get string round-trip", "[presidio][nvs]")
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    TEST_ASSERT_EQUAL(ESP_OK, err);

    presidio_nvs_handle_t h;
    TEST_ASSERT_EQUAL(ESP_OK, presidio_nvs_open("ptest", &h));

    TEST_ASSERT_EQUAL(ESP_OK,
                      presidio_nvs_set_str(h, "hostname", "example.com"));

    char *val = NULL;
    TEST_ASSERT_EQUAL(ESP_OK, presidio_nvs_get_str(h, "hostname", &val));
    TEST_ASSERT_NOT_NULL(val);
    TEST_ASSERT_EQUAL_STRING("example.com", val);
    free(val);

    TEST_ASSERT_EQUAL(ESP_OK, presidio_nvs_close(h));
    nvs_flash_deinit();
}

/* ------------------------------------------------------------------ */
/*  Boot security tests                                               */
/* ------------------------------------------------------------------ */

TEST_CASE("BOOT: get_status rejects NULL", "[presidio][boot]")
{
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, presidio_boot_get_status(NULL));
}

TEST_CASE("BOOT: get_status returns valid struct", "[presidio][boot]")
{
    presidio_boot_status_t st;
    TEST_ASSERT_EQUAL(ESP_OK, presidio_boot_get_status(&st));
    /* On a dev board without fuses burned, these should be false */
}

TEST_CASE("BOOT: status string is non-empty", "[presidio][boot]")
{
    const char *s = presidio_boot_status_str();
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT_GREATER_THAN(0, strlen(s));
}

/* ------------------------------------------------------------------ */
/*  Integration: full init/deinit cycle                               */
/* ------------------------------------------------------------------ */

TEST_CASE("SECURITY: init and status", "[presidio][integration]")
{
    presidio_security_deinit();

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }

    TEST_ASSERT_EQUAL(ESP_OK, presidio_security_init());

    const char *status = presidio_security_status();
    TEST_ASSERT_NOT_NULL(status);
    TEST_ASSERT_NOT_EQUAL(0, strlen(status));

    presidio_security_deinit();
    nvs_flash_deinit();
}
