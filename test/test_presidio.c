#include "unity.h"
#include "presidio_security.h"
#include "presidio_tls.h"
#include "presidio_nvs.h"
#include "presidio_boot.h"
#include "presidio_anomaly.h"
#include "presidio_input.h"
#include "presidio_log.h"

#include "mbedtls/ssl.h"
#include "nvs_flash.h"

#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  TLS hardening tests                                                */
/* ------------------------------------------------------------------ */

TEST_CASE("TLS: apply_hardening rejects NULL config", "[presidio][tls]")
{
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
                      presidio_tls_apply_hardening(NULL));
}

TEST_CASE("TLS: apply_hardening succeeds on valid config", "[presidio][tls]")
{
    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init(&conf);
    TEST_ASSERT_EQUAL(ESP_OK, presidio_tls_apply_hardening(&conf));
    mbedtls_ssl_config_free(&conf);
}

TEST_CASE("TLS: approved suites list is non-empty and terminated", "[presidio][tls]")
{
    const int *suites = presidio_tls_get_allowed_suites();
    TEST_ASSERT_NOT_NULL(suites);
    TEST_ASSERT_NOT_EQUAL(0, suites[0]);

    int count = 0;
    while (suites[count] != 0) {
        count++;
    }
    TEST_ASSERT_GREATER_THAN(0, count);
}

TEST_CASE("TLS: weak suites are rejected", "[presidio][tls]")
{
    /* RC4-based suite should be rejected */
    TEST_ASSERT_FALSE(presidio_tls_is_suite_allowed(0x0005));  /* TLS_RSA_WITH_RC4_128_SHA */
    TEST_ASSERT_FALSE(presidio_tls_is_suite_allowed(0x000A));  /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
}

TEST_CASE("TLS: strong suites are allowed", "[presidio][tls]")
{
    /* ECDHE-RSA-AES256-GCM-SHA384 = 0xC030 */
    TEST_ASSERT_TRUE(presidio_tls_is_suite_allowed(0xC030));
    /* ECDHE-ECDSA-AES128-GCM-SHA256 = 0xC02B */
    TEST_ASSERT_TRUE(presidio_tls_is_suite_allowed(0xC02B));
}

/* ------------------------------------------------------------------ */
/*  NVS secure storage tests                                           */
/* ------------------------------------------------------------------ */

TEST_CASE("NVS: secret key detection", "[presidio][nvs]")
{
    TEST_ASSERT_TRUE(presidio_nvs_is_secret_key("wifi_password"));
    TEST_ASSERT_TRUE(presidio_nvs_is_secret_key("api_key"));
    TEST_ASSERT_TRUE(presidio_nvs_is_secret_key("auth_token"));
    TEST_ASSERT_TRUE(presidio_nvs_is_secret_key("MY_SECRET"));
    TEST_ASSERT_TRUE(presidio_nvs_is_secret_key("user_credential"));

    TEST_ASSERT_FALSE(presidio_nvs_is_secret_key("hostname"));
    TEST_ASSERT_FALSE(presidio_nvs_is_secret_key("port"));
    TEST_ASSERT_FALSE(presidio_nvs_is_secret_key("brightness"));
    TEST_ASSERT_FALSE(presidio_nvs_is_secret_key(NULL));
}

TEST_CASE("NVS: open rejects NULL args", "[presidio][nvs]")
{
    presidio_nvs_handle_t h;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, presidio_nvs_open(NULL, &h));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, presidio_nvs_open("test", NULL));
}

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

TEST_CASE("NVS: close rejects NULL", "[presidio][nvs]")
{
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, presidio_nvs_close(NULL));
}

/* ------------------------------------------------------------------ */
/*  Boot security tests                                                */
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
/*  Anomaly detection tests                                            */
/* ------------------------------------------------------------------ */

static uint32_t s_cb_count = 0;
static void test_anomaly_cb(presidio_anomaly_type_t type, uint32_t count,
                             void *ctx)
{
    (void)type;
    (void)ctx;
    s_cb_count = count;
}

TEST_CASE("ANOMALY: init and report", "[presidio][anomaly]")
{
    presidio_anomaly_deinit();
    TEST_ASSERT_EQUAL(ESP_OK, presidio_anomaly_init());

    TEST_ASSERT_EQUAL(0, presidio_anomaly_get_count(PRESIDIO_ANOMALY_AUTH_FAILURE));
    TEST_ASSERT_EQUAL(ESP_OK, presidio_anomaly_report(PRESIDIO_ANOMALY_AUTH_FAILURE));
    TEST_ASSERT_EQUAL(1, presidio_anomaly_get_count(PRESIDIO_ANOMALY_AUTH_FAILURE));

    presidio_anomaly_reset_counters();
    TEST_ASSERT_EQUAL(0, presidio_anomaly_get_count(PRESIDIO_ANOMALY_AUTH_FAILURE));

    presidio_anomaly_deinit();
}

TEST_CASE("ANOMALY: handler callback fires", "[presidio][anomaly]")
{
    presidio_anomaly_deinit();
    presidio_anomaly_init();

    s_cb_count = 0;
    TEST_ASSERT_EQUAL(ESP_OK,
        presidio_anomaly_register_handler(PRESIDIO_ANOMALY_AUTH_FAILURE,
                                          test_anomaly_cb, NULL));

    presidio_anomaly_report(PRESIDIO_ANOMALY_AUTH_FAILURE);
    TEST_ASSERT_EQUAL(1, s_cb_count);

    presidio_anomaly_report(PRESIDIO_ANOMALY_AUTH_FAILURE);
    TEST_ASSERT_EQUAL(2, s_cb_count);

    presidio_anomaly_deinit();
}

TEST_CASE("ANOMALY: invalid type rejected", "[presidio][anomaly]")
{
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
                      presidio_anomaly_report(PRESIDIO_ANOMALY_TYPE_MAX));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
        presidio_anomaly_register_handler(PRESIDIO_ANOMALY_TYPE_MAX, test_anomaly_cb, NULL));
}

/* ------------------------------------------------------------------ */
/*  Input sanitization tests                                           */
/* ------------------------------------------------------------------ */

TEST_CASE("INPUT: valid SSID accepted", "[presidio][input]")
{
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_OK,
                      presidio_input_sanitize_ssid("MyNetwork"));
}

TEST_CASE("INPUT: NULL SSID rejected", "[presidio][input]")
{
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_NULL_PTR,
                      presidio_input_sanitize_ssid(NULL));
}

TEST_CASE("INPUT: empty SSID rejected", "[presidio][input]")
{
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_TOO_SHORT,
                      presidio_input_sanitize_ssid(""));
}

TEST_CASE("INPUT: oversized SSID rejected", "[presidio][input]")
{
    char big[64];
    memset(big, 'A', 33);
    big[33] = '\0';
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_TOO_LONG,
                      presidio_input_sanitize_ssid(big));
}

TEST_CASE("INPUT: SSID with control chars rejected", "[presidio][input]")
{
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INVALID_CHARS,
                      presidio_input_sanitize_ssid("Net\x01work"));
}

TEST_CASE("INPUT: valid Wi-Fi password accepted", "[presidio][input]")
{
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_OK,
                      presidio_input_sanitize_wifi_password("Str0ngP@ss!"));
}

TEST_CASE("INPUT: short Wi-Fi password rejected", "[presidio][input]")
{
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_TOO_SHORT,
                      presidio_input_sanitize_wifi_password("short"));
}

TEST_CASE("INPUT: valid MQTT topic accepted", "[presidio][input]")
{
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_OK,
                      presidio_input_sanitize_mqtt_topic("home/sensor/temp"));
}

TEST_CASE("INPUT: MQTT stacked wildcards rejected", "[presidio][input]")
{
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INJECTION_DETECTED,
                      presidio_input_sanitize_mqtt_topic("home/#/#"));
}

TEST_CASE("INPUT: MQTT # not at end rejected", "[presidio][input]")
{
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INJECTION_DETECTED,
                      presidio_input_sanitize_mqtt_topic("home/#/temp"));
}

TEST_CASE("INPUT: MQTT $SYS traversal rejected", "[presidio][input]")
{
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INJECTION_DETECTED,
                      presidio_input_sanitize_mqtt_topic("home/../$SYS/broker"));
}

TEST_CASE("INPUT: valid HTTP body accepted", "[presidio][input]")
{
    const char *body = "{\"temperature\": 23.5}";
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_OK,
                      presidio_input_sanitize_http_body(body, strlen(body)));
}

TEST_CASE("INPUT: HTTP body with script injection rejected", "[presidio][input]")
{
    const char *body = "<script>alert('xss')</script>";
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INJECTION_DETECTED,
                      presidio_input_sanitize_http_body(body, strlen(body)));
}

TEST_CASE("INPUT: result_to_str returns valid strings", "[presidio][input]")
{
    TEST_ASSERT_EQUAL_STRING("OK",
        presidio_input_result_to_str(PRESIDIO_INPUT_OK));
    TEST_ASSERT_EQUAL_STRING("injection detected",
        presidio_input_result_to_str(PRESIDIO_INPUT_INJECTION_DETECTED));
}

/* ------------------------------------------------------------------ */
/*  Security event logging tests                                       */
/* ------------------------------------------------------------------ */

TEST_CASE("LOG: init and event logging", "[presidio][log]")
{
    presidio_log_deinit();
    TEST_ASSERT_EQUAL(ESP_OK, presidio_log_init());

    TEST_ASSERT_EQUAL(ESP_OK,
        presidio_log_event(PRESIDIO_SEV_INFO, "TEST", "unit test event"));
    TEST_ASSERT_EQUAL(1, presidio_log_get_total_count());

    presidio_security_event_t events[4];
    int n = presidio_log_get_recent(events, 4);
    TEST_ASSERT_EQUAL(1, n);
    TEST_ASSERT_EQUAL(PRESIDIO_SEV_INFO, events[0].severity);
    TEST_ASSERT_EQUAL_STRING("TEST", events[0].module);

    presidio_log_deinit();
}

TEST_CASE("LOG: rejects NULL args", "[presidio][log]")
{
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
        presidio_log_event(PRESIDIO_SEV_INFO, NULL, "msg"));
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
        presidio_log_event(PRESIDIO_SEV_INFO, "MOD", NULL));
}

static uint32_t s_log_cb_count = 0;
static void test_log_cb(const presidio_security_event_t *ev, void *ctx)
{
    (void)ctx;
    (void)ev;
    s_log_cb_count++;
}

TEST_CASE("LOG: handler callback fires", "[presidio][log]")
{
    presidio_log_deinit();
    presidio_log_init();

    s_log_cb_count = 0;
    TEST_ASSERT_EQUAL(ESP_OK, presidio_log_register_handler(test_log_cb, NULL));

    presidio_log_event(PRESIDIO_SEV_WARNING, "TEST", "warn event");
    TEST_ASSERT_EQUAL(1, s_log_cb_count);

    presidio_log_deinit();
}

TEST_CASE("LOG: ring buffer wraps correctly", "[presidio][log]")
{
    presidio_log_deinit();
    presidio_log_init();

    /* Write more events than the buffer can hold (default 64) */
    for (int i = 0; i < 70; i++) {
        presidio_log_event(PRESIDIO_SEV_INFO, "WRAP", "overflow test");
    }
    TEST_ASSERT_EQUAL(70, presidio_log_get_total_count());

    presidio_security_event_t events[10];
    int n = presidio_log_get_recent(events, 10);
    TEST_ASSERT_EQUAL(10, n);

    presidio_log_deinit();
}

/* ------------------------------------------------------------------ */
/*  Integration: full init/deinit cycle                                */
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
