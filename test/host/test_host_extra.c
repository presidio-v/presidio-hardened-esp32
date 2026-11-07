/*
 * Host-only edge cases for the pure-logic modules. These complement the
 * shared cases in the test/ directory; they use the host timer fake, so they are not
 * part of the device test app.
 */

#include "unity.h"
#include "host_fakes.h"
#include "presidio_anomaly.h"
#include "presidio_input.h"
#include "presidio_log.h"
#include "presidio_nvs.h"
#include "presidio_tls.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---- LOG ---------------------------------------------------------- */

TEST_CASE("LOG(host): recent events are the newest, oldest first", "[host][log]")
{
    char msg[16];

    presidio_log_deinit();
    TEST_ASSERT_EQUAL(ESP_OK, presidio_log_init());
    for (int i = 0; i < 70; i++) {
        snprintf(msg, sizeof(msg), "e%d", i);
        presidio_log_event(PRESIDIO_SEV_INFO, "WRAP", msg);
    }

    presidio_security_event_t ev[3];
    TEST_ASSERT_EQUAL(3, presidio_log_get_recent(ev, 3));
    TEST_ASSERT_EQUAL_STRING("e67", ev[0].message);
    TEST_ASSERT_EQUAL_STRING("e68", ev[1].message);
    TEST_ASSERT_EQUAL_STRING("e69", ev[2].message);

    /* Asking for more than the ring holds returns the ring size. */
    presidio_security_event_t all[100];
    TEST_ASSERT_EQUAL(64, presidio_log_get_recent(all, 100));
    TEST_ASSERT_EQUAL_STRING("e6", all[0].message);
    TEST_ASSERT_EQUAL_STRING("e69", all[63].message);

    presidio_log_deinit();
}

TEST_CASE("LOG(host): timestamp is esp_timer time in ms", "[host][log]")
{
    presidio_log_deinit();
    presidio_log_init();
    host_fake_timer_set_us(1234567);
    presidio_log_event(PRESIDIO_SEV_ALERT, "TS", "tick");

    presidio_security_event_t ev[1];
    TEST_ASSERT_EQUAL(1, presidio_log_get_recent(ev, 1));
    TEST_ASSERT_EQUAL(1234, ev[0].timestamp_ms);
    TEST_ASSERT_EQUAL(PRESIDIO_SEV_ALERT, ev[0].severity);

    host_fake_timer_set_us(0);
    presidio_log_deinit();
}

TEST_CASE("LOG(host): long module and message are truncated", "[host][log]")
{
    char long_msg[300];
    memset(long_msg, 'm', sizeof(long_msg) - 1);
    long_msg[sizeof(long_msg) - 1] = '\0';

    presidio_log_deinit();
    presidio_log_init();
    presidio_log_event(PRESIDIO_SEV_INFO, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", long_msg);

    presidio_security_event_t ev[1];
    TEST_ASSERT_EQUAL(1, presidio_log_get_recent(ev, 1));
    TEST_ASSERT_EQUAL_STRING("ABCDEFGHIJKLMNO", ev[0].module);
    TEST_ASSERT_EQUAL(127, strlen(ev[0].message));

    presidio_log_deinit();
}

static int s_forwarded = 0;
static void count_cb(const presidio_security_event_t *ev, void *ctx)
{
    (void)ev;
    (void)ctx;
    s_forwarded++;
}

TEST_CASE("LOG(host): before init, events reach the handler but not the ring", "[host][log]")
{
    presidio_log_deinit();
    s_forwarded = 0;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, presidio_log_register_handler(NULL, NULL));
    TEST_ASSERT_EQUAL(ESP_OK, presidio_log_register_handler(count_cb, NULL));

    TEST_ASSERT_EQUAL(ESP_OK, presidio_log_event(PRESIDIO_SEV_INFO, "PRE", "early"));
    TEST_ASSERT_EQUAL(1, s_forwarded);
    TEST_ASSERT_EQUAL(0, presidio_log_get_total_count());

    presidio_security_event_t ev[1];
    TEST_ASSERT_EQUAL(0, presidio_log_get_recent(ev, 1));
    TEST_ASSERT_EQUAL(0, presidio_log_get_recent(NULL, 1));

    presidio_log_deinit();
}

/* ---- ANOMALY ------------------------------------------------------ */

TEST_CASE("ANOMALY(host): auth-failure threshold raises an ALERT event", "[host][anomaly]")
{
    presidio_log_deinit();
    presidio_log_init();
    presidio_anomaly_deinit();
    presidio_anomaly_init();

    presidio_security_event_t ev[1];
    for (int i = 0; i < 4; i++) {
        presidio_anomaly_report(PRESIDIO_ANOMALY_AUTH_FAILURE);
    }
    TEST_ASSERT_EQUAL(1, presidio_log_get_recent(ev, 1));
    TEST_ASSERT_EQUAL(PRESIDIO_SEV_INFO, ev[0].severity); /* init message only */

    presidio_anomaly_report(PRESIDIO_ANOMALY_AUTH_FAILURE); /* 5th = default threshold */
    TEST_ASSERT_EQUAL(1, presidio_log_get_recent(ev, 1));
    TEST_ASSERT_EQUAL(PRESIDIO_SEV_ALERT, ev[0].severity);
    TEST_ASSERT_EQUAL_STRING("ANOMALY", ev[0].module);

    presidio_anomaly_deinit();
    presidio_log_deinit();
}

TEST_CASE("ANOMALY(host): counters are per type and reset keeps none", "[host][anomaly]")
{
    presidio_anomaly_deinit();
    presidio_anomaly_init();
    presidio_anomaly_report(PRESIDIO_ANOMALY_OTA_TAMPER);
    presidio_anomaly_report(PRESIDIO_ANOMALY_OTA_TAMPER);
    TEST_ASSERT_EQUAL(2, presidio_anomaly_get_count(PRESIDIO_ANOMALY_OTA_TAMPER));
    TEST_ASSERT_EQUAL(0, presidio_anomaly_get_count(PRESIDIO_ANOMALY_HEAP_CORRUPTION));
    TEST_ASSERT_EQUAL(0, presidio_anomaly_get_count(PRESIDIO_ANOMALY_TYPE_MAX));

    presidio_anomaly_reset_counters();
    for (int t = 0; t < PRESIDIO_ANOMALY_TYPE_MAX; t++) {
        TEST_ASSERT_EQUAL(0, presidio_anomaly_get_count((presidio_anomaly_type_t)t));
    }
    presidio_anomaly_deinit();
}

/* ---- INPUT -------------------------------------------------------- */

TEST_CASE("INPUT(host): length limits at the Kconfig defaults", "[host][input]")
{
    char buf[80];

    memset(buf, 'S', 32);
    buf[32] = '\0';
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_OK, presidio_input_sanitize_ssid(buf));

    memset(buf, 'p', 64);
    buf[64] = '\0';
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_OK, presidio_input_sanitize_wifi_password(buf));
    buf[64] = 'p';
    buf[65] = '\0';
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_TOO_LONG, presidio_input_sanitize_wifi_password(buf));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_NULL_PTR, presidio_input_sanitize_wifi_password(NULL));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INVALID_CHARS,
                      presidio_input_sanitize_wifi_password("password\x07x"));
}

TEST_CASE("INPUT(host): MQTT topic edge cases", "[host][input]")
{
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_OK, presidio_input_sanitize_mqtt_topic("$SYS/broker/uptime"));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_OK, presidio_input_sanitize_mqtt_topic("home/+/temp"));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_OK, presidio_input_sanitize_mqtt_topic("home/#"));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INJECTION_DETECTED, presidio_input_sanitize_mqtt_topic("home/##"));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_NULL_PTR, presidio_input_sanitize_mqtt_topic(NULL));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_TOO_SHORT, presidio_input_sanitize_mqtt_topic(""));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INVALID_CHARS, presidio_input_sanitize_mqtt_topic("a/\x1b/b"));

    char big[300];
    memset(big, 't', 257);
    big[257] = '\0';
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_TOO_LONG, presidio_input_sanitize_mqtt_topic(big));
}

TEST_CASE("INPUT(host): HTTP body checks", "[host][input]")
{
    static const char nul_body[] = { 'a', '\0', 'b' };
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INVALID_CHARS,
                      presidio_input_sanitize_http_body(nul_body, sizeof(nul_body)));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_NULL_PTR, presidio_input_sanitize_http_body(NULL, 0));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_OK, presidio_input_sanitize_http_body("", 0));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_TOO_LONG, presidio_input_sanitize_http_body("x", 4097));

    /* Pattern matching is case-insensitive. */
    const char *upper = "<SCRIPT>x</SCRIPT>";
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INJECTION_DETECTED,
                      presidio_input_sanitize_http_body(upper, strlen(upper)));
    const char *js = "href=JavaScript:alert(1)";
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INJECTION_DETECTED,
                      presidio_input_sanitize_http_body(js, strlen(js)));

    /* Only the first `length` bytes are scanned; a pattern past it is ignored. */
    const char *tail = "abc<script";
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_OK, presidio_input_sanitize_http_body(tail, 3));
    TEST_ASSERT_EQUAL(PRESIDIO_INPUT_INJECTION_DETECTED,
                      presidio_input_sanitize_http_body(tail, strlen(tail)));
}

TEST_CASE("INPUT(host): result_to_str covers every value", "[host][input]")
{
    TEST_ASSERT_EQUAL_STRING("null pointer", presidio_input_result_to_str(PRESIDIO_INPUT_NULL_PTR));
    TEST_ASSERT_EQUAL_STRING("input too long", presidio_input_result_to_str(PRESIDIO_INPUT_TOO_LONG));
    TEST_ASSERT_EQUAL_STRING("input too short", presidio_input_result_to_str(PRESIDIO_INPUT_TOO_SHORT));
    TEST_ASSERT_EQUAL_STRING("invalid characters", presidio_input_result_to_str(PRESIDIO_INPUT_INVALID_CHARS));
    TEST_ASSERT_EQUAL_STRING("unknown", presidio_input_result_to_str((presidio_input_result_t)99));
}

/* ---- TLS policy --------------------------------------------------- */

TEST_CASE("TLS(host): allow-list is exactly ECDHE + AEAD suites", "[host][tls]")
{
    /* IANA IDs of the ECDHE AES-GCM and ChaCha20-Poly1305 suites. */
    static const int aead_ecdhe[] = { 0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9 };
    const size_t n_known          = sizeof(aead_ecdhe) / sizeof(aead_ecdhe[0]);

    const int *suites = presidio_tls_get_allowed_suites();
    for (int i = 0; suites[i] != 0; i++) {
        int known = 0;
        for (size_t j = 0; j < n_known; j++) {
            if (suites[i] == aead_ecdhe[j]) {
                known = 1;
            }
        }
        TEST_ASSERT_TRUE(known);
    }

    /* Non-forward-secret GCM and CBC suites stay blocked. */
    TEST_ASSERT_FALSE(presidio_tls_is_suite_allowed(0x009C)); /* RSA_WITH_AES_128_GCM_SHA256 */
    TEST_ASSERT_FALSE(presidio_tls_is_suite_allowed(0xC013)); /* ECDHE_RSA_WITH_AES_128_CBC_SHA */
    TEST_ASSERT_FALSE(presidio_tls_is_suite_allowed(0));
}

/* ---- NVS key classification --------------------------------------- */

TEST_CASE("NVS(host): secret-key match is case-insensitive", "[host][nvs]")
{
    TEST_ASSERT_TRUE(presidio_nvs_is_secret_key("WiFi_PassWord"));
    TEST_ASSERT_TRUE(presidio_nvs_is_secret_key("TLS_CERT"));
    TEST_ASSERT_FALSE(presidio_nvs_is_secret_key(""));
    TEST_ASSERT_FALSE(presidio_nvs_is_secret_key("ssid"));
}
