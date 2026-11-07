#include "unity.h"
#include "presidio_input.h"

#include <string.h>

/*
 * Portable test cases: these run on the device (test_app, ESP-IDF Unity)
 * and on the host (test/host, see test/host/README.md). Keep them free of
 * hardware access so both builds stay meaningful.
 */

/* ------------------------------------------------------------------ */
/*  Input sanitization tests                                          */
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
