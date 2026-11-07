#include "unity.h"
#include "presidio_nvs.h"

#include <stddef.h>

/*
 * Portable test cases: these run on the device (test_app, ESP-IDF Unity)
 * and on the host (test/host, see test/host/README.md). Keep them free of
 * hardware access so both builds stay meaningful.
 */

/* ------------------------------------------------------------------ */
/*  NVS secret-key classification and argument checks                 */
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

TEST_CASE("NVS: close rejects NULL", "[presidio][nvs]")
{
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG, presidio_nvs_close(NULL));
}
