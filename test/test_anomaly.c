#include "unity.h"
#include "presidio_anomaly.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Portable test cases: these run on the device (test_app, ESP-IDF Unity)
 * and on the host (test/host, see test/host/README.md). Keep them free of
 * hardware access so both builds stay meaningful.
 */

/* ------------------------------------------------------------------ */
/*  Anomaly detection tests                                           */
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
