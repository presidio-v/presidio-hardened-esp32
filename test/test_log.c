#include "unity.h"
#include "presidio_log.h"

#include <stddef.h>
#include <stdint.h>

/*
 * Portable test cases: these run on the device (test_app, ESP-IDF Unity)
 * and on the host (test/host, see test/host/README.md). Keep them free of
 * hardware access so both builds stay meaningful.
 */

/* ------------------------------------------------------------------ */
/*  Security event logging tests                                      */
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
