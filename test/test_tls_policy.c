#include "unity.h"
#include "presidio_tls.h"

#include <stddef.h>

/*
 * Portable test cases: these run on the device (test_app, ESP-IDF Unity)
 * and on the host (test/host, see test/host/README.md). Keep them free of
 * hardware access so both builds stay meaningful.
 */

/* ------------------------------------------------------------------ */
/*  TLS cipher-suite policy tests                                     */
/* ------------------------------------------------------------------ */

TEST_CASE("TLS: apply_hardening rejects NULL config", "[presidio][tls]")
{
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_ARG,
                      presidio_tls_apply_hardening(NULL));
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
    TEST_ASSERT_FALSE(presidio_tls_is_suite_allowed(0x0005)); /* TLS_RSA_WITH_RC4_128_SHA */
    TEST_ASSERT_FALSE(presidio_tls_is_suite_allowed(0x000A)); /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
}

TEST_CASE("TLS: strong suites are allowed", "[presidio][tls]")
{
    /* ECDHE-RSA-AES256-GCM-SHA384 = 0xC030 */
    TEST_ASSERT_TRUE(presidio_tls_is_suite_allowed(0xC030));
    /* ECDHE-ECDSA-AES128-GCM-SHA256 = 0xC02B */
    TEST_ASSERT_TRUE(presidio_tls_is_suite_allowed(0xC02B));
}
