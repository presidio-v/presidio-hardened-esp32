#ifndef PRESIDIO_HOST_UNITY_H
#define PRESIDIO_HOST_UNITY_H

/*
 * Minimal host stand-in for the subset of the ESP-IDF Unity API that the
 * portable test files in test/ use (TEST_CASE plus a few assertions).
 * Semantics follow Unity: integer assertions compare as signed integers and
 * a failed assertion ends the current test case.
 */

#include <stddef.h>

typedef void (*host_test_fn_t)(void);

void host_test_register(host_test_fn_t fn, const char *name, const char *file, int line);

_Noreturn void host_test_fail_int(const char *file, int line, const char *what,
                                  long long expected, long long actual);
_Noreturn void host_test_fail_str(const char *file, int line,
                                  const char *expected, const char *actual);
_Noreturn void host_test_fail_msg(const char *file, int line, const char *what);
int host_test_str_equal(const char *a, const char *b);

#define HOST_CAT_(a, b) a##b
#define HOST_CAT(a, b) HOST_CAT_(a, b)

#define TEST_CASE(name_, tags_) HOST_TEST_CASE_(HOST_CAT(host_test_, __LINE__), name_)
#define HOST_TEST_CASE_(fn_, name_)                                    \
    static void fn_(void);                                             \
    __attribute__((constructor)) static void HOST_CAT(fn_, _reg)(void) \
    {                                                                  \
        host_test_register(fn_, name_, __FILE__, __LINE__);            \
    }                                                                  \
    static void fn_(void)

#define HOST_INT_CHECK_(e, a, op, what)                                     \
    do {                                                                    \
        long long host_e_ = (long long)(e);                                 \
        long long host_a_ = (long long)(a);                                 \
        if (!(host_a_ op host_e_)) {                                        \
            host_test_fail_int(__FILE__, __LINE__, what, host_e_, host_a_); \
        }                                                                   \
    } while (0)

#define TEST_ASSERT_EQUAL(e, a) HOST_INT_CHECK_(e, a, ==, "TEST_ASSERT_EQUAL")
#define TEST_ASSERT_NOT_EQUAL(e, a) HOST_INT_CHECK_(e, a, !=, "TEST_ASSERT_NOT_EQUAL")
#define TEST_ASSERT_GREATER_THAN(t, a) HOST_INT_CHECK_(t, a, >, "TEST_ASSERT_GREATER_THAN")

#define TEST_ASSERT_TRUE(c)                                               \
    do {                                                                  \
        if (!(c)) {                                                       \
            host_test_fail_msg(__FILE__, __LINE__, "expected TRUE: " #c); \
        }                                                                 \
    } while (0)
#define TEST_ASSERT_FALSE(c)                                               \
    do {                                                                   \
        if (c) {                                                           \
            host_test_fail_msg(__FILE__, __LINE__, "expected FALSE: " #c); \
        }                                                                  \
    } while (0)
#define TEST_ASSERT_NULL(p) TEST_ASSERT_TRUE((p) == NULL)
#define TEST_ASSERT_NOT_NULL(p) TEST_ASSERT_TRUE((p) != NULL)

#define TEST_ASSERT_EQUAL_STRING(e, a)                                  \
    do {                                                                \
        const char *host_es_ = (e);                                     \
        const char *host_as_ = (a);                                     \
        if (!host_test_str_equal(host_es_, host_as_)) {                 \
            host_test_fail_str(__FILE__, __LINE__, host_es_, host_as_); \
        }                                                               \
    } while (0)

#endif /* PRESIDIO_HOST_UNITY_H */
