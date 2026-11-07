/*
 * Test registry and runner for the host build. TEST_CASE registers each
 * case from a constructor; main() runs them in registration order.
 * Usage: presidio_host_tests [substring]  (runs only cases whose name
 * contains the substring).
 */

#include "unity.h"

#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#define HOST_MAX_TESTS 256

typedef struct {
    host_test_fn_t fn;
    const char *name;
    const char *file;
    int line;
} host_test_t;

static host_test_t s_tests[HOST_MAX_TESTS];
static int s_test_count = 0;
static int s_overflow   = 0;
static jmp_buf s_jmp;

void host_test_register(host_test_fn_t fn, const char *name, const char *file, int line)
{
    if (s_test_count >= HOST_MAX_TESTS) {
        s_overflow = 1;
        return;
    }
    s_tests[s_test_count].fn   = fn;
    s_tests[s_test_count].name = name;
    s_tests[s_test_count].file = file;
    s_tests[s_test_count].line = line;
    s_test_count++;
}

int host_test_str_equal(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return a == b;
    }
    return strcmp(a, b) == 0;
}

void host_test_fail_int(const char *file, int line, const char *what,
                        long long expected, long long actual)
{
    printf("    %s:%d: %s: expected %lld, got %lld\n", file, line, what,
           expected, actual);
    longjmp(s_jmp, 1);
}

void host_test_fail_str(const char *file, int line,
                        const char *expected, const char *actual)
{
    printf("    %s:%d: TEST_ASSERT_EQUAL_STRING: expected \"%s\", got \"%s\"\n",
           file, line, expected ? expected : "(null)",
           actual ? actual : "(null)");
    longjmp(s_jmp, 1);
}

void host_test_fail_msg(const char *file, int line, const char *what)
{
    printf("    %s:%d: %s\n", file, line, what);
    longjmp(s_jmp, 1);
}

/* Returns 1 if the case passed. Kept separate so no caller locals live
 * across setjmp/longjmp. */
static int run_one(const host_test_t *t)
{
    if (setjmp(s_jmp) == 0) {
        t->fn();
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *filter = (argc > 1) ? argv[1] : NULL;
    int run            = 0;
    int failed         = 0;

    if (s_overflow) {
        printf("too many test cases (max %d)\n", HOST_MAX_TESTS);
        return 2;
    }

    for (int i = 0; i < s_test_count; i++) {
        const host_test_t *t = &s_tests[i];
        if (filter && !strstr(t->name, filter)) {
            continue;
        }
        run++;
        if (run_one(t)) {
            printf("PASS  %s\n", t->name);
        } else {
            failed++;
            printf("FAIL  %s  (%s:%d)\n", t->name, t->file, t->line);
        }
    }

    printf("\n%d tests, %d failures\n", run, failed);
    if (run == 0) {
        printf("no test cases ran\n");
        return 2;
    }
    return failed ? 1 : 0;
}
