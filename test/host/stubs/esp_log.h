#ifndef ESP_LOG_H
#define ESP_LOG_H

/*
 * Host stub: log macros discard output but keep printf-style format
 * checking, like the real ESP_LOGx macros do.
 */

#include <inttypes.h>
#include <stdio.h>

#define HOST_LOG_(tag, fmt, ...)        \
    do {                                \
        (void)(tag);                    \
        if (0) {                        \
            printf(fmt, ##__VA_ARGS__); \
        }                               \
    } while (0)

#define ESP_LOGE(tag, fmt, ...) HOST_LOG_(tag, fmt, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) HOST_LOG_(tag, fmt, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) HOST_LOG_(tag, fmt, ##__VA_ARGS__)
#define ESP_LOGD(tag, fmt, ...) HOST_LOG_(tag, fmt, ##__VA_ARGS__)
#define ESP_LOGV(tag, fmt, ...) HOST_LOG_(tag, fmt, ##__VA_ARGS__)

#endif /* ESP_LOG_H */
