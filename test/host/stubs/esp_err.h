#ifndef ESP_ERR_H
#define ESP_ERR_H

/* Host stub: the esp_err_t codes the component uses, values as in ESP-IDF. */

#include <stdint.h>
#include <stdio.h>

typedef int esp_err_t;

#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NOT_SUPPORTED 0x106

const char *esp_err_to_name(esp_err_t code);

#endif /* ESP_ERR_H */
