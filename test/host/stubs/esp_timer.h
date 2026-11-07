#ifndef ESP_TIMER_H
#define ESP_TIMER_H

/* Host stub: time comes from host_fake_timer_set_us() (see host_fakes.h). */

#include <stdint.h>

int64_t esp_timer_get_time(void);

#endif /* ESP_TIMER_H */
