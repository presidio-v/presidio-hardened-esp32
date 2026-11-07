#ifndef HOST_FAKES_H
#define HOST_FAKES_H

/* Host-only controls for the stubbed ESP-IDF services. */

#include <stdint.h>

/* Set the value returned by esp_timer_get_time() (microseconds). */
void host_fake_timer_set_us(int64_t us);

#endif /* HOST_FAKES_H */
