# Presidio Hardened ESP32

> Production-ready security hardening layer for ESP-IDF (pure C component)

[![ESP-IDF Build](https://github.com/presidio-iot/presidio-hardened-esp32/actions/workflows/build.yml/badge.svg)](https://github.com/presidio-iot/presidio-hardened-esp32/actions/workflows/build.yml)
[![CodeQL](https://github.com/presidio-iot/presidio-hardened-esp32/actions/workflows/codeql.yml/badge.svg)](https://github.com/presidio-iot/presidio-hardened-esp32/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-green.svg)](idf_component.yml)

Add `presidio-hardened-esp32` to any ESP-IDF v5.0+ project and your existing code
automatically receives strong security defaults — no rewrites needed.

## Features

| Feature | What it does |
|---------|-------------|
| **TLS Hardening** | Enforces TLS 1.2+ with AEAD-only cipher suites, mandatory certificate verification, no renegotiation |
| **NVS Secret Redaction** | Wraps NVS read/write with automatic `***REDACTED***` log output for keys matching `password`, `token`, `secret`, etc. |
| **Secure Boot Enforcement** | Checks eFuse state for secure boot and flash encryption; optionally halts if unset |
| **Anomaly Detection** | Monitors auth failures, disconnections, OTA events with configurable thresholds and callbacks |
| **Input Sanitization** | Validates Wi-Fi credentials, MQTT topics, HTTP bodies against injection and overflow attacks |
| **Security Event Logging** | Structured ring-buffer logging with severity levels, timestamps, and real-time callbacks |

## Quick Start

### 1. Add the component

**Option A — idf_component.yml** (recommended):

```yaml
dependencies:
  presidio-hardened-esp32:
    git: https://github.com/presidio-iot/presidio-hardened-esp32.git
    version: "0.1.0"
```

**Option B — git submodule**:

```bash
git submodule add https://github.com/presidio-iot/presidio-hardened-esp32.git components/presidio-hardened-esp32
```

### 2. Initialize in app_main

```c
#include "presidio_security.h"

void app_main(void)
{
    // One call enables all Presidio hardening
    ESP_ERROR_CHECK(presidio_security_init());

    ESP_LOGI("app", "Status: %s", presidio_security_status());

    // ... your application code ...
}
```

### 3. Configure via menuconfig

```bash
idf.py menuconfig
# → Presidio Hardened ESP32
```

All features are **enabled by default** and can be individually toggled.

---

## Side-by-Side: Plain ESP-IDF vs Presidio-Hardened

### TLS Connection

<table>
<tr><th>Plain ESP-IDF</th><th>With Presidio</th></tr>
<tr>
<td>

```c
// No cipher restrictions — any suite accepted
// No minimum TLS version enforced
// Certificate verification optional
mbedtls_ssl_config conf;
mbedtls_ssl_config_init(&conf);
mbedtls_ssl_config_defaults(&conf, ...);
// Developer must manually configure
// every security parameter
```

</td>
<td>

```c
#include "presidio_tls.h"

mbedtls_ssl_config conf;
mbedtls_ssl_config_init(&conf);
mbedtls_ssl_config_defaults(&conf, ...);

// One call: TLS 1.2+, AEAD only,
// certs required, no renegotiation
presidio_tls_apply_hardening(&conf);
```

</td>
</tr>
</table>

### Storing Secrets in NVS

<table>
<tr><th>Plain ESP-IDF</th><th>With Presidio</th></tr>
<tr>
<td>

```c
// Passwords appear in plaintext in logs:
// I (1234) app: Setting wifi_password = hunter2
nvs_handle_t h;
nvs_open("wifi", NVS_READWRITE, &h);
nvs_set_str(h, "wifi_password", "hunter2");
nvs_commit(h);
nvs_close(h);
```

</td>
<td>

```c
#include "presidio_nvs.h"

// Automatic redaction in logs:
// I (1234) presidio_nvs: SET_STR [wifi]
//   wifi_password = ***REDACTED***
presidio_nvs_handle_t h;
presidio_nvs_open("wifi", &h);
presidio_nvs_set_str(h, "wifi_password",
                     "hunter2");
presidio_nvs_close(h);
```

</td>
</tr>
</table>

### Input Validation

<table>
<tr><th>Plain ESP-IDF</th><th>With Presidio</th></tr>
<tr>
<td>

```c
// No validation — attacker-controlled
// SSID/password accepted as-is
wifi_config_t cfg = { ... };
memcpy(cfg.sta.ssid, user_ssid, len);
esp_wifi_set_config(WIFI_IF_STA, &cfg);
```

</td>
<td>

```c
#include "presidio_input.h"

if (presidio_input_sanitize_ssid(user_ssid)
    != PRESIDIO_INPUT_OK) {
    ESP_LOGE(TAG, "Invalid SSID rejected");
    return;
}
if (presidio_input_sanitize_wifi_password(
        user_pass) != PRESIDIO_INPUT_OK) {
    ESP_LOGE(TAG, "Invalid password rejected");
    return;
}
// Safe to use
esp_wifi_set_config(WIFI_IF_STA, &cfg);
```

</td>
</tr>
</table>

### Boot Security

<table>
<tr><th>Plain ESP-IDF</th><th>With Presidio</th></tr>
<tr>
<td>

```c
// Developer never checks if secure boot
// is actually enabled. Firmware ships
// with unburned fuses — anyone can flash
// a modified image.
void app_main(void) {
    start_application();
}
```

</td>
<td>

```c
#include "presidio_boot.h"

void app_main(void) {
    presidio_boot_verify();
    // Logs:
    // W (100) presidio_boot: Secure boot
    //   is NOT enabled
    // W (100) presidio_boot: Flash
    //   encryption is NOT enabled

    ESP_LOGI(TAG, "%s",
             presidio_boot_status_str());
    // "secure_boot=OFF flash_enc=OFF ..."
}
```

</td>
</tr>
</table>

### Anomaly Detection

<table>
<tr><th>Plain ESP-IDF</th><th>With Presidio</th></tr>
<tr>
<td>

```c
// Auth failures silently ignored.
// No rate limiting, no alerting.
void wifi_event_handler(...) {
    if (event == WIFI_EVENT_STA_DISCONNECTED)
        esp_wifi_connect();  // retry forever
}
```

</td>
<td>

```c
#include "presidio_anomaly.h"

void on_alert(presidio_anomaly_type_t t,
              uint32_t count, void *ctx) {
    ESP_LOGE(TAG, "Security alert! type=%d"
             " count=%lu", t, count);
}

presidio_anomaly_init();
presidio_anomaly_register_handler(
    PRESIDIO_ANOMALY_AUTH_FAILURE,
    on_alert, NULL);

// After 5 failures (configurable):
// E (5000) presidio_anomaly: Auth failure
//   threshold reached (5)
```

</td>
</tr>
</table>

---

## API Reference

### Core

| Function | Description |
|----------|-------------|
| `presidio_security_init()` | Initialize all enabled security extensions |
| `presidio_security_status()` | Get human-readable status string |
| `presidio_security_deinit()` | Tear down and free resources |

### TLS (`presidio_tls.h`)

| Function | Description |
|----------|-------------|
| `presidio_tls_apply_hardening(conf)` | Apply strict settings to mbedTLS config |
| `presidio_tls_is_suite_allowed(id)` | Check if a cipher suite is permitted |
| `presidio_tls_get_allowed_suites()` | Get NULL-terminated list of approved suites |

### NVS (`presidio_nvs.h`)

| Function | Description |
|----------|-------------|
| `presidio_nvs_open(ns, handle)` | Open namespace with security wrappers |
| `presidio_nvs_set_str / get_str` | String storage with automatic redaction |
| `presidio_nvs_set_blob / get_blob` | Binary storage with automatic redaction |
| `presidio_nvs_is_secret_key(key)` | Check if a key matches secret patterns |
| `presidio_nvs_close(handle)` | Commit and close |

### Boot (`presidio_boot.h`)

| Function | Description |
|----------|-------------|
| `presidio_boot_get_status(st)` | Query eFuse boot security flags |
| `presidio_boot_verify()` | Check and log boot security state |
| `presidio_boot_status_str()` | Human-readable boot status |

### Anomaly Detection (`presidio_anomaly.h`)

| Function | Description |
|----------|-------------|
| `presidio_anomaly_init()` | Start runtime monitoring |
| `presidio_anomaly_register_handler(type, cb, ctx)` | Register per-type callback |
| `presidio_anomaly_report(type)` | Manually report an anomaly |
| `presidio_anomaly_get_count(type)` | Current counter for a type |
| `presidio_anomaly_reset_counters()` | Reset all counters |

### Input Sanitization (`presidio_input.h`)

| Function | Description |
|----------|-------------|
| `presidio_input_sanitize_ssid(s)` | Validate Wi-Fi SSID |
| `presidio_input_sanitize_wifi_password(s)` | Validate Wi-Fi password |
| `presidio_input_sanitize_mqtt_topic(s)` | Validate MQTT topic |
| `presidio_input_sanitize_http_body(b, len)` | Validate HTTP body |

### Security Logging (`presidio_log.h`)

| Function | Description |
|----------|-------------|
| `presidio_log_init()` | Initialize ring buffer |
| `presidio_log_event(sev, mod, msg)` | Log a structured security event |
| `presidio_log_register_handler(cb, ctx)` | Real-time event callback |
| `presidio_log_get_recent(evts, max)` | Retrieve recent events |

---

## Kconfig Options

All options live under **Presidio Hardened ESP32** in menuconfig:

| Option | Default | Description |
|--------|---------|-------------|
| `PRESIDIO_SECURITY_ENABLE` | `y` | Master switch |
| `PRESIDIO_TLS_HARDENING` | `y` | Enforce strong TLS |
| `PRESIDIO_TLS_MIN_VERSION_13` | `n` | Require TLS 1.3 |
| `PRESIDIO_NVS_REDACTION` | `y` | Redact secrets in logs |
| `PRESIDIO_BOOT_ENFORCEMENT` | `y` | Check boot fuses |
| `PRESIDIO_BOOT_HALT_IF_INSECURE` | `n` | Abort if fuses unset |
| `PRESIDIO_ANOMALY_DETECTION` | `y` | Runtime monitoring |
| `PRESIDIO_ANOMALY_MAX_AUTH_FAILURES` | `5` | Alert threshold |
| `PRESIDIO_INPUT_SANITIZATION` | `y` | Input validation |
| `PRESIDIO_SECURITY_LOG` | `y` | Event logging |

---

## Building & Testing

```bash
# Build the test app
cd test_app
idf.py set-target esp32
idf.py build

# Flash and run tests
idf.py -p /dev/ttyUSB0 flash monitor
```

---

## Supported Targets

ESP32, ESP32-S2, ESP32-S3, ESP32-C3, ESP32-C6, ESP32-H2

## Requirements

- ESP-IDF v5.0 or later
- CMake 3.16+

## License

[MIT](LICENSE)
