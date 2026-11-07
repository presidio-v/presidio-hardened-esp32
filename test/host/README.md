# Host unit tests

Builds the component's pure-logic code with the host compiler (gcc or clang)
and runs it under AddressSanitizer and UndefinedBehaviorSanitizer. No ESP-IDF
install, board or emulator is needed. CI runs this in the `host-tests` job of
`.github/workflows/ci.yml`.

```bash
make -C test/host test                                         # Linux, libmbedtls-dev installed
make -C test/host test MBEDTLS_CFLAGS=-I/opt/homebrew/include  # macOS, brew install mbedtls
```

mbedTLS is needed for its headers only (the cipher-suite IDs in
`presidio_tls.c`); nothing is linked against it.

## What is covered

| Module | Covered on host |
|--------|-----------------|
| `presidio_input.c` | All of it: SSID, Wi-Fi password, MQTT topic and HTTP body checks, `result_to_str` |
| `presidio_log.c` | Ring buffer, wrap-around ordering, truncation, handler forwarding, timestamps (fake timer) |
| `presidio_anomaly.c` | Counters, handlers, reset, invalid types, auth-failure threshold alert |
| `presidio_nvs.c` | `presidio_nvs_is_secret_key` and the NULL-argument checks of `open`/`close` only |
| `presidio_tls.c` | Cipher-suite allow-list (`is_suite_allowed`, `get_allowed_suites`) and the NULL check of `apply_hardening` |

The test cases come from two places:

- `test/test_{input,log,anomaly,nvs_policy,tls_policy}.c` are shared with the
  device test app. The device build picks them up through `SRC_DIRS "."` in
  `test/CMakeLists.txt`; the host build compiles the same files.
- `test/host/test_host_extra.c` adds host-only edge cases (boundaries,
  ordering after wrap, case-insensitive matching, the timer fake).

## What is not covered

These paths need real hardware or ESP-IDF services and stay in the device
test app (`test/test_presidio.c`, run with `idf.py flash monitor`):

- `presidio_tls_apply_hardening` on a real config. The host build leaves
  `CONFIG_PRESIDIO_TLS_HARDENING` undefined, so the mbedTLS configuration
  calls are not compiled or tested here.
- NVS reads and writes, and the redacted logging around them. The `nvs_*`
  stubs abort if called, so a host test cannot pass by reaching flash code.
- `presidio_boot.c` (secure boot and flash-encryption eFuse state) and
  `presidio_security.c` (full init sequence). Neither is built on host.
- ESP event-loop integration in the anomaly module (there is none today; the
  `esp_event.h` stub is empty and will need declarations if that changes).
- Non-default Kconfig values. The Makefile pins the Kconfig defaults.

## Layout

- `unity.h`, `unity_host.c`: a minimal stand-in for the part of the ESP-IDF
  Unity API the shared tests use (`TEST_CASE` plus assertions). A failed
  assertion ends the test case, as in Unity.
- `stubs/`: tiny ESP-IDF headers (`esp_err.h`, `esp_log.h`, `esp_timer.h`,
  `esp_event.h`, `nvs.h`, `nvs_flash.h`) and their definitions in
  `host_stubs.c`. Error codes match ESP-IDF. Log macros discard output but
  keep format checking.

Run a subset by name (from the repo root, after a build):
`test/host/build/presidio_host_tests INPUT`.
