# Presidio-Hardened ESP32 — Requirements

## Overview

`presidio-hardened-esp32` is a pure-C ESP-IDF component that applies
production-grade security defaults to any ESP-IDF v5.0+ project through a
single `presidio_security_init()` call at `app_main`. It was developed on
customer specification for embedded / IoT deployments that need hardening
without rewriting application code, and is not linked to any PRES-EDU
experiment.

## Mandatory Presidio Security Extensions

- TLS 1.2+ enforcement with AEAD-only cipher suites, mandatory certificate
  verification, and renegotiation disabled
- NVS secret redaction — NVS read/write is wrapped so that keys matching
  `password`, `token`, `secret`, etc. log as `***REDACTED***`
- Secure Boot / flash-encryption eFuse-state check (halt-on-insecure is
  opt-in via `menuconfig`, not the default, to preserve bring-up flows)
- Anomaly detection for auth failures, disconnections, and OTA events with
  configurable thresholds and callbacks
- Input sanitisation for Wi-Fi credentials, MQTT topics, and HTTP bodies
  (injection / overflow rejection)
- Structured security event logging (ring-buffer, severity levels,
  timestamps, real-time callbacks)
- Full GitHub security files: `SECURITY.md`, `.github/dependabot.yml`,
  `.github/workflows/codeql.yml`, `.github/workflows/build.yml`

## Technical Requirements

- ESP-IDF v5.0+
- Pure C (no C++) — chosen to minimise the runtime footprint and to keep the
  library usable from the same compilation units as ESP-IDF core code
- Distributed as an ESP-IDF component (`idf_component.yml`) or git submodule
- Integration tests run on the qemu ESP32 target in CI (`build.yml`)
- MIT License, version 0.1.0

## Out of scope

- Secure-boot key provisioning (device-lifecycle concern, not a library
  concern)
- Flash-encryption key rotation
- Firmware signing / OTA image signing — handled by the caller's release
  pipeline, not at runtime

## Version Deliberation Log

### v0.1.0 — Initial release

**Scope decision:** Pure C, no C++. ESP-IDF components are commonly linked
into mixed C/C++ projects; restricting the library itself to C keeps the
dependency surface minimal and avoids exception-related code-size overhead
on devices with tight flash budgets.

**Scope decision:** Compile-time `menuconfig` configuration preferred over a
runtime API. Embedded customers want the hardening baseline to be
reproducible from the `sdkconfig` file and visible at build time; a runtime
API would make the actual posture dependent on boot-time calls.

**Scope decision:** `halt-on-insecure-boot` is opt-in rather than default.
Developers routinely flash unprovisioned devices during bring-up; halting on
missing secure-boot eFuses would break the first-run path. The default is a
loud warning; the customer opts in to halt once provisioning is in place.

**Scope decision:** NVS redaction matches a fixed keyword list rather than
regex patterns. Pattern compilation on an ESP32 is expensive and the
customer's secret-naming conventions are known; a keyword list is smaller,
auditable, and deterministic.

## SDLC

These requirements are delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
