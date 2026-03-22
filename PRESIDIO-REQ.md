# Presidio-Hardened ESP32 – Top-Level Requirements

## Overview
Build a production-ready ESP-IDF component `presidio-hardened-esp32` (pure C) that acts as a hardened security layer for the ESP32 platform.
Users add it to any ESP-IDF project via `idf_component.yml` or `CMakeLists.txt`, and their existing code mostly works unchanged while automatically receiving strong Presidio security defaults.

## Mandatory Presidio Security Extensions
- Hardened mbedTLS configuration (strict TLS 1.3, certificate validation, no weak ciphers)
- Secure NVS storage with automatic secret redaction and encryption helpers
- Flash encryption and secure boot enforcement helpers (Kconfig overlays)
- Runtime anomaly detection and security event logging for network/OTA/boot events
- Input sanitization for common attack vectors (Wi-Fi credentials, MQTT topics, HTTP bodies)
- Automatic dependency/CVE quick-check on build (via ESP-IDF tools)
- Security event logging ("Presidio hardening applied to ESP32 session")
- Full GitHub security files: SECURITY.md, .github/dependabot.yml, .github/workflows/codeql.yml + ESP-IDF build workflow

## Technical Requirements
- ESP-IDF v5.0+
- Pure C (no Python/C++)
- Standard ESP-IDF component layout: CMakeLists.txt, Kconfig, include/, src/, idf_component.yml
- Do NOT copy ESP-IDF source; extend via component overrides, middleware, and Kconfig defaults
- Unit tests with ESP-IDF test framework (verify TLS, storage redaction, secure boot)
- README.md with side-by-side examples: plain ESP-IDF vs presidio-hardened-esp32 showing security wins
- LICENSE = MIT
- Version = 0.1.0

