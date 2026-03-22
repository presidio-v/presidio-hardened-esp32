# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in `presidio-hardened-esp32`, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email**: Send a detailed report to **security@presidio-iot.example** (replace with your actual security contact).
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Potential impact assessment
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Fix timeline**: Critical issues patched within 7 days; others within 30 days
- **Credit**: We will credit reporters in the release notes (unless you prefer anonymity)

### Scope

The following are in scope for security reports:

- Bypass of TLS hardening (weak ciphers accepted when they should be blocked)
- NVS secret leakage (redacted values appearing in logs)
- Input sanitization bypass (injection patterns not detected)
- Anomaly detection evasion
- Buffer overflows or memory corruption in any Presidio module
- Secure boot/flash encryption check bypass

### Out of Scope

- Vulnerabilities in ESP-IDF itself (report to [Espressif](https://www.espressif.com/en/security))
- Vulnerabilities in mbedTLS (report to [ARM mbedTLS](https://github.com/Mbed-TLS/mbedtls/security))
- Issues requiring physical access to an unprotected device with debug interfaces enabled
- Denial of service via excessive API calls (expected behavior in embedded context)

## Security Best Practices

When deploying with `presidio-hardened-esp32`:

1. **Burn eFuses** for secure boot and flash encryption in production
2. **Enable** `PRESIDIO_BOOT_HALT_IF_INSECURE` for production builds
3. **Enable** `PRESIDIO_TLS_MIN_VERSION_13` when your server supports TLS 1.3
4. **Register anomaly handlers** to respond to security events (e.g., disable Wi-Fi after repeated auth failures)
5. **Review Kconfig** settings before each release build
6. **Keep dependencies updated** — Dependabot is configured for this repository
