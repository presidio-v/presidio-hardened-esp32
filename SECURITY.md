# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory
(via the "Security" tab → "Report a vulnerability") rather than a public issue.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 5 business days. We aim to release a patch
within 30 days of a confirmed vulnerability.

## Security Best Practices

When deploying with `presidio-hardened-esp32`:

1. **Burn eFuses** for secure boot and flash encryption in production
2. **Enable** `PRESIDIO_BOOT_HALT_IF_INSECURE` for production builds
3. **Enable** `PRESIDIO_TLS_MIN_VERSION_13` when your server supports TLS 1.3
4. **Register anomaly handlers** to respond to security events (e.g., disable Wi-Fi after repeated auth failures)
5. **Review Kconfig** settings before each release build
6. **Keep dependencies updated** — Dependabot is configured for this repository

## Continuous Integration

Every push and pull request to `main` runs the ESP-IDF build matrix, CodeQL,
cppcheck, a clang-format check, host unit tests under ASan/UBSan, and a
dependency pin check on `idf_component.yml`. The component declares no managed
dependencies besides the ESP-IDF framework itself, so there is no third-party
component to scan; Dependabot keeps the GitHub Actions pins current. ESP-IDF
(including its bundled mbedTLS) is not scanned by this repository's CI; track
its advisories upstream and build against a patched IDF release.

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
