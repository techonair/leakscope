# Security Policy

## Scope and safe operation

LeakScope handles hostile, potentially sensitive input. The v0.1 API is unauthenticated and intended for loopback/local use only. Do not expose it to an untrusted network. Use synthetic data for development and issue reports; never include live credentials or personal data.

The pipeline normalizes and caps input, masks supported secret patterns before returning or classifying it, and fingerprints values with HMAC. Raw input exists transiently in process memory while a request is handled. This release does not persist cases, make model/provider calls, test credentials, or guarantee detection of every secret format. Logs, crash dumps, upstream proxies, and host instrumentation remain deployment responsibilities.

## Reporting a vulnerability

Please do not open a public issue containing exploit details or sensitive data. Use GitHub's private vulnerability reporting for this repository. Include a minimal reproduction using synthetic values, affected version, and impact. Allow maintainers reasonable time to investigate and coordinate a fix before disclosure.

## Supported versions

Only the latest release is supported while the project is pre-1.0.
