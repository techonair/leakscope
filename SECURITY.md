# Security Policy

## Scope and safe operation

LeakScope handles hostile, potentially sensitive input. The v0.1 API is unauthenticated and intended for loopback/local use only. Do not expose it to an untrusted network. Use synthetic data for development and issue reports; never include live credentials or personal data.

The pipeline normalizes and caps input, masks supported secret patterns before returning or classifying it, and fingerprints values with HMAC. Raw input exists transiently in process memory while a request is handled. When `JEV_API_KEY` is configured, LeakScope sends masked text and deterministic facts to Jev AI's hosted `POST /v1/systemone` endpoint. The API key stays server-side; it is not returned to the browser. The current detector set is incomplete, so an unrecognized secret or personal value could remain in text sent to Jev. Review that data flow, Jev's current retention terms, and your legal/security requirements before enabling the key on real leak data.

This release does not persist cases or test credentials. Missing credentials, provider errors, invalid model output, injection flags, uncertainty, and truncated inputs fail to `REVIEW`. Logs, crash dumps, upstream proxies, and host instrumentation remain deployment responsibilities. The local API is unauthenticated and must only be bound to loopback unless an authenticated deployment layer is added.

## Reporting a vulnerability

Please do not open a public issue containing exploit details or sensitive data. Use GitHub's private vulnerability reporting for this repository. Include a minimal reproduction using synthetic values, affected version, and impact. Allow maintainers reasonable time to investigate and coordinate a fix before disclosure.

## Supported versions

Only the latest release is supported while the project is pre-1.0.
